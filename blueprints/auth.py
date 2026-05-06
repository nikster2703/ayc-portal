"""
AYC Portal — Authentication blueprint.
Routes: /, /api/auth/*
"""

import json
import time
from datetime import datetime, timezone

import bcrypt
from flask import Blueprint, jsonify, redirect, request, session, url_for

from config import (
    ROLE_DISPLAY_NAMES, LOGIN_MAX_FAILURES, LOGIN_LOCKOUT_SECONDS,
    APP_VERSION, CLUB_NAME, CLUB_SHORT_NAME,
)
from extensions import csrf
from flask import render_template
from helpers import (
    get_db, log_action, login_required, validate_password,
    get_brand_settings, get_session_types, tpl_ctx,
)

bp = Blueprint('auth', __name__)

# ── Login rate limiter (in-memory, per-IP) ─────────────────────────────────────
_login_attempts: dict = {}


def _check_login_rate_limit(ip: str):
    now = time.time()
    rec = _login_attempts.get(ip, {'count': 0, 'locked_until': 0})
    if now < rec['locked_until']:
        return False, int(rec['locked_until'] - now)
    return True, 0


def _record_login_failure(ip: str):
    now = time.time()
    rec = _login_attempts.get(ip, {'count': 0, 'locked_until': 0})
    rec['count'] += 1
    if rec['count'] >= LOGIN_MAX_FAILURES:
        rec['locked_until'] = now + LOGIN_LOCKOUT_SECONDS
        rec['count']        = 0
    _login_attempts[ip] = rec


def _clear_login_failures(ip: str):
    _login_attempts.pop(ip, None)


# ── Page routes ────────────────────────────────────────────────────────────────

@bp.route('/')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('pages.dashboard_page'))
    brand = get_brand_settings()
    club  = brand.get('brand_club_name')  or CLUB_NAME
    short = brand.get('brand_short_name') or CLUB_SHORT_NAME
    return render_template('index.html', app_version=APP_VERSION,
                           club_name=club, club_short_name=short, brand=brand)


# ── API routes ─────────────────────────────────────────────────────────────────

@bp.route('/api/auth/login', methods=['POST'])
@csrf.exempt
def api_login():
    ip      = request.remote_addr or '0.0.0.0'
    allowed, retry_after = _check_login_rate_limit(ip)
    if not allowed:
        return jsonify({
            'error': f'Too many failed login attempts. Please try again in {retry_after // 60 + 1} minutes.'
        }), 429

    data     = request.get_json() or {}
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    db   = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE lower(username) = ? AND active = 1',
        (username,)
    ).fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'),
                                user['password_hash'].encode('utf-8')):
        perms            = []
        role_name        = user['role']
        role_display     = ROLE_DISPLAY_NAMES.get(role_name, role_name)
        resolved_role_id = user['role_id']

        if user['role_id']:
            role_row = db.execute(
                'SELECT id, name, permissions, display_name FROM roles WHERE id = ?',
                (user['role_id'],)
            ).fetchone()
            if role_row:
                resolved_role_id = role_row['id']
                role_name    = role_row['name']
                role_display = role_row['display_name'] or ROLE_DISPLAY_NAMES.get(role_name, role_name)
                try:
                    perms = json.loads(role_row['permissions'])
                except (TypeError, ValueError):
                    perms = []
        else:
            role_row = db.execute(
                'SELECT id, name, permissions, display_name FROM roles WHERE name = ?',
                (user['role'],)
            ).fetchone()
            if role_row:
                resolved_role_id = role_row['id']
                role_display = role_row['display_name'] or ROLE_DISPLAY_NAMES.get(role_name, role_name)
                try:
                    perms = json.loads(role_row['permissions'])
                except (TypeError, ValueError):
                    perms = []

        session['user_id']          = user['id']
        session['username']         = user['username']
        session['role']             = role_name
        session['role_display']     = role_display
        session['role_id']          = resolved_role_id
        session['permissions']      = perms
        session['session_assigned'] = user['session_assigned'] or ''

        db.execute('UPDATE users SET last_login = ? WHERE id = ?',
                   (datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), user['id']))
        db.commit()

        _clear_login_failures(ip)
        log_action('login')

        return jsonify({
            'success': True,
            'redirect': '/dashboard',
            'user': {
                'username':         user['username'],
                'role':             role_name,
                'session_assigned': user['session_assigned'],
            }
        })

    _record_login_failure(ip)
    log_action('login_failed', details={'attempted_username': username})
    return jsonify({'error': 'Incorrect username or password'}), 401


@bp.route('/api/auth/logout', methods=['POST'])
def api_logout():
    log_action('logout')
    session.clear()
    return jsonify({'ok': True})


@bp.route('/api/auth/me')
@login_required
def api_me():
    return jsonify({
        'username':         session['username'],
        'role':             session['role'],
        'role_display':     session.get('role_display', session['role']),
        'session_assigned': session.get('session_assigned', ''),
        'permissions':      session.get('permissions', []),
    })


@bp.route('/api/auth/change-password', methods=['POST'])
@login_required
def api_change_password():
    data       = request.get_json() or {}
    current_pw = data.get('current_password', '')
    new_pw     = data.get('new_password', '')

    if not current_pw or not new_pw:
        return jsonify({'error': 'Both current and new passwords are required'}), 400
    pw_error = validate_password(new_pw)
    if pw_error:
        return jsonify({'error': pw_error}), 400

    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or not bcrypt.checkpw(current_pw.encode('utf-8'),
                                      user['password_hash'].encode('utf-8')):
        return jsonify({'error': 'Current password is incorrect'}), 401

    new_hash = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db.execute('UPDATE users SET password_hash = ? WHERE id = ?',
               (new_hash, session['user_id']))
    db.commit()
    log_action('change_password')
    return jsonify({'success': True})
