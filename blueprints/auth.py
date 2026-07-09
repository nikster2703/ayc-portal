"""
AYC Portal — Authentication blueprint.
Routes: /, /api/auth/*
"""

import json
from datetime import datetime, timezone

import bcrypt
from flask import Blueprint, jsonify, redirect, request, session, url_for

from config import (
    ROLE_DISPLAY_NAMES,
    APP_VERSION, CLUB_NAME, CLUB_SHORT_NAME,
)
from extensions import csrf
from flask import render_template
from helpers import (
    get_db, log_action, login_required, validate_password,
    get_brand_settings, client_ip,
    login_rate_status, record_login_failure, clear_login_failures,
)

bp = Blueprint('auth', __name__)


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
    # v12.42: use client_ip() — behind Caddy request.remote_addr is the proxy's
    # IP, so every user shared one login-failure bucket (10 failures by anyone
    # locked ALL users out for 15 minutes).
    ip      = client_ip()
    allowed, retry_after = login_rate_status(ip)
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

        # Load all sessions this user has access to from the junction table
        sess_rows = db.execute(
            'SELECT st.name FROM user_sessions us '
            'JOIN session_types st ON st.id = us.session_type_id '
            'WHERE us.user_id = ? AND st.active = 1 '
            'ORDER BY st.sort_order, st.name',
            (user['id'],)
        ).fetchall()
        session_names = [r['name'] for r in sess_rows]

        # Determine which session is currently active (persisted in users table)
        active_session = None
        if user['active_session_id']:
            act_row = db.execute(
                'SELECT name FROM session_types WHERE id = ? AND active = 1',
                (user['active_session_id'],)
            ).fetchone()
            if act_row:
                active_session = act_row['name']
        # Fall back to first allowed session if active_session_id not set or no longer valid
        if not active_session and session_names:
            active_session = session_names[0]
            # Persist the fallback so subsequent logins are consistent
            first_id = db.execute(
                'SELECT id FROM session_types WHERE name = ?', (active_session,)
            ).fetchone()
            if first_id:
                db.execute(
                    'UPDATE users SET active_session_id = ? WHERE id = ?',
                    (first_id['id'], user['id'])
                )

        # v12.42: mark the session permanent so app.permanent_session_lifetime
        # (8h) actually applies — without this the lifetime setting had no
        # effect and the cookie was browser-session only. The 30-min idle
        # timeout in app.py still applies on top.
        session.permanent        = True
        session['user_id']       = user['id']
        session['username']      = user['username']
        session['role']          = role_name
        session['role_display']  = role_display
        session['role_id']       = resolved_role_id
        session['permissions']   = perms
        session['session_names'] = session_names
        session['active_session'] = active_session

        db.execute('UPDATE users SET last_login = ? WHERE id = ?',
                   (datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), user['id']))
        db.commit()

        clear_login_failures(ip)
        log_action('login')

        return jsonify({
            'success': True,
            'redirect': '/dashboard',
            'user': {
                'username':       user['username'],
                'role':           role_name,
                'session_names':  session_names,
                'active_session': active_session,
            }
        })

    record_login_failure(ip)
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
        'username':       session['username'],
        'role':           session['role'],
        'role_display':   session.get('role_display', session['role']),
        'session_names':  session.get('session_names', []),
        'active_session': session.get('active_session'),
        'permissions':    session.get('permissions', []),
    })


@bp.route('/api/auth/active-session', methods=['POST'])
@login_required
def api_set_active_session():
    """Switch the user's active session. Persists to DB and updates the Flask session."""
    data         = request.get_json() or {}
    session_name = (data.get('session_name') or '').strip()
    if not session_name:
        return jsonify({'error': 'session_name is required'}), 400

    allowed = session.get('session_names', [])
    if session.get('role') != 'admin' and session_name not in allowed:
        return jsonify({'error': 'You do not have access to that session'}), 403

    db      = get_db()
    st_row  = db.execute(
        'SELECT id FROM session_types WHERE name = ? AND active = 1', (session_name,)
    ).fetchone()
    if not st_row:
        return jsonify({'error': 'Session not found or inactive'}), 404

    db.execute(
        'UPDATE users SET active_session_id = ? WHERE id = ?',
        (st_row['id'], session['user_id'])
    )
    db.commit()
    session['active_session'] = session_name
    log_action('switch_session', details={'session': session_name})
    return jsonify({'ok': True, 'active_session': session_name})


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
