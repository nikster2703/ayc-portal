"""
AYC Portal — Application factory  v10.0
Phases 1–8: Auth, members, audit, user admin, approvals, register,
            documents, comms, term calendar, staff registrations,
            configurable Roles + Permissions, Member Alert Rules,
            Notifications, QR quick sign-in.

All routes live in blueprints/:
  auth          — login/logout/me/change-password
  pages         — HTML page rendering (all templates)
  members       — /api/members/*, /api/field-config, /api/postcode
  approvals     — /api/approvals/*, /api/registration
  attendance    — /api/register/*, /api/display/*
  documents     — /api/documents/*, /api/document-categories/*
  communications— /api/email-templates/*, /api/mailshots/*
  calendar      — /api/calendar/*, /api/session-types
  dashboard     — /api/dashboard, /api/admin/audit*
  admin         — /api/settings, /api/admin/*, import/backup/restore
  alerts        — /api/alert-rules/*, /api/alerts/*, /api/members/*/flags*
  notifications — /api/notifications/*
  qr_signin     — /api/quick-signin/*
"""

import logging
import os
import secrets
import time
from datetime import timedelta
from logging.handlers import RotatingFileHandler

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import Flask, g, jsonify, redirect, request, session, url_for
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException

from config import (
    APP_VERSION, DATABASE, LOG_DIR, UPLOAD_DIR, BRANDING_DIR,
    ALLOWED_EXTENSIONS, SESSION_IDLE_TIMEOUT,
)
from db import ensure_tables
from extensions import csrf
from helpers import close_db, get_brand_settings


# ── Create app ────────────────────────────────────────────────────────────────

app = Flask(__name__)

_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key:
    import warnings
    warnings.warn(
        'SECRET_KEY is not set in .env — a random key will be used and all sessions '
        'will be invalidated on every restart. Set SECRET_KEY in your .env file.',
        stacklevel=2,
    )
    _secret_key = secrets.token_hex(32)

app.secret_key                          = _secret_key
app.permanent_session_lifetime          = timedelta(hours=8)
app.config['WTF_CSRF_HEADERS']          = ['X-CSRFToken']
app.config['WTF_CSRF_TIME_LIMIT']       = None               # bounded by session lifetime
app.config['MAX_CONTENT_LENGTH']        = 20 * 1024 * 1024   # 20 MB max upload
app.config['ALLOWED_EXTENSIONS']        = ALLOWED_EXTENSIONS
# ── Session cookie security ───────────────────────────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY']   = True   # prevent JS access to cookie
app.config['SESSION_COOKIE_SAMESITE']  = 'Lax'  # CSRF mitigation
# Set SECURE only in production so local HTTP dev still works
app.config['SESSION_COOKIE_SECURE']    = os.environ.get('FLASK_DEBUG', '0') != '1'

# Ensure data directories exist
os.makedirs(UPLOAD_DIR,    exist_ok=True)
os.makedirs(LOG_DIR,       exist_ok=True)
os.makedirs(BRANDING_DIR,  exist_ok=True)

# ── CSRF ──────────────────────────────────────────────────────────────────────
# Bind the singleton from extensions.py (blueprints import it for @csrf.exempt)
csrf.init_app(app)

# ── File logging ──────────────────────────────────────────────────────────────
_log_path  = os.path.join(LOG_DIR, 'app.log')
_file_hdlr = RotatingFileHandler(
    _log_path, maxBytes=5 * 1024 * 1024, backupCount=9, encoding='utf-8'
)
_file_hdlr.setLevel(logging.WARNING)
_file_hdlr.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)-8s] %(module)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
))
app.logger.addHandler(_file_hdlr)
app.logger.setLevel(logging.WARNING)


# ── Request lifecycle ─────────────────────────────────────────────────────────

@app.after_request
def _add_security_headers(response):
    """Attach HTTP security headers to every response."""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Prevent MIME-type sniffing (closes the document-serving XSS vector)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Limit referrer information sent to third parties
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Disable browser features we don't use
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # Basic CSP: same-origin scripts/styles only; inline is currently required so
    # unsafe-inline is permitted until scripts are refactored to use nonces.
    # This still blocks third-party script injection.
    if 'Content-Security-Policy' not in response.headers:
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
    return response


@app.teardown_appcontext
def _teardown_db(error):
    close_db(error)


@app.before_request
def enforce_idle_timeout():
    """Expire sessions idle for more than SESSION_IDLE_TIMEOUT seconds."""
    if 'user_id' not in session:
        return
    if request.path == '/api/display/stream':
        return   # SSE long-poll — skip
    now         = time.time()
    last_active = session.get('last_activity', now)
    if now - last_active > SESSION_IDLE_TIMEOUT:
        session.clear()
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Session expired due to inactivity. Please log in again.'}), 401
        return redirect(url_for('auth.login_page'))
    session['last_activity'] = now


# ── Health check ─────────────────────────────────────────────────────────────

@app.route('/api/health')
def health_check():
    """Lightweight liveness probe for Docker / load-balancer healthchecks.
    Returns 200 OK with no auth required.  Does NOT touch the DB.
    """
    return jsonify({'status': 'ok', 'version': APP_VERSION}), 200


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(CSRFError)
def _handle_csrf_error(e):
    return jsonify({'error': 'CSRF token missing or invalid — please refresh the page and try again.'}), 400


@app.errorhandler(Exception)
def _handle_unhandled_exception(exc):
    if isinstance(exc, HTTPException):
        return exc
    app.logger.error('Unhandled exception', exc_info=True)
    return jsonify({'error': 'Internal server error — check System Logs for details'}), 500


# ── Blueprint registration ────────────────────────────────────────────────────

from blueprints.auth          import bp as auth_bp
from blueprints.pages         import bp as pages_bp
from blueprints.members       import bp as members_bp
from blueprints.approvals     import bp as approvals_bp
from blueprints.attendance    import bp as attendance_bp
from blueprints.documents     import bp as documents_bp
from blueprints.communications import bp as communications_bp
from blueprints.calendar      import bp as calendar_bp
from blueprints.dashboard     import bp as dashboard_bp
from blueprints.admin         import bp as admin_bp
from blueprints.alerts        import bp as alerts_bp
from blueprints.notifications import bp as notifications_bp
from blueprints.qr_signin     import bp as qr_signin_bp

app.register_blueprint(auth_bp)
app.register_blueprint(pages_bp)
app.register_blueprint(members_bp)
app.register_blueprint(approvals_bp)
app.register_blueprint(attendance_bp)
app.register_blueprint(documents_bp)
app.register_blueprint(communications_bp)
app.register_blueprint(calendar_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(notifications_bp)
app.register_blueprint(qr_signin_bp)


# ── Database initialisation ───────────────────────────────────────────────────

ensure_tables()


# ── Flask CLI ─────────────────────────────────────────────────────────────────

@app.cli.command('init-db')
def init_db_command():
    """Flask CLI: flask init-db — initialise a fresh database from schema.sql."""
    from db import init_db
    init_db()
    print('Database initialised.')


# ── APScheduler — nightly alert check at 02:00 ───────────────────────────────

def _start_scheduler():
    """Start the background scheduler for nightly alert rule evaluation.
    In Flask debug/reloader mode only start in the child process (WERKZEUG_RUN_MAIN)
    so the scheduler doesn't run twice.
    """
    if os.environ.get('FLASK_DEBUG') == '1':
        if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
            return

    from blueprints.alerts import run_all_alert_rules

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_all_alert_rules,
        CronTrigger(hour=2, minute=0),
        id='nightly_alert_check',
        replace_existing=True,
    )
    scheduler.start()
    print('[alerts] Nightly scheduler started (02:00 daily)')


_start_scheduler()


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        print('First run — initialising database…')
        from db import init_db
        init_db()
    _debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    _port  = int(os.environ.get('PORT', 5001))
    app.run(debug=_debug, host='0.0.0.0', port=_port, threaded=True)
