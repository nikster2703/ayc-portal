"""
AYC Portal — Flask Application  v6.0
Phases 1-6: Auth, members, audit, user admin, approvals, register,
            documents, comms, term calendar, staff registrations,
            configurable Roles + Permissions system.

Phase roadmap (this file grows into blueprints as phases are added):
  Phase 1 — Auth, members lookup, edit/delete, audit log, user admin    ✓
  Phase 2 — Approvals: review pending registrations                     ✓
  Phase 3 — Digital session register + attendance history + auto-leaver ✓
  Phase 4 — Document repository, email templates, mailshots             ✓
  Phase 5 — Term calendar, staff registrations, user permanent delete   ✓
  Phase 6 — Configurable Roles + Permissions (DB-driven, replaces all   ✓
             hard-coded role checks with permission_required decorator)
  Phase 7 — Duke of Edinburgh module

To split into blueprints later, each section marked ## BLUEPRINT: <name>
can be extracted to blueprints/<name>.py and registered with app.register_blueprint().
"""

import os
import json
import secrets
import sqlcipher3 as sqlite3  # SQLCipher — transparent AES-256 encryption at rest
import hashlib
import base64
import re
import smtplib
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from functools import wraps

import bcrypt
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import (Flask, g, jsonify, redirect, render_template,
                   request, session, url_for, send_from_directory,
                   Response, stream_with_context)
from werkzeug.utils import secure_filename

# Load .env before anything reads os.environ
load_dotenv()

# ── App setup ──────────────────────────────────────────────────────────────────

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
app.secret_key = _secret_key
app.permanent_session_lifetime = timedelta(hours=8)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATABASE   = os.path.join(BASE_DIR, 'data', 'ayc.db')
UPLOAD_DIR = os.path.join(BASE_DIR, 'data', 'documents')
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'jpg', 'jpeg', 'png', 'xlsx', 'xls'}
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB max upload

APP_VERSION = 'v6.2'  # Security hardening — SQLCipher DB encryption, document encryption at rest, password policy

# ── Permission catalogue ───────────────────────────────────────────────────────
# Single source of truth for every permission code the app supports.
# Used to seed the DB on first run and to populate the roles editor UI.
ALL_PERMISSIONS = [
    # Members
    ('members.view',        'View Members',            'View member list and full detail cards',               'members'),
    ('members.edit',        'Edit Members',             'Edit member records',                                  'members'),
    ('members.delete',      'Soft Delete Members',      'Mark a member as Leaver (reversible)',                 'members'),
    ('members.hard_delete', 'Permanent Delete Members', 'Permanently and irreversibly delete a member',         'members'),
    # Register / attendance
    ('register.signin',     'Sign In',                  'Sign members in on the session register',              'register'),
    ('register.signout',    'Sign Out',                 'Sign members out on the session register',              'register'),
    ('register.complete',   'Complete Register',        'Lock the register at end of session',                  'register'),
    ('register.reset',      'Reset Register',           'Wipe all sign-in/out data for a session',             'register'),
    ('register.at_risk',    'Mark At Risk',             'Run the at-risk check and flag members',               'register'),
    ('register.print',      'Print Register',           'Print a paper copy of the session register',           'register'),
    # Approvals
    ('approvals.view',      'View Approvals',           'View pending self-registration submissions',           'approvals'),
    ('approvals.approve',   'Approve Registrations',    'Approve a pending registration',                       'approvals'),
    ('approvals.reject',    'Reject Registrations',     'Reject a pending registration',                        'approvals'),
    # Documents
    ('documents.view',      'View Documents',           'Browse the document repository (per-doc rank still applies)', 'documents'),
    ('documents.upload',    'Upload Documents',         'Upload new files to the repository',                   'documents'),
    ('documents.delete',    'Delete Documents',         'Soft-delete documents from the repository',            'documents'),
    # Calendar
    ('calendar.create',     'Create Calendar Sessions', 'Add sessions to the term calendar',                    'calendar'),
    ('calendar.edit',       'Edit Calendar',            'Update session status, notes and term name',           'calendar'),
    ('calendar.delete',     'Delete Calendar Sessions', 'Remove sessions from the term calendar',               'calendar'),
    # Users
    ('users.view',          'View Users',               'View the portal user list',                            'users'),
    ('users.create',        'Create Users',             'Create new portal staff accounts',                     'users'),
    ('users.edit',          'Edit Users',               'Edit existing portal accounts',                        'users'),
    ('users.create.admin',  'Create Admin Users',       'Assign roles that carry admin-level permissions',      'users'),
    ('users.delete',        'Delete Users',             'Permanently delete a portal user account',             'users'),
    # Admin / settings
    ('admin.settings',      'Manage Settings',          'Access and change club settings and roles',            'admin'),
    ('admin.session_types', 'Manage Session Types',     'Create, edit and reorder session types',               'admin'),
    ('admin.maintenance',   'Maintenance Tools',        'Clear audit logs, attendance and registration data',   'admin'),
    # Audit
    ('audit.view',          'View Audit Log',           'View the full system audit log',                       'audit'),
    # Communications
    ('mailshots.send',      'Send Mailshots',           'Send bulk emails to member contacts',                  'communications'),
    ('mailshots.templates', 'Manage Email Templates',   'Create, edit and delete email templates',              'communications'),
    # Display board
    ('activities.manage',   'Manage Activities Board',  'Add and remove activities from the TV display',        'display'),
]

# Default permission sets — exact match to old hard-coded behaviour.
# These seed the roles table on first run; admins can customise from /admin/roles.
DEFAULT_ROLE_PERMISSIONS = {
    'admin': [
        'members.view', 'members.edit', 'members.delete', 'members.hard_delete',
        'register.signin', 'register.signout', 'register.complete', 'register.reset',
        'register.at_risk', 'register.print',
        'approvals.view', 'approvals.approve', 'approvals.reject',
        'documents.view', 'documents.upload', 'documents.delete',
        'calendar.create', 'calendar.edit', 'calendar.delete',
        'users.view', 'users.create', 'users.edit', 'users.create.admin', 'users.delete',
        'admin.settings', 'admin.session_types', 'admin.maintenance',
        'audit.view',
        'mailshots.send', 'mailshots.templates',
        'activities.manage',
    ],
    'editor': [
        'members.view', 'members.edit', 'members.delete',
        'register.signin', 'register.signout', 'register.complete', 'register.at_risk', 'register.print',
        'approvals.view', 'approvals.approve', 'approvals.reject',
        'documents.view', 'documents.upload', 'documents.delete',
        'calendar.create', 'calendar.edit', 'calendar.delete',
        'users.view', 'users.create', 'users.edit',
        'admin.settings',
        'audit.view',
        'mailshots.send', 'mailshots.templates',
        'activities.manage',
    ],
    'leader': [
        'members.view',
        'register.signin', 'register.signout',
        'activities.manage',
    ],
    'readonly': [
        'register.signout',
        'documents.view',
        'activities.manage',
    ],
}

# ── Postcode lookup (getaddress.io) ──────────────────────────────────────────
GETADDRESS_KEY = os.environ.get('GETADDRESS_KEY', '')

# ── SMTP config (set in .env) ─────────────────────────────────────────────────
SMTP_HOST = os.environ.get('MAIL_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('MAIL_PORT', 587))
SMTP_USER = os.environ.get('MAIL_USERNAME', '')
SMTP_PASS = os.environ.get('MAIL_PASSWORD', '')
SMTP_FROM = os.environ.get('MAIL_FROM', SMTP_USER)

# ── Club identity (multi-tenant) ──────────────────────────────────────────────
CLUB_NAME       = os.environ.get('CLUB_NAME',       'Ashford Youth Club')
CLUB_SHORT_NAME = os.environ.get('CLUB_SHORT_NAME', 'AYC')

# ── Database helpers ───────────────────────────────────────────────────────────

def _connect_db(path=None):
    """Open a SQLCipher-encrypted DB connection.

    Raises RuntimeError on startup if DB_ENCRYPTION_KEY is missing — the app
    must never run without the key once the database is encrypted.
    Verifies the key immediately so a wrong key fails fast and clearly.
    """
    if path is None:
        path = DATABASE
    key = os.environ.get('DB_ENCRYPTION_KEY')
    if not key:
        raise RuntimeError(
            'DB_ENCRYPTION_KEY is not set in .env — refusing to start. '
            'Add the key to .env and restart the portal.'
        )
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA key='{key}'")
    conn.execute('SELECT count(*) FROM sqlite_master')  # verify key immediately
    return conn


# ── Document encryption helpers ────────────────────────────────────────────────

def _doc_fernet():
    """Return a Fernet instance derived from DB_ENCRYPTION_KEY.

    We derive a 32-byte key by SHA-256 hashing the DB_ENCRYPTION_KEY so that
    a single key in .env covers both database and document encryption.
    Raises RuntimeError if the key is missing — same hard-fail policy as the DB.
    """
    raw_key = os.environ.get('DB_ENCRYPTION_KEY')
    if not raw_key:
        raise RuntimeError(
            'DB_ENCRYPTION_KEY is not set in .env — cannot encrypt/decrypt documents.'
        )
    derived = hashlib.sha256(raw_key.encode()).digest()  # always 32 bytes
    fernet_key = base64.urlsafe_b64encode(derived)
    return Fernet(fernet_key)


def encrypt_file(data: bytes) -> bytes:
    """Encrypt raw file bytes. Returns Fernet token (bytes)."""
    return _doc_fernet().encrypt(data)


def decrypt_file(token: bytes) -> bytes:
    """Decrypt a Fernet token back to the original file bytes."""
    return _doc_fernet().decrypt(token)


def get_db():
    """Return a request-scoped DB connection with SQLCipher encryption."""
    if 'db' not in g:
        g.db = _connect_db()
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def log_action(action, table_name=None, record_id=None, details=None):
    """Write an entry to the audit log. Never raises — logging must not break the app."""
    try:
        db = get_db()
        db.execute(
            'INSERT INTO audit_log (user_id, action, table_name, record_id, details, ip_address)'
            ' VALUES (?,?,?,?,?,?)',
            (
                session.get('user_id'),
                action,
                table_name,
                record_id,
                json.dumps(details) if details else None,
                request.remote_addr,
            )
        )
        db.commit()
    except Exception:
        pass

def init_db():
    """Initialise the database from schema.sql. Safe to run multiple times."""
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    db = _connect_db()
    with open(os.path.join(BASE_DIR, 'schema.sql'), 'r') as f:
        db.executescript(f.read())
    db.commit()
    db.close()
    print(f'Database initialised at {DATABASE}')

@app.cli.command('init-db')
def init_db_command():
    """Flask CLI: flask init-db"""
    init_db()

def ensure_tables():
    """Create any tables added after initial deploy without requiring a full init-db.
    Safe to run on every startup — all operations are idempotent."""
    db = _connect_db()

    # ── Tables ────────────────────────────────────────────────────────────────
    db.executescript('''
        CREATE TABLE IF NOT EXISTS session_activities (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_type TEXT    NOT NULL,
            activity     TEXT    NOT NULL,
            added_by     INTEGER REFERENCES users(id),
            created_at   TEXT    DEFAULT (datetime('now')),
            active       INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS term_sessions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_date TEXT    NOT NULL,
            session_type TEXT    NOT NULL,
            term_name    TEXT,
            status       TEXT    NOT NULL DEFAULT 'planned',
            notes        TEXT,
            created_by   INTEGER REFERENCES users(id),
            created_at   TEXT    DEFAULT (datetime('now')),
            UNIQUE(session_date, session_type)
        );
        CREATE INDEX IF NOT EXISTS idx_term_sessions_date ON term_sessions(session_date);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp    ON audit_log(timestamp);
        CREATE TABLE IF NOT EXISTS session_completions (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            session_date       TEXT    NOT NULL,
            session_type       TEXT    NOT NULL,
            completed_by       INTEGER REFERENCES users(id),
            completed_at       TEXT    DEFAULT (datetime('now')),
            auto_signout_count INTEGER DEFAULT 0,
            UNIQUE(session_date, session_type)
        );
        CREATE TABLE IF NOT EXISTS session_types (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL UNIQUE,
            weekday    INTEGER NOT NULL,
            active     INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS settings (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            updated_at TEXT,
            updated_by INTEGER REFERENCES users(id)
        );
        -- v6.0: permissions catalogue and configurable roles
        CREATE TABLE IF NOT EXISTS permissions (
            code        TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            description TEXT,
            category    TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS roles (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    UNIQUE NOT NULL,
            is_default  INTEGER DEFAULT 0,
            permissions TEXT    NOT NULL,
            created_at  TEXT    DEFAULT (datetime('now'))
        );
    ''')

    # ── ALTER TABLE migrations (idempotent — each wrapped individually) ───────
    alter_stmts = [
        "ALTER TABLE members ADD COLUMN member_type TEXT NOT NULL DEFAULT 'member'",
        "ALTER TABLE members ADD COLUMN staff_role TEXT",
        "ALTER TABLE pending_registrations ADD COLUMN registration_type TEXT NOT NULL DEFAULT 'member'",
        "ALTER TABLE pending_registrations ADD COLUMN applicant_role TEXT",
        "ALTER TABLE pending_registrations ADD COLUMN mobile TEXT",
        "ALTER TABLE pending_registrations ADD COLUMN email TEXT",
        "ALTER TABLE members ADD COLUMN status_note TEXT",
        # v6.0: link users to the new roles table
        "ALTER TABLE users ADD COLUMN role_id INTEGER REFERENCES roles(id)",
    ]
    for stmt in alter_stmts:
        try:
            db.execute(stmt)
        except Exception:
            pass  # Column already exists — safe to ignore

    db.commit()
    db.close()

    # ── Seed default settings ─────────────────────────────────────────────────
    sdb = _connect_db()
    sdb.row_factory = sqlite3.Row
    for key, val in [
        ('at_risk_threshold_tuesday',  '5'),
        ('at_risk_threshold_thursday', '5'),
    ]:
        if not sdb.execute('SELECT key FROM settings WHERE key = ?', (key,)).fetchone():
            sdb.execute('INSERT INTO settings (key, value) VALUES (?, ?)', (key, val))
    sdb.commit()
    sdb.close()

    # ── Seed default session types ─────────────────────────────────────────────
    tdb = _connect_db()
    for sort_order, (name, weekday) in enumerate([('Tuesday', 1), ('Thursday', 3)]):
        if not tdb.execute('SELECT id FROM session_types WHERE name = ?', (name,)).fetchone():
            tdb.execute(
                'INSERT INTO session_types (name, weekday, active, sort_order) VALUES (?,?,1,?)',
                (name, weekday, sort_order),
            )
    tdb.commit()
    tdb.close()

    # ── Seed permissions catalogue (v6.0) ──────────────────────────────────────
    pdb = _connect_db()
    for code, name, desc, cat in ALL_PERMISSIONS:
        pdb.execute(
            'INSERT OR IGNORE INTO permissions (code, name, description, category) VALUES (?,?,?,?)',
            (code, name, desc, cat),
        )
    pdb.commit()
    pdb.close()

    # ── Seed default roles (v6.0) ──────────────────────────────────────────────
    rdb = _connect_db()
    rdb.row_factory = sqlite3.Row
    for role_name, perms in DEFAULT_ROLE_PERMISSIONS.items():
        rdb.execute(
            'INSERT OR IGNORE INTO roles (name, permissions, is_default) VALUES (?,?,1)',
            (role_name, json.dumps(perms)),
        )
    rdb.commit()

    # ── Migrate existing users → role_id (v6.0) ───────────────────────────────
    # Any user whose role_id is still NULL gets it set from their old role text column.
    users_needing_migration = rdb.execute(
        'SELECT id, role FROM users WHERE role_id IS NULL'
    ).fetchall()
    for user in users_needing_migration:
        role_row = rdb.execute(
            'SELECT id FROM roles WHERE name = ?', (user['role'],)
        ).fetchone()
        if role_row:
            rdb.execute(
                'UPDATE users SET role_id = ? WHERE id = ?',
                (role_row['id'], user['id']),
            )
    rdb.commit()
    rdb.close()

# Run migration on startup
with app.app_context():
    if os.path.exists(DATABASE):
        ensure_tables()

# ── Password policy ────────────────────────────────────────────────────────────

def validate_password(password):
    """Enforce the portal password policy.
    Returns an error string if the password fails, or None if it passes.
    Policy: 8+ characters, at least one uppercase letter, one number, one special character.
    """
    if len(password) < 8:
        return 'Password must be at least 8 characters'
    if not re.search(r'[A-Z]', password):
        return 'Password must contain at least one uppercase letter'
    if not re.search(r'[0-9]', password):
        return 'Password must contain at least one number'
    if not re.search(r'[^A-Za-z0-9]', password):
        return 'Password must contain at least one special character'
    return None


# ── Auth helpers ───────────────────────────────────────────────────────────────

def login_required(f):
    """Redirect to login (or return 401) if user is not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorised'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def permission_required(permission_code):
    """Restrict access to users whose role includes the given permission code."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            if permission_code not in session.get('permissions', []):
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Forbidden'}), 403
                return redirect(url_for('dashboard_page'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def has_permission(permission_code):
    """Return True if the current session user has the given permission.
    Safe to call from templates and helper functions."""
    return permission_code in session.get('permissions', [])

def tpl_ctx():
    """Inject current user info into every protected template."""
    return {
        'current_user':     session.get('username', ''),
        'current_role':     session.get('role', ''),
        'current_session':  session.get('session_assigned', ''),
        'app_version':      APP_VERSION,
        'session_types':    get_session_types(),        # [{id, name, weekday}, ...]
        'user_permissions': session.get('permissions', []),  # list of permission codes
        'club_name':        CLUB_NAME,
        'club_short_name':  CLUB_SHORT_NAME,
    }

# ── Page routes ────────────────────────────────────────────────────────────────

@app.route('/')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard_page'))
    return render_template('index.html', app_version=APP_VERSION,
                           club_name=CLUB_NAME, club_short_name=CLUB_SHORT_NAME)

@app.route('/dashboard')
@login_required
def dashboard_page():
    return render_template('dashboard.html', active_page='dashboard', **tpl_ctx())

@app.route('/members')
@permission_required('members.view')
def members_page():
    return render_template('members.html', active_page='members', **tpl_ctx())

@app.route('/approvals')
@permission_required('approvals.view')
def approvals_page():
    return render_template('approvals.html', active_page='approvals', **tpl_ctx())

@app.route('/register')
@login_required
def register_page():
    return render_template('register.html', active_page='register', **tpl_ctx())


@app.route('/register/print')
@login_required
def print_register_page():
    """
    Render a printable paper register for a given session and date.
    Accessible to editors and admins only (register.print permission).
    Query params: ?session=Tuesday&date=2026-04-18
    """
    if not has_permission('register.print'):
        return 'Access denied', 403

    session_type = request.args.get('session', '').strip()
    date         = request.args.get('date', '').strip()

    if not session_type or not date:
        return 'Missing session or date parameter', 400

    # Validate session type
    valid_sessions = get_valid_session_names()
    if session_type not in valid_sessions:
        return 'Invalid session type', 400

    db = get_db()

    # Fetch all active members for this session, sorted alphabetically
    members = db.execute('''
        SELECT  m.id, m.first_name, m.surname, m.unattended_exit
        FROM    members m
        WHERE   m.status     != "Leaver"
          AND   m.member_type = "member"
          AND   m.session     = ?
        ORDER   BY m.first_name, m.surname
    ''', (session_type,)).fetchall()

    # Format date nicely for display (YYYY-MM-DD → DD/MM/YYYY)
    try:
        from datetime import datetime as _dt
        display_date = _dt.strptime(date, '%Y-%m-%d').strftime('%d/%m/%Y')
    except ValueError:
        display_date = date

    return render_template(
        'print_register.html',
        session_type=session_type,
        date=date,
        display_date=display_date,
        members=[dict(r) for r in members],
        club_name=CLUB_NAME,
        club_short_name=CLUB_SHORT_NAME,
    )


@app.route('/registration')
def registration_page():
    """Landing page — choose member or staff registration."""
    return render_template('registration_landing.html',
                           club_name=CLUB_NAME, club_short_name=CLUB_SHORT_NAME)

@app.route('/registration/member')
def registration_member_page():
    """Full member self-registration form — no login required."""
    return render_template('registration.html', version=APP_VERSION,
                           club_name=CLUB_NAME, club_short_name=CLUB_SHORT_NAME)

@app.route('/registration/staff')
def registration_staff_page():
    """Simplified staff/volunteer registration form — no login required."""
    return render_template('registration_staff.html', version=APP_VERSION,
                           session_types=get_session_types(),
                           club_name=CLUB_NAME, club_short_name=CLUB_SHORT_NAME)

@app.route('/documents')
@permission_required('documents.view')
def documents_page():
    return render_template('documents.html', active_page='documents', **tpl_ctx())

@app.route('/communications')
@permission_required('mailshots.send')
def communications_page():
    return render_template('communications.html', active_page='communications', **tpl_ctx())

@app.route('/admin/users')
@permission_required('users.view')
def users_page():
    return render_template('admin/users.html', active_page='users', **tpl_ctx())

@app.route('/admin/audit')
@permission_required('audit.view')
def audit_page():
    return render_template('admin/audit.html', active_page='audit', **tpl_ctx())

@app.route('/admin/settings')
@permission_required('admin.settings')
def settings_page():
    return render_template('admin/settings.html', active_page='settings', **tpl_ctx())

@app.route('/admin/roles')
@permission_required('admin.settings')
def roles_page():
    return render_template('admin/roles.html', active_page='roles', **tpl_ctx())

@app.route('/admin/staff-roles')
@permission_required('admin.settings')
def staff_roles_page():
    return render_template('admin/staff_roles.html', active_page='staff_roles', **tpl_ctx())

@app.route('/api/settings')
@permission_required('admin.settings')
def api_settings_get():
    """Return all settings as a key/value dict."""
    db   = get_db()
    rows = db.execute('SELECT key, value FROM settings').fetchall()
    return jsonify({r['key']: r['value'] for r in rows})

@app.route('/api/settings', methods=['POST'])
@permission_required('admin.settings')
def api_settings_save():
    """Save one or more settings. Body: {key: value, ...}
    Only at-risk thresholds are modifiable here; register permissions
    are now managed via the Roles system (/admin/roles)."""
    data = request.get_json() or {}
    allowed_keys = {'at_risk_threshold_tuesday', 'at_risk_threshold_thursday'}

    # Non-admin users are scoped — can only update threshold for their own session
    scoped = _assigned_session()
    if scoped is not None:
        session_key = f'at_risk_threshold_{scoped.lower()}'
        allowed_keys = {session_key}

    db = get_db()
    for key, value in data.items():
        if key not in allowed_keys:
            continue
        try:
            val = int(value)
            if val < 1:
                return jsonify({'error': f'Threshold must be at least 1'}), 400
        except (TypeError, ValueError):
            return jsonify({'error': f'Invalid value for {key}'}), 400
        db.execute(
            'INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime("now"), ?)'
            ' ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by',
            (key, str(val), session['user_id'])
        )
    db.commit()
    log_action('update_settings', 'settings', None, {'changes': data})
    return jsonify({'success': True})

# ── BLUEPRINT: auth ────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def api_login():
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
        # Load permissions from the roles table via role_id.
        # Fall back to the role text column if role_id is not yet set
        # (safety net for the one-release transition period).
        perms = []
        role_name = user['role']
        if user['role_id']:
            role_row = db.execute(
                'SELECT name, permissions FROM roles WHERE id = ?', (user['role_id'],)
            ).fetchone()
            if role_row:
                role_name = role_row['name']
                try:
                    perms = json.loads(role_row['permissions'])
                except (TypeError, ValueError):
                    perms = []
        else:
            # Fallback: look up by role name (covers users not yet migrated)
            role_row = db.execute(
                'SELECT name, permissions FROM roles WHERE name = ?', (user['role'],)
            ).fetchone()
            if role_row:
                try:
                    perms = json.loads(role_row['permissions'])
                except (TypeError, ValueError):
                    perms = []

        session.permanent = True
        session['user_id']          = user['id']
        session['username']         = user['username']
        session['role']             = role_name          # kept for _assigned_session() + templates
        session['permissions']      = perms              # v6.0: full permission list
        session['session_assigned'] = user['session_assigned'] or ''

        db.execute('UPDATE users SET last_login = ? WHERE id = ?',
                   (datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), user['id']))
        db.commit()

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

    return jsonify({'error': 'Incorrect username or password'}), 401

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/auth/me')
@login_required
def api_me():
    return jsonify({
        'username':         session['username'],
        'role':             session['role'],
        'session_assigned': session.get('session_assigned', ''),
        'permissions':      session.get('permissions', []),
    })

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def api_change_password():
    data         = request.get_json() or {}
    current_pw   = data.get('current_password', '')
    new_pw       = data.get('new_password', '')

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

# ── BLUEPRINT: members ─────────────────────────────────────────────────────────

@app.route('/api/members')
@permission_required('members.view')
def api_members():
    db = get_db()

    status_filter  = request.args.get('status', 'active')  # active | leaver | at_risk | all
    session_filter = request.args.get('session', 'all')     # all | Tuesday | Thursday

    conditions = ['1=1']
    params = []

    if status_filter == 'active':
        conditions.append("m.status NOT IN ('Leaver', 'At Risk')")
    elif status_filter == 'leaver':
        conditions.append("m.status = 'Leaver'")
    elif status_filter == 'at_risk':
        conditions.append("m.status = 'At Risk'")

    if session_filter != 'all':
        conditions.append('m.session = ?')
        params.append(session_filter)

    # All non-admin roles are scoped to their assigned session.
    # No session assigned → return empty (safest default).
    scoped = _assigned_session()
    if scoped is not None:           # non-admin
        if not scoped:
            return jsonify([])       # no session set — return empty
        conditions.append('m.session = ?')
        params.append(scoped)

    # Leaders cannot see staff/volunteer records — youth members only.
    if session.get('role') == 'leader':
        conditions.append("m.member_type = 'member'")

    where = ' AND '.join(conditions)

    rows = db.execute(f'''
        SELECT  m.*,
                c1.contact_name  AS contact1_name,
                c1.contact_phone AS contact1_phone,
                c1.contact_email AS contact1_email,
                c2.contact_name  AS contact2_name,
                c2.contact_phone AS contact2_phone,
                c2.contact_email AS contact2_email
        FROM    members m
        LEFT JOIN member_contacts c1
               ON c1.member_id = m.id AND c1.contact_order = 1
        LEFT JOIN member_contacts c2
               ON c2.member_id = m.id AND c2.contact_order = 2
        WHERE   {where}
        ORDER   BY m.first_name, m.surname
    ''', params).fetchall()

    return jsonify([dict(r) for r in rows])

@app.route('/api/members/<int:member_id>')
@permission_required('members.view')
def api_member_detail(member_id):
    db     = get_db()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Not found'}), 404

    # Enforce session scope for non-admin roles
    scoped = _assigned_session()
    if scoped is not None and member['session'] != scoped:
        return jsonify({'error': 'Forbidden'}), 403

    contacts = db.execute(
        'SELECT * FROM member_contacts WHERE member_id = ? ORDER BY contact_order',
        (member_id,)
    ).fetchall()

    result             = dict(member)
    result['contacts'] = [dict(c) for c in contacts]
    return jsonify(result)

@app.route('/api/members/<int:member_id>/viewed', methods=['POST'])
@permission_required('members.view')
def api_member_viewed(member_id):
    """Record in the audit log that a member's card was opened and their details viewed."""
    db     = get_db()
    member = db.execute('SELECT first_name, surname, session FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Not found'}), 404

    # Enforce session scope for non-admin roles
    scoped = _assigned_session()
    if scoped is not None and member['session'] != scoped:
        return jsonify({'error': 'Forbidden'}), 403

    log_action('view_member', 'members', member_id, {
        'member':    f"{member['first_name']} {member['surname']}",
        'viewed_by': session['username'],
    })
    return jsonify({'ok': True})


@app.route('/api/members/<int:member_id>', methods=['PUT'])
@permission_required('members.edit')
def api_member_update(member_id):
    """Edit a member record. Logs every change to the audit trail."""
    data = request.get_json() or {}
    db   = get_db()

    before = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not before:
        return jsonify({'error': 'Not found'}), 404

    # Enforce session scope for non-admin roles
    scoped = _assigned_session()
    if scoped is not None and before['session'] != scoped:
        return jsonify({'error': 'Forbidden'}), 403

    text_fields = ['first_name', 'surname', 'date_of_birth', 'address', 'postcode',
                   'ethnicity_religion', 'medical_sen', 'gp_contact', 'status',
                   'session', 'comments']
    bool_fields = ['unattended_exit', 'gdpr_consent']

    updates, params = [], []
    changes = {}

    for field in text_fields:
        if field in data:
            updates.append(f'{field} = ?')
            params.append(data[field])
            if str(before[field] or '') != str(data[field] or ''):
                changes[field] = {'from': before[field], 'to': data[field]}

    for field in bool_fields:
        if field in data:
            new_val = 1 if data[field] else 0
            updates.append(f'{field} = ?')
            params.append(new_val)
            if before[field] != new_val:
                changes[field] = {'from': bool(before[field]), 'to': bool(new_val)}

    updates += ['updated_at = datetime("now")', 'updated_by = ?']
    params  += [session['user_id'], member_id]

    db.execute(f"UPDATE members SET {', '.join(updates)} WHERE id = ?", params)

    # Contacts — replace wholesale if provided
    if 'contacts' in data:
        db.execute('DELETE FROM member_contacts WHERE member_id = ?', (member_id,))
        for c in data['contacts']:
            if c.get('contact_name') or c.get('contact_phone') or c.get('contact_email'):
                db.execute(
                    'INSERT INTO member_contacts'
                    ' (member_id, contact_order, contact_name, contact_phone, contact_email)'
                    ' VALUES (?,?,?,?,?)',
                    (member_id, c.get('contact_order', 1),
                     c.get('contact_name', ''), c.get('contact_phone', ''),
                     c.get('contact_email', ''))
                )

    db.commit()
    log_action('edit_member', 'members', member_id, {
        'member': f"{before['first_name']} {before['surname']}",
        'editor': session['username'],
        'changes': changes,
    })
    return jsonify({'success': True})


@app.route('/api/members/<int:member_id>', methods=['DELETE'])
@permission_required('members.delete')
def api_member_delete(member_id):
    """
    Soft-delete: mark member as Leaver. Requires a reason.
    Core Leader and Admin only. Record is kept for audit/history.
    """
    data   = request.get_json() or {}
    reason = data.get('reason', '').strip()
    if not reason:
        return jsonify({'error': 'A reason is required when marking a member as Leaver'}), 400

    db     = get_db()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Not found'}), 404

    # Enforce session scope for non-admin roles
    scoped = _assigned_session()
    if scoped is not None and member['session'] != scoped:
        return jsonify({'error': 'Forbidden'}), 403

    db.execute(
        "UPDATE members SET status = 'Leaver', status_note = ?, "
        "updated_at = datetime('now'), updated_by = ? WHERE id = ?",
        (reason, session['user_id'], member_id)
    )
    db.commit()
    log_action('soft_delete_member', 'members', member_id,
               {'member':  f"{member['first_name']} {member['surname']}",
                'reason':  reason,
                'by':      session['username']})
    return jsonify({'success': True})


@app.route('/api/members/<int:member_id>/permanent', methods=['DELETE'])
@permission_required('members.hard_delete')
def api_member_permanent_delete(member_id):
    """
    Permanently and irreversibly delete a member and ALL associated data.
    Admin only. Wrapped in a transaction — either everything goes or nothing does.
    Requires confirmation token (member's full name) to prevent accidental calls.
    """
    data  = request.get_json() or {}
    token = data.get('confirm_name', '').strip()

    db     = get_db()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Member not found'}), 404

    expected = f"{member['first_name']} {member['surname']}"
    if token.lower() != expected.lower():
        return jsonify({'error': 'Confirmation name does not match — deletion cancelled'}), 400

    # Gather counts for the audit entry before we delete anything
    att_count = db.execute(
        'SELECT COUNT(*) AS n FROM attendance WHERE member_id = ?', (member_id,)
    ).fetchone()['n']
    dofe_count = db.execute(
        'SELECT COUNT(*) AS n FROM dofe_participants WHERE member_id = ?', (member_id,)
    ).fetchone()['n']
    contact_count = db.execute(
        'SELECT COUNT(*) AS n FROM member_contacts WHERE member_id = ?', (member_id,)
    ).fetchone()['n']

    # Write the audit entry BEFORE deletion (same connection, inside transaction)
    # so the log is committed atomically with the delete.
    try:
        db.execute('BEGIN')

        # 1. Attendance records
        db.execute('DELETE FROM attendance WHERE member_id = ?', (member_id,))
        # 2. DoE participants
        db.execute('DELETE FROM dofe_participants WHERE member_id = ?', (member_id,))
        # 3. Member contacts (CASCADE would handle this but being explicit)
        db.execute('DELETE FROM member_contacts WHERE member_id = ?', (member_id,))
        # 4. Nullify the reviewed_by link on any pending_registrations (no FK, just housekeeping)
        db.execute(
            "UPDATE pending_registrations SET notes = COALESCE(notes || ' ', '') || '[Member record permanently deleted]'"
            " WHERE id IN ("
            "  SELECT id FROM pending_registrations WHERE status = 'approved'"
            "  AND first_name = ? AND surname = ?"
            ")",
            (member['first_name'], member['surname'])
        )
        # 5. Audit log entry — written inside transaction so it commits or rolls back together
        db.execute(
            'INSERT INTO audit_log (user_id, action, table_name, record_id, details, ip_address)'
            ' VALUES (?,?,?,?,?,?)',
            (
                session.get('user_id'),
                'permanent_delete_member',
                'members',
                member_id,
                json.dumps({
                    'member':        expected,
                    'member_id':     member['member_id'],
                    'session':       member['session'],
                    'deleted_by':    session.get('username'),
                    'att_deleted':   att_count,
                    'dofe_deleted':  dofe_count,
                    'contacts_deleted': contact_count,
                }),
                request.remote_addr,
            )
        )
        # 6. The member row itself — last
        db.execute('DELETE FROM members WHERE id = ?', (member_id,))

        db.execute('COMMIT')
    except Exception as e:
        db.execute('ROLLBACK')
        return jsonify({'error': f'Deletion failed and was rolled back: {str(e)}'}), 500

    return jsonify({
        'success':  True,
        'deleted':  expected,
        'summary': {
            'attendance': att_count,
            'contacts':   contact_count,
            'dofe':       dofe_count,
        }
    })


@app.route('/api/dashboard')
@login_required
def api_dashboard():
    """Summary stats for the dashboard home page. Session-scoped for all non-admin roles."""
    db    = get_db()
    today = datetime.now().strftime('%Y-%m-%d')

    scoped = _assigned_session()   # None for admin, session string for everyone else

    if scoped is None:
        # Admin — global counts
        counts = db.execute('''
            SELECT
                SUM(CASE WHEN member_type = "member"                        THEN 1 ELSE 0 END) AS total,
                SUM(CASE WHEN member_type = "member" AND status != "Leaver" THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN member_type = "member" AND status  = "Leaver" THEN 1 ELSE 0 END) AS leavers,
                SUM(CASE WHEN member_type = "member" AND status  = "At Risk" THEN 1 ELSE 0 END) AS at_risk,
                SUM(CASE WHEN member_type = "staff"  AND status != "Leaver" THEN 1 ELSE 0 END) AS staff_active
            FROM members
        ''').fetchone()
        # Per-session counts (dynamic)
        session_rows = db.execute('''
            SELECT session,
                   SUM(CASE WHEN member_type = "member" AND status != "Leaver" THEN 1 ELSE 0 END) AS members,
                   SUM(CASE WHEN member_type = "staff"  AND status != "Leaver" THEN 1 ELSE 0 END) AS staff
            FROM members GROUP BY session
        ''').fetchall()
        pending = db.execute(
            'SELECT COUNT(*) AS n FROM pending_registrations WHERE status = "pending"'
        ).fetchone()['n']
    else:
        # Scoped user — counts restricted to their session only
        counts = db.execute('''
            SELECT
                SUM(CASE WHEN member_type = "member"                        THEN 1 ELSE 0 END) AS total,
                SUM(CASE WHEN member_type = "member" AND status != "Leaver" THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN member_type = "member" AND status  = "Leaver" THEN 1 ELSE 0 END) AS leavers,
                SUM(CASE WHEN member_type = "member" AND status  = "At Risk" THEN 1 ELSE 0 END) AS at_risk,
                SUM(CASE WHEN member_type = "staff"  AND status != "Leaver" THEN 1 ELSE 0 END) AS staff_active
            FROM members WHERE session = ?
        ''', (scoped,)).fetchone()
        # Per-session counts (scoped — only the user's session)
        session_rows = db.execute('''
            SELECT session,
                   SUM(CASE WHEN member_type = "member" AND status != "Leaver" THEN 1 ELSE 0 END) AS members,
                   SUM(CASE WHEN member_type = "staff"  AND status != "Leaver" THEN 1 ELSE 0 END) AS staff
            FROM members WHERE session = ? GROUP BY session
        ''', (scoped,)).fetchall()
        pending = db.execute(
            'SELECT COUNT(*) AS n FROM pending_registrations WHERE status = "pending"'
            ' AND (assigned_session = ? OR assigned_session IS NULL OR assigned_session = "")',
            (scoped,)
        ).fetchone()['n']

    # Build per-session dict: {session_name: {members: N, staff: N}}
    session_counts = {r['session']: {'members': r['members'], 'staff': r['staff']}
                      for r in session_rows}

    # Today's attendance (scoped where applicable)
    if scoped is None:
        today_att = db.execute('''
            SELECT COUNT(*) AS total_signed_in,
                   SUM(CASE WHEN signed_out_at IS NOT NULL THEN 1 ELSE 0 END) AS signed_out,
                   session_type
            FROM attendance
            WHERE session_date = ?
            GROUP BY session_type
        ''', (today,)).fetchall()
    else:
        today_att = db.execute('''
            SELECT COUNT(*) AS total_signed_in,
                   SUM(CASE WHEN signed_out_at IS NOT NULL THEN 1 ELSE 0 END) AS signed_out,
                   session_type
            FROM attendance
            WHERE session_date = ? AND session_type = ?
            GROUP BY session_type
        ''', (today, scoped)).fetchall()

    # Recent audit log (last 8 entries)
    recent = db.execute('''
        SELECT a.action, a.details, a.timestamp, u.username
        FROM   audit_log a
        LEFT JOIN users u ON u.id = a.user_id
        ORDER  BY a.timestamp DESC
        LIMIT  8
    ''').fetchall()

    return jsonify({
        'members':          dict(counts),
        'session_counts':   session_counts,   # {session_name: {members, staff}}
        'pending_approvals': pending,
        'today_attendance': [dict(r) for r in today_att],
        'recent_activity':  [dict(r) for r in recent],
        'scoped_session':   scoped,
    })


@app.route('/api/admin/audit')
@permission_required('audit.view')
def api_audit_log():
    """Return recent audit log entries."""
    limit  = min(int(request.args.get('limit', 200)), 500)
    offset = int(request.args.get('offset', 0))
    db     = get_db()
    rows   = db.execute('''
        SELECT  a.*, u.username
        FROM    audit_log a
        LEFT JOIN users u ON u.id = a.user_id
        ORDER   BY a.timestamp DESC
        LIMIT   ? OFFSET ?
    ''', (limit, offset)).fetchall()
    return jsonify([dict(r) for r in rows])


# ── BLUEPRINT: postcode lookup proxy ─────────────────────────────────────────

@app.route('/api/postcode/<path:postcode>')
def api_postcode_lookup(postcode):
    """Proxy getaddress.io lookups server-side to avoid browser CORS restrictions."""
    if not GETADDRESS_KEY:
        return jsonify({'error': 'Address lookup not configured on this server'}), 503

    clean = urllib.parse.quote(postcode.replace(' ', '').upper())
    url   = f'https://ga.ideal-postcodes.co.uk/find/{clean}?api-key={GETADDRESS_KEY}'

    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        return jsonify(data)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            parsed = json.loads(body)
            return jsonify(parsed), e.code
        except Exception:
            return jsonify({'error': body, 'http_status': e.code}), e.code
    except Exception as e:
        return jsonify({'error': str(e), 'type': type(e).__name__}), 502



# ── BLUEPRINT: staff roles (public read) ──────────────────────────────────────

@app.route('/api/staff-roles')
def api_staff_roles_public():
    """Return active staff roles ordered by display_order — no auth required (used on public registration form)."""
    db   = get_db()
    rows = db.execute(
        'SELECT id, name, display_order FROM staff_roles WHERE active = 1 ORDER BY display_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ── BLUEPRINT: registration (public) ──────────────────────────────────────────

@app.route('/api/registration', methods=['POST'])
def api_registration():
    """Accept a public self-registration (member or staff) and store it as pending."""
    data  = request.get_json() or {}
    rtype = data.get('registration_type', 'member')

    if rtype not in ('member', 'staff'):
        return jsonify({'error': 'Invalid registration type'}), 400
    if not data.get('first_name', '').strip() or not data.get('surname', '').strip():
        return jsonify({'error': 'First name and surname are required'}), 400

    db = get_db()

    if rtype == 'staff':
        # Simplified staff/volunteer registration
        applicant_role = data.get('applicant_role', '').strip()
        valid_roles = [r['name'] for r in db.execute(
            'SELECT name FROM staff_roles WHERE active = 1'
        ).fetchall()]
        if applicant_role not in valid_roles:
            return jsonify({'error': 'Invalid role'}), 400
        session_pref = data.get('assigned_session', '').strip()
        if session_pref not in get_valid_session_names():
            return jsonify({'error': 'Invalid session preference'}), 400

        db.execute('''
            INSERT INTO pending_registrations
                (first_name, surname, date_of_birth, address, postcode,
                 mobile, email, registration_type, applicant_role, assigned_session)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        ''', (
            data.get('first_name', '').strip(),
            data.get('surname', '').strip(),
            data.get('date_of_birth', ''),
            data.get('address', '').strip(),
            data.get('postcode', '').strip(),
            data.get('mobile', '').strip(),
            data.get('email', '').strip(),
            'staff',
            applicant_role,
            session_pref,
        ))
    else:
        # Full member registration
        db.execute('''
            INSERT INTO pending_registrations
                (first_name, surname, date_of_birth, address, postcode,
                 ethnicity_religion, medical_sen, gp_contact,
                 unattended_exit, gdpr_consent, comms_consent,
                 contact1_name, contact1_phone, contact1_email,
                 contact2_name, contact2_phone, contact2_email,
                 declarations, registration_type)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            data.get('first_name', '').strip(),
            data.get('surname', '').strip(),
            data.get('date_of_birth', ''),
            data.get('address', '').strip(),
            data.get('postcode', '').strip(),
            data.get('ethnicity_religion', '').strip(),
            data.get('medical_sen', '').strip(),
            data.get('gp_contact', '').strip(),
            1 if data.get('unattended_exit') else 0,
            1 if data.get('gdpr_consent') else 0,
            1 if data.get('comms_consent') else 0,
            data.get('contact1_name', '').strip(),
            data.get('contact1_phone', '').strip(),
            data.get('contact1_email', '').strip(),
            data.get('contact2_name', '').strip(),
            data.get('contact2_phone', '').strip(),
            data.get('contact2_email', '').strip(),
            json.dumps(data.get('declarations', {})),
            'member',
        ))

    db.commit()
    return jsonify({'success': True})

# ── BLUEPRINT: admin ───────────────────────────────────────────────────────────

# ── Session types API ──────────────────────────────────────────────────────────

@app.route('/api/session-types')
@login_required
def api_session_types_list():
    """Public read endpoint — returns active session types for dropdowns/JS."""
    return jsonify(get_session_types())


@app.route('/api/admin/session-types', methods=['GET'])
@permission_required('admin.session_types')
def api_admin_session_types_get():
    """Return all session types (including inactive)."""
    db   = get_db()
    rows = db.execute(
        'SELECT id, name, weekday, active, sort_order FROM session_types ORDER BY sort_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/admin/session-types', methods=['POST'])
@permission_required('admin.session_types')
def api_admin_session_types_create():
    """Create a new session type."""
    data    = request.get_json() or {}
    name    = data.get('name', '').strip()
    weekday = data.get('weekday')

    if not name:
        return jsonify({'error': 'name is required'}), 400
    if weekday is None or not isinstance(weekday, int) or weekday < 0 or weekday > 6:
        return jsonify({'error': 'weekday must be an integer 0–6 (Mon=0)'}), 400

    db = get_db()
    max_order = db.execute('SELECT COALESCE(MAX(sort_order), -1) FROM session_types').fetchone()[0]
    try:
        cur = db.execute(
            'INSERT INTO session_types (name, weekday, active, sort_order) VALUES (?,?,1,?)',
            (name, weekday, max_order + 1)
        )
        db.commit()
        log_action('create_session_type', 'session_types', cur.lastrowid, {'name': name, 'weekday': weekday})
        row = db.execute('SELECT * FROM session_types WHERE id = ?', (cur.lastrowid,)).fetchone()
        return jsonify(dict(row)), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A session type named "{name}" already exists'}), 409


@app.route('/api/admin/session-types/<int:st_id>', methods=['PUT'])
@permission_required('admin.session_types')
def api_admin_session_types_update(st_id):
    """Update a session type's name, weekday, or active status."""
    data    = request.get_json() or {}
    db      = get_db()
    current = db.execute('SELECT * FROM session_types WHERE id = ?', (st_id,)).fetchone()
    if not current:
        return jsonify({'error': 'Session type not found'}), 404

    name    = data.get('name', current['name']).strip()
    weekday = data.get('weekday', current['weekday'])
    active  = int(data.get('active', current['active']))

    if not name:
        return jsonify({'error': 'name is required'}), 400
    if not isinstance(weekday, int) or weekday < 0 or weekday > 6:
        return jsonify({'error': 'weekday must be an integer 0–6'}), 400

    # Prevent deactivating the last active session type
    if not active:
        active_count = db.execute(
            'SELECT COUNT(*) FROM session_types WHERE active = 1 AND id != ?', (st_id,)
        ).fetchone()[0]
        if active_count == 0:
            return jsonify({'error': 'Cannot deactivate the only active session type'}), 400

    try:
        db.execute(
            'UPDATE session_types SET name = ?, weekday = ?, active = ? WHERE id = ?',
            (name, weekday, active, st_id)
        )
        db.commit()
        log_action('update_session_type', 'session_types', st_id,
                   {'name': name, 'weekday': weekday, 'active': active})
        return jsonify(dict(db.execute('SELECT * FROM session_types WHERE id = ?', (st_id,)).fetchone()))
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A session type named "{name}" already exists'}), 409


@app.route('/api/admin/session-types/<int:st_id>', methods=['DELETE'])
@permission_required('admin.session_types')
def api_admin_session_types_delete(st_id):
    """Delete a session type (only if no members or attendance records use it)."""
    db  = get_db()
    row = db.execute('SELECT * FROM session_types WHERE id = ?', (st_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Session type not found'}), 404

    # Safety checks
    member_count = db.execute(
        'SELECT COUNT(*) FROM members WHERE session = ?', (row['name'],)
    ).fetchone()[0]
    if member_count:
        return jsonify({'error': f'Cannot delete — {member_count} member(s) are assigned to this session'}), 400

    active_count = db.execute(
        'SELECT COUNT(*) FROM session_types WHERE active = 1 AND id != ?', (st_id,)
    ).fetchone()[0]
    if row['active'] and active_count == 0:
        return jsonify({'error': 'Cannot delete the only active session type'}), 400

    db.execute('DELETE FROM session_types WHERE id = ?', (st_id,))
    db.commit()
    log_action('delete_session_type', 'session_types', st_id, {'name': row['name']})
    return jsonify({'success': True})


@app.route('/api/admin/session-types/reorder', methods=['POST'])
@permission_required('admin.session_types')
def api_admin_session_types_reorder():
    """Reorder session types. Body: [{id, sort_order}, ...]"""
    items = request.get_json() or []
    db    = get_db()
    for item in items:
        db.execute(
            'UPDATE session_types SET sort_order = ? WHERE id = ?',
            (item.get('sort_order', 0), item.get('id'))
        )
    db.commit()
    return jsonify({'success': True})


# ── BLUEPRINT: staff roles admin CRUD ─────────────────────────────────────────

@app.route('/api/admin/staff-roles', methods=['GET'])
@permission_required('admin.settings')
def api_admin_staff_roles_get():
    """Return all staff roles including inactive ones (admin view)."""
    db   = get_db()
    rows = db.execute(
        'SELECT id, name, active, display_order FROM staff_roles ORDER BY display_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/admin/staff-roles', methods=['POST'])
@permission_required('admin.settings')
def api_admin_staff_roles_create():
    """Create a new staff role."""
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400

    db        = get_db()
    max_order = db.execute('SELECT COALESCE(MAX(display_order), -1) FROM staff_roles').fetchone()[0]
    try:
        cur = db.execute(
            'INSERT INTO staff_roles (name, active, display_order) VALUES (?,1,?)',
            (name, max_order + 1)
        )
        db.commit()
        log_action('create_staff_role', 'staff_roles', cur.lastrowid, {'name': name})
        row = db.execute('SELECT * FROM staff_roles WHERE id = ?', (cur.lastrowid,)).fetchone()
        return jsonify(dict(row)), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A role named "{name}" already exists'}), 409


@app.route('/api/admin/staff-roles/<int:role_id>', methods=['PUT'])
@permission_required('admin.settings')
def api_admin_staff_roles_update(role_id):
    """Update a staff role's name or active status."""
    data    = request.get_json() or {}
    db      = get_db()
    current = db.execute('SELECT * FROM staff_roles WHERE id = ?', (role_id,)).fetchone()
    if not current:
        return jsonify({'error': 'Role not found'}), 404

    name   = data.get('name', current['name']).strip()
    active = int(data.get('active', current['active']))

    if not name:
        return jsonify({'error': 'name is required'}), 400

    # Prevent deactivating the last active role
    if not active:
        active_count = db.execute(
            'SELECT COUNT(*) FROM staff_roles WHERE active = 1 AND id != ?', (role_id,)
        ).fetchone()[0]
        if active_count == 0:
            return jsonify({'error': 'Cannot deactivate the only active staff role'}), 400

    try:
        db.execute(
            'UPDATE staff_roles SET name = ?, active = ? WHERE id = ?',
            (name, active, role_id)
        )
        db.commit()
        log_action('update_staff_role', 'staff_roles', role_id,
                   {'name': name, 'active': active})
        return jsonify(dict(db.execute('SELECT * FROM staff_roles WHERE id = ?', (role_id,)).fetchone()))
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A role named "{name}" already exists'}), 409


@app.route('/api/admin/staff-roles/reorder', methods=['POST'])
@permission_required('admin.settings')
def api_admin_staff_roles_reorder():
    """Reorder staff roles. Body: [{id, display_order}, ...]"""
    items = request.get_json() or []
    db    = get_db()
    for item in items:
        db.execute(
            'UPDATE staff_roles SET display_order = ? WHERE id = ?',
            (item.get('display_order', 0), item.get('id'))
        )
    db.commit()
    return jsonify({'success': True})


@app.route('/api/admin/users')
@permission_required('users.view')
def api_users_list():
    db     = get_db()
    scoped = _assigned_session()
    if scoped is not None:
        # Editors see only non-admin users for their own session
        users = db.execute(
            'SELECT id, username, email, role, session_assigned, active, '
            'created_at, last_login FROM users '
            "WHERE role != 'admin' AND session_assigned = ? ORDER BY username",
            (scoped,)
        ).fetchall()
    else:
        users = db.execute(
            'SELECT id, username, email, role, session_assigned, active, '
            'created_at, last_login FROM users ORDER BY username'
        ).fetchall()
    return jsonify([dict(u) for u in users])

@app.route('/api/admin/users', methods=['POST'])
@permission_required('users.create')
def api_users_create():
    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role     = data.get('role', 'readonly')
    email    = data.get('email', '').strip()
    sess     = data.get('session_assigned', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    pw_error = validate_password(password)
    if pw_error:
        return jsonify({'error': pw_error}), 400

    db = get_db()

    # Validate role exists in the roles table
    target_role_row = db.execute('SELECT id, permissions FROM roles WHERE name = ?', (role,)).fetchone()
    if not target_role_row:
        return jsonify({'error': 'Invalid role'}), 400

    # If the target role carries admin-level privileges, require users.create.admin
    target_perms = json.loads(target_role_row['permissions'])
    if 'users.create.admin' in target_perms and not has_permission('users.create.admin'):
        return jsonify({'error': 'You do not have permission to assign this role'}), 403

    # Non-admin-level users must have a session assigned
    # (sessions scope data — leaving it blank would expose all data)
    if 'admin.maintenance' not in target_perms and not sess:
        return jsonify({'error': 'A session must be assigned for non-admin users'}), 400
    if sess and sess not in get_valid_session_names():
        return jsonify({'error': 'Invalid session'}), 400

    # Scoped users (Core Leaders) can only create users for their own session
    scoped = _assigned_session()
    if scoped is not None and sess != scoped:
        return jsonify({'error': 'You can only create users for your own session'}), 403

    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    try:
        db.execute(
            'INSERT INTO users (username, email, password_hash, role, role_id, session_assigned)'
            ' VALUES (?,?,?,?,?,?)',
            (username, email, pw_hash, role, target_role_row['id'], sess)
        )
        db.commit()
        log_action('create_user', 'users', None,
                   {'username': username, 'role': role, 'created_by': session.get('username')})
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@permission_required('users.edit')
def api_users_update(user_id):
    data    = request.get_json() or {}
    db      = get_db()
    updates = []
    params  = []

    # Safety: cannot deactivate your own account
    if user_id == session['user_id'] and data.get('active') is False:
        return jsonify({'error': 'You cannot deactivate your own account'}), 400

    # If changing role, validate the target role and check admin-level permission
    if 'role' in data:
        target_role_row = db.execute(
            'SELECT id, permissions FROM roles WHERE name = ?', (data['role'],)
        ).fetchone()
        if not target_role_row:
            return jsonify({'error': 'Invalid role'}), 400
        target_perms = json.loads(target_role_row['permissions'])
        if 'users.create.admin' in target_perms and not has_permission('users.create.admin'):
            return jsonify({'error': 'You do not have permission to assign this role'}), 403

    # Editors can only modify users in their own session
    scoped = _assigned_session()
    if scoped is not None:
        target = db.execute('SELECT role, session_assigned FROM users WHERE id = ?', (user_id,)).fetchone()
        if not target or target['role'] == 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        if target['session_assigned'] != scoped:
            return jsonify({'error': 'You can only manage users in your own session'}), 403
        # Cannot re-assign to a different session
        if 'session_assigned' in data and data['session_assigned'] != scoped:
            return jsonify({'error': 'You cannot move a user to a different session'}), 403

    if 'email' in data:
        updates.append('email = ?')
        params.append(data['email'])

    if 'role' in data:
        # role and role_id are updated together; validation already done above
        target_role_row = db.execute('SELECT id FROM roles WHERE name = ?', (data['role'],)).fetchone()
        updates.append('role = ?')
        params.append(data['role'])
        if target_role_row:
            updates.append('role_id = ?')
            params.append(target_role_row['id'])

    if 'session_assigned' in data:
        updates.append('session_assigned = ?')
        params.append(data['session_assigned'])

    if 'active' in data:
        updates.append('active = ?')
        params.append(1 if data['active'] else 0)

    if 'password' in data and data['password']:
        pw_error = validate_password(data['password'])
        if pw_error:
            return jsonify({'error': pw_error}), 400
        pw_hash = bcrypt.hashpw(data['password'].encode('utf-8'),
                                bcrypt.gensalt()).decode('utf-8')
        updates.append('password_hash = ?')
        params.append(pw_hash)

    if updates:
        params.append(user_id)
        db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        db.commit()

    return jsonify({'success': True})

@app.route('/api/admin/users/<int:user_id>/permanent', methods=['DELETE'])
@permission_required('users.delete')
def api_users_permanent_delete(user_id):
    """Permanently delete a portal user account.

    Requires JSON body: { "confirm_username": "<username>" }
    Safety: admin cannot delete their own account this way.
    All FK references in other tables are nullified; audit_log rows are kept.
    """
    data = request.get_json() or {}
    db   = get_db()

    # Prevent self-deletion
    if user_id == session['user_id']:
        return jsonify({'error': 'You cannot delete your own account'}), 400

    user = db.execute('SELECT id, username FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Verify confirmation
    confirm = (data.get('confirm_username') or '').strip().lower()
    if confirm != user['username'].lower():
        return jsonify({'error': 'Username confirmation does not match'}), 400

    username = user['username']

    try:
        db.execute('BEGIN')

        # Nullify all FK references across tables
        db.execute('UPDATE members               SET updated_by = NULL WHERE updated_by = ?', (user_id,))
        db.execute('UPDATE pending_registrations SET reviewed_by = NULL WHERE reviewed_by = ?', (user_id,))
        db.execute('UPDATE documents             SET uploaded_by = NULL WHERE uploaded_by = ?', (user_id,))
        db.execute('UPDATE email_templates       SET created_by  = NULL WHERE created_by  = ?', (user_id,))
        db.execute('UPDATE mailshot_log          SET sent_by     = NULL WHERE sent_by     = ?', (user_id,))
        db.execute('UPDATE attendance            SET recorded_by = NULL WHERE recorded_by = ?', (user_id,))
        db.execute('UPDATE term_sessions         SET created_by  = NULL WHERE created_by  = ?', (user_id,))
        db.execute('UPDATE session_activities    SET added_by    = NULL WHERE added_by    = ?', (user_id,))
        # audit_log rows are retained; user_id is nullified to preserve history
        db.execute('UPDATE audit_log             SET user_id     = NULL WHERE user_id     = ?', (user_id,))

        # Delete the user
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))

        # Audit entry for the deletion (recorded under the acting admin)
        db.execute(
            'INSERT INTO audit_log (user_id, action, table_name, record_id, details, ip_address)'
            ' VALUES (?, ?, ?, ?, ?, ?)',
            (
                session['user_id'], 'delete_user', 'users', user_id,
                json.dumps({'username': username}),
                request.remote_addr,
            )
        )

        db.execute('COMMIT')
    except Exception as exc:
        db.execute('ROLLBACK')
        return jsonify({'error': str(exc)}), 500

    return jsonify({'success': True, 'deleted': username})

# ── BLUEPRINT: approvals ──────────────────────────────────────────────────────

def _next_member_id(db):
    """Generate the next sequential member ID using CLUB_SHORT_NAME, e.g. AYC042."""
    prefix = CLUB_SHORT_NAME
    prefix_len = len(prefix)
    row = db.execute(
        f"SELECT member_id FROM members WHERE member_id LIKE '{prefix}%'"
        f" ORDER BY CAST(SUBSTR(member_id, {prefix_len + 1}) AS INTEGER) DESC LIMIT 1"
    ).fetchone()
    if row:
        try:
            num = int(row['member_id'][prefix_len:]) + 1
        except (ValueError, AttributeError):
            num = 1
    else:
        num = 1
    return f'{prefix}{num:03d}'


@app.route('/api/approvals')
@permission_required('approvals.view')
def api_approvals_list():
    """List pending registrations. ?status=pending|approved|rejected|all
    Editors (Core Leaders) only see registrations for their assigned session."""
    status = request.args.get('status', 'pending')
    db     = get_db()
    scoped = _assigned_session()

    base_query = (
        'SELECT pr.*, u.username AS reviewed_by_name'
        ' FROM pending_registrations pr'
        ' LEFT JOIN users u ON u.id = pr.reviewed_by'
    )

    if scoped is not None:
        # Scoped: show pending (unassigned or matching their session) and
        # their own approved/rejected work.
        if status == 'all':
            rows = db.execute(
                base_query +
                ' WHERE (pr.assigned_session = ? OR pr.assigned_session IS NULL OR pr.assigned_session = "")'
                ' ORDER BY pr.submitted_at DESC',
                (scoped,)
            ).fetchall()
        else:
            rows = db.execute(
                base_query +
                ' WHERE pr.status = ?'
                ' AND (pr.assigned_session = ? OR pr.assigned_session IS NULL OR pr.assigned_session = "")'
                ' ORDER BY pr.submitted_at DESC',
                (status, scoped)
            ).fetchall()
    else:
        # Admin — see everything
        if status == 'all':
            rows = db.execute(
                base_query + ' ORDER BY pr.submitted_at DESC'
            ).fetchall()
        else:
            rows = db.execute(
                base_query + ' WHERE pr.status = ? ORDER BY pr.submitted_at DESC',
                (status,)
            ).fetchall()

    return jsonify([dict(r) for r in rows])


@app.route('/api/approvals/<int:reg_id>/approve', methods=['POST'])
@permission_required('approvals.approve')
def api_approvals_approve(reg_id):
    """Approve a pending registration — handles both member and staff types."""
    data = request.get_json() or {}
    db   = get_db()

    reg = db.execute(
        'SELECT * FROM pending_registrations WHERE id = ? AND status = "pending"',
        (reg_id,)
    ).fetchone()
    if not reg:
        return jsonify({'error': 'Registration not found or already reviewed'}), 404

    assigned_session = data.get('session_assigned', '').strip()
    if not assigned_session:
        return jsonify({'error': 'Session must be assigned when approving'}), 400

    # Editors can only approve into their own session
    scoped = _assigned_session()
    if scoped is not None and assigned_session != scoped:
        return jsonify({'error': 'You can only approve registrations for your own session'}), 403

    rtype      = reg['registration_type'] or 'member'
    mid        = _next_member_id(db)
    portal_user_id = None

    if rtype == 'staff':
        # ── Staff/volunteer approval ──────────────────────────────
        staff_role = data.get('staff_role', reg['applicant_role'] or '').strip()
        if not staff_role:
            return jsonify({'error': 'Staff role is required'}), 400

        db.execute('''
            INSERT INTO members
                (member_id, first_name, surname, date_of_birth, address, postcode,
                 status, session, member_type, staff_role, date_registered)
            VALUES (?,?,?,?,?,?,"Active",?,?,?,date("now"))
        ''', (
            mid,
            reg['first_name'], reg['surname'], reg['date_of_birth'],
            reg['address'], reg['postcode'],
            assigned_session,
            'staff',
            staff_role,
        ))
        member_db_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]

        # Store mobile and email as contact 1 (self-contact for staff)
        full_name = f"{reg['first_name']} {reg['surname']}".strip()
        if reg['mobile'] or reg['email']:
            db.execute(
                'INSERT INTO member_contacts'
                ' (member_id, contact_order, contact_name, contact_phone, contact_email)'
                ' VALUES (?,1,?,?,?)',
                (member_db_id, full_name, reg['mobile'] or '', reg['email'] or '')
            )

        # Optionally create a portal login
        create_login  = data.get('create_login', False)
        portal_role   = data.get('portal_role', '').strip()
        username      = data.get('username', '').strip()
        temp_password = data.get('temp_password', '').strip()

        if create_login:
            if not username or not temp_password:
                return jsonify({'error': 'Username and password are required to create a login'}), 400
            pw_error = validate_password(temp_password)
            if pw_error:
                return jsonify({'error': pw_error}), 400
            # Validate portal_role against the roles table
            role_row = db.execute('SELECT id, permissions FROM roles WHERE name = ?', (portal_role,)).fetchone()
            if not role_row:
                return jsonify({'error': 'Invalid portal role'}), 400
            role_perms = json.loads(role_row['permissions'])
            if 'users.create.admin' in role_perms and not has_permission('users.create.admin'):
                return jsonify({'error': 'You do not have permission to assign this role'}), 403
            existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            if existing:
                return jsonify({'error': f'Username "{username}" is already taken'}), 409
            pw_hash = bcrypt.hashpw(temp_password.encode(), bcrypt.gensalt()).decode()
            cur = db.execute(
                'INSERT INTO users (username, email, password_hash, role, role_id, session_assigned, active)'
                ' VALUES (?,?,?,?,?,?,1)',
                (username, reg['email'] or '', pw_hash, portal_role, role_row['id'], assigned_session)
            )
            portal_user_id = cur.lastrowid
            log_action('create_user', 'users', portal_user_id, {
                'username': username, 'role': portal_role,
                'created_by': session.get('username'),
                'via': 'staff_approval',
            })

    else:
        # ── Standard member approval ──────────────────────────────
        db.execute('''
            INSERT INTO members
                (member_id, first_name, surname, date_of_birth, address, postcode,
                 ethnicity_religion, medical_sen, gp_contact,
                 unattended_exit, gdpr_consent, status, session,
                 member_type, date_registered)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,"Active",?,"member",date("now"))
        ''', (
            mid,
            reg['first_name'], reg['surname'], reg['date_of_birth'],
            reg['address'], reg['postcode'],
            reg['ethnicity_religion'], reg['medical_sen'], reg['gp_contact'],
            reg['unattended_exit'], reg['gdpr_consent'],
            assigned_session,
        ))
        member_db_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]

        # Insert contacts
        for order, (name, phone, email) in enumerate([
            (reg['contact1_name'], reg['contact1_phone'], reg['contact1_email']),
            (reg['contact2_name'], reg['contact2_phone'], reg['contact2_email']),
        ], start=1):
            if name or phone or email:
                db.execute(
                    'INSERT INTO member_contacts'
                    ' (member_id, contact_order, contact_name, contact_phone, contact_email)'
                    ' VALUES (?,?,?,?,?)',
                    (member_db_id, order, name or '', phone or '', email or '')
                )

    # Mark registration as approved
    db.execute(
        'UPDATE pending_registrations'
        ' SET status = "approved", assigned_session = ?, reviewed_by = ?, reviewed_at = datetime("now")'
        ' WHERE id = ?',
        (assigned_session, session['user_id'], reg_id)
    )
    db.commit()

    log_action('approve_registration', 'pending_registrations', reg_id, {
        'new_member_id':   mid,
        'name':            f"{reg['first_name']} {reg['surname']}",
        'type':            rtype,
        'session':         assigned_session,
        'portal_user_id':  portal_user_id,
        'approved_by':     session['username'],
    })
    return jsonify({
        'success':      True,
        'member_id':    mid,
        'user_created': portal_user_id is not None,
    })


@app.route('/api/approvals/<int:reg_id>/reject', methods=['POST'])
@permission_required('approvals.reject')
def api_approvals_reject(reg_id):
    """Reject a pending registration with optional notes."""
    data = request.get_json() or {}
    db   = get_db()

    reg = db.execute(
        'SELECT * FROM pending_registrations WHERE id = ? AND status = "pending"',
        (reg_id,)
    ).fetchone()
    if not reg:
        return jsonify({'error': 'Registration not found or already reviewed'}), 404

    # Editors can only reject registrations in their session (or unassigned ones)
    scoped = _assigned_session()
    if scoped is not None:
        reg_session = reg['assigned_session'] or ''
        if reg_session and reg_session != scoped:
            return jsonify({'error': 'Access denied for this registration'}), 403

    notes = data.get('notes', '').strip()
    db.execute(
        'UPDATE pending_registrations'
        ' SET status = "rejected", notes = ?, reviewed_by = ?, reviewed_at = datetime("now")'
        ' WHERE id = ?',
        (notes, session['user_id'], reg_id)
    )
    db.commit()

    log_action('reject_registration', 'pending_registrations', reg_id, {
        'name': f"{reg['first_name']} {reg['surname']}",
        'notes': notes,
        'rejected_by': session['username'],
    })
    return jsonify({'success': True})


# ── BLUEPRINT: attendance (Phase 3) ───────────────────────────────────────────

@app.route('/api/attendance/<session_type>/<date>')
@login_required
def api_attendance_get(session_type, date):
    """
    Return all active members for a session on a given date,
    annotated with their sign-in/out times if recorded.
    session_type: Tuesday | Thursday
    date: YYYY-MM-DD
    """
    db = get_db()

    # Session-scope for all non-admin roles
    scoped = _assigned_session()
    if scoped is not None:
        if not scoped:
            return jsonify([])
        if scoped != session_type:
            return jsonify({'error': 'Access denied for this session'}), 403

    rows = db.execute('''
        SELECT  m.id, m.member_id, m.first_name, m.surname,
                m.medical_sen, m.unattended_exit,
                a.id         AS att_id,
                a.signed_in_at,
                a.signed_out_at
        FROM    members m
        LEFT JOIN attendance a
               ON  a.member_id   = m.id
               AND a.session_date = ?
               AND a.session_type = ?
        WHERE   m.status      != "Leaver"
          AND   m.member_type  = "member"
          AND   m.session      = ?
        ORDER   BY m.first_name, m.surname
    ''', (date, session_type, session_type)).fetchall()

    return jsonify([dict(r) for r in rows])


@app.route('/api/attendance/staff/<session_type>/<date>')
@login_required
def api_attendance_staff_get(session_type, date):
    """
    Return all active staff members for a session on a given date,
    annotated with sign-in/out times. Staff are never subject to At Risk logic.
    """
    if session_type not in get_valid_session_names():
        return jsonify({'error': 'Invalid session'}), 400

    scoped = _assigned_session()
    if scoped is not None and scoped != session_type:
        return jsonify({'error': 'Access denied for this session'}), 403

    db   = get_db()
    rows = db.execute('''
        SELECT  m.id, m.first_name, m.surname, m.staff_role,
                a.signed_in_at,
                a.signed_out_at
        FROM    members m
        LEFT JOIN attendance a
               ON  a.member_id    = m.id
               AND a.session_date = ?
               AND a.session_type = ?
        WHERE   m.status      != "Leaver"
          AND   m.member_type  = "staff"
          AND   m.session      = ?
        ORDER   BY m.first_name, m.surname
    ''', (date, session_type, session_type)).fetchall()

    return jsonify([dict(r) for r in rows])


@app.route('/api/attendance/signin', methods=['POST'])
@permission_required('register.signin')
def api_attendance_signin():
    data        = request.get_json() or {}
    member_id   = data.get('member_id')
    sess_type   = data.get('session_type', '').strip()
    sess_date   = data.get('date', '').strip()

    if not all([member_id, sess_type, sess_date]):
        return jsonify({'error': 'member_id, session_type and date are required'}), 400

    # Enforce session scope for non-admin roles
    scoped = _assigned_session()
    if scoped is not None and scoped != sess_type:
        return jsonify({'error': 'Access denied for this session'}), 403

    # Reject if register is locked
    if _is_register_locked(sess_type, sess_date):
        return jsonify({'error': 'This register has been completed and is now locked.'}), 403

    db = get_db()
    # Upsert — insert if not exists, update signed_in_at if already there
    existing = db.execute(
        'SELECT id FROM attendance WHERE member_id = ? AND session_date = ? AND session_type = ?',
        (member_id, sess_date, sess_type)
    ).fetchone()

    now = datetime.now().strftime('%H:%M')
    if existing:
        db.execute(
            'UPDATE attendance SET signed_in_at = ?, recorded_by = ? WHERE id = ?',
            (now, session['user_id'], existing['id'])
        )
    else:
        db.execute(
            'INSERT INTO attendance (member_id, session_date, session_type, signed_in_at, recorded_by)'
            ' VALUES (?,?,?,?,?)',
            (member_id, sess_date, sess_type, now, session['user_id'])
        )
    # Auto-revert: if the member was flagged At Risk and has now attended, reinstate them
    member_row = db.execute('SELECT status, first_name, surname FROM members WHERE id = ?',
                            (member_id,)).fetchone()
    if member_row and member_row['status'] == 'At Risk':
        db.execute(
            "UPDATE members SET status = 'Active', status_note = NULL, "
            "updated_at = datetime('now'), updated_by = ? WHERE id = ?",
            (session['user_id'], member_id)
        )
        log_action('reinstate_member', 'members', member_id, {
            'member': f"{member_row['first_name']} {member_row['surname']}",
            'reason': 'attended session — auto-reinstated from At Risk',
        })

    db.commit()
    _touch_attendance()
    return jsonify({'success': True, 'signed_in_at': now})


@app.route('/api/attendance/signout', methods=['POST'])
@permission_required('register.signout')
def api_attendance_signout():
    data        = request.get_json() or {}
    member_id   = data.get('member_id')
    sess_type   = data.get('session_type', '').strip()
    sess_date   = data.get('date', '').strip()
    clear       = data.get('clear', False)   # True = undo sign-out (set to NULL)

    if not all([member_id, sess_type, sess_date]):
        return jsonify({'error': 'member_id, session_type and date are required'}), 400

    # Enforce session scope for non-admin roles
    scoped = _assigned_session()
    if scoped is not None and scoped != sess_type:
        return jsonify({'error': 'Access denied for this session'}), 403

    # Reject if register is locked
    if _is_register_locked(sess_type, sess_date):
        return jsonify({'error': 'This register has been completed and is now locked.'}), 403

    db        = get_db()
    out_value = None if clear else datetime.now().strftime('%H:%M')
    result = db.execute(
        'UPDATE attendance SET signed_out_at = ?, recorded_by = ?'
        ' WHERE member_id = ? AND session_date = ? AND session_type = ?',
        (out_value, session['user_id'], member_id, sess_date, sess_type)
    )
    if result.rowcount == 0:
        return jsonify({'error': 'No sign-in record found — member may not be signed in yet'}), 404
    db.commit()
    _touch_attendance()
    return jsonify({'success': True, 'signed_out_at': out_value})


@app.route('/api/attendance/complete/<session_type>/<date>')
@login_required
def api_attendance_complete_status(session_type, date):
    """Return whether the register for this session+date has been completed."""
    db  = get_db()
    row = db.execute(
        '''SELECT sc.completed_at, sc.auto_signout_count,
                  u.username AS completed_by_name
           FROM session_completions sc
           LEFT JOIN users u ON u.id = sc.completed_by
           WHERE sc.session_date = ? AND sc.session_type = ?''',
        (date, session_type)
    ).fetchone()
    if row:
        return jsonify({
            'completed':          True,
            'completed_by':       row['completed_by_name'],
            'completed_at':       row['completed_at'],
            'auto_signout_count': row['auto_signout_count'],
        })
    return jsonify({'completed': False})


@app.route('/api/attendance/complete', methods=['POST'])
@permission_required('register.complete')
def api_attendance_complete():
    """
    Mark a session register as complete (locked).
    Auto signs out any members still signed in.
    Restricted to admin (any session) and editor (own session only).
    """
    data      = request.get_json() or {}
    sess_type = data.get('session_type', '').strip()
    sess_date = data.get('date', '').strip()

    if not all([sess_type, sess_date]):
        return jsonify({'error': 'session_type and date are required'}), 400

    # Editors are scoped to their assigned session
    scoped = _assigned_session()
    if scoped is not None and scoped != sess_type:
        return jsonify({'error': 'You can only complete your own session register'}), 403

    db = get_db()

    # Prevent double-completion
    existing = db.execute(
        'SELECT id FROM session_completions WHERE session_date = ? AND session_type = ?',
        (sess_date, sess_type)
    ).fetchone()
    if existing:
        return jsonify({'error': 'This register has already been completed'}), 409

    # Auto sign out anyone still signed in
    now         = datetime.now().strftime('%H:%M')
    still_in    = db.execute(
        '''SELECT id FROM attendance
           WHERE session_date = ? AND session_type = ?
             AND signed_in_at IS NOT NULL AND signed_out_at IS NULL''',
        (sess_date, sess_type)
    ).fetchall()
    auto_count  = len(still_in)
    if auto_count:
        db.execute(
            '''UPDATE attendance SET signed_out_at = ?, recorded_by = ?
               WHERE session_date = ? AND session_type = ?
                 AND signed_in_at IS NOT NULL AND signed_out_at IS NULL''',
            (now, session['user_id'], sess_date, sess_type)
        )

    # Record the completion
    db.execute(
        '''INSERT INTO session_completions
               (session_date, session_type, completed_by, completed_at, auto_signout_count)
           VALUES (?, ?, ?, datetime('now'), ?)''',
        (sess_date, sess_type, session['user_id'], auto_count)
    )
    db.commit()
    _touch_attendance()

    # Fetch summary counts for the response
    totals = db.execute(
        '''SELECT
             COUNT(*) AS total,
             SUM(CASE WHEN signed_out_at IS NOT NULL THEN 1 ELSE 0 END) AS signed_out
           FROM attendance
           WHERE session_date = ? AND session_type = ?''',
        (sess_date, sess_type)
    ).fetchone()

    log_action('register_complete', 'session_completions', None, {
        'session_type':      sess_type,
        'session_date':      sess_date,
        'auto_signout_count': auto_count,
    })

    return jsonify({
        'success':           True,
        'auto_signout_count': auto_count,
        'total_members':     totals['total'] if totals else 0,
        'total_signed_out':  totals['signed_out'] if totals else 0,
    })


@app.route('/api/attendance/reset', methods=['POST'])
@permission_required('register.reset')
def api_attendance_reset():
    """
    Admin-only: completely wipe a session register.
    Deletes all attendance rows and the session_completions record for
    the given session_type + date, leaving the register blank and unlocked.
    """
    data      = request.get_json() or {}
    sess_type = data.get('session_type', '').strip()
    sess_date = data.get('date', '').strip()

    if not all([sess_type, sess_date]):
        return jsonify({'error': 'session_type and date are required'}), 400

    db = get_db()

    # Count rows being deleted so we can return a useful summary
    att_count = db.execute(
        'SELECT COUNT(*) AS n FROM attendance WHERE session_date = ? AND session_type = ?',
        (sess_date, sess_type)
    ).fetchone()['n']

    # Wipe attendance records
    db.execute(
        'DELETE FROM attendance WHERE session_date = ? AND session_type = ?',
        (sess_date, sess_type)
    )

    # Unlock the register (remove completion record if one exists)
    db.execute(
        'DELETE FROM session_completions WHERE session_date = ? AND session_type = ?',
        (sess_date, sess_type)
    )

    db.commit()
    _touch_attendance()

    log_action('register_reset', 'attendance', None, {
        'session_type':       sess_type,
        'session_date':       sess_date,
        'attendance_deleted': att_count,
    })

    return jsonify({
        'success':            True,
        'attendance_deleted': att_count,
    })


def get_setting(key, default=None):
    """Return a value from the settings table, or default if not found."""
    db  = get_db()
    row = db.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
    return row['value'] if row else default


def _touch_attendance():
    """Stamp the current time into settings so the SSE stream can detect changes."""
    db  = get_db()
    now = datetime.now().isoformat()
    db.execute(
        'INSERT INTO settings (key, value) VALUES (?,?) '
        'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
        ('last_attendance_change', now)
    )
    db.commit()


@app.route('/api/display/stream')
def api_display_stream():
    """SSE endpoint — pushes a 'refresh' event whenever attendance changes."""
    def generate():
        last = None
        while True:
            current = get_setting('last_attendance_change')
            if current != last:
                last = current
                yield 'data: refresh\n\n'
            time.sleep(1)
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


def get_session_types():
    """Return active session types from the DB, cached per request in Flask g."""
    if 'session_types' not in g:
        db   = get_db()
        rows = db.execute(
            'SELECT id, name, weekday FROM session_types WHERE active = 1 ORDER BY sort_order, name'
        ).fetchall()
        g.session_types = [dict(r) for r in rows]
    return g.session_types


def get_valid_session_names():
    """Return a tuple of valid session name strings (for validation checks)."""
    return tuple(s['name'] for s in get_session_types())


def weekday_to_session_map():
    """Return dict mapping Python weekday int -> session name."""
    return {s['weekday']: s['name'] for s in get_session_types()}


def session_to_weekday_map():
    """Return dict mapping session name -> Python weekday int."""
    return {s['name']: s['weekday'] for s in get_session_types()}


def _is_register_locked(sess_type, sess_date):
    """Return True if the register for this session+date has been completed/locked."""
    db = get_db()
    row = db.execute(
        'SELECT id FROM session_completions WHERE session_date = ? AND session_type = ?',
        (sess_date, sess_type)
    ).fetchone()
    return row is not None


def _assigned_session():
    """
    Return the session this user is scoped to, or None for admin (unscoped).
    All non-admin roles MUST have a session_assigned.
    """
    if session.get('role') == 'admin':
        return None
    return session.get('session_assigned') or ''


@app.route('/api/attendance/check-at-risk')
@permission_required('register.at_risk')
def api_attendance_check_at_risk():
    """
    Return active members who have missed their last N consecutive sessions,
    where N is the configurable per-session threshold from settings.
    Uses term_sessions to determine what sessions have occurred.
    """
    db    = get_db()
    today = datetime.now().strftime('%Y-%m-%d')

    # Build per-session thresholds dynamically from settings
    thresholds = {}
    for st in get_session_types():
        key = 'at_risk_threshold_' + st['name'].lower().replace(' ', '_')
        thresholds[st['name']] = int(get_setting(key, '5'))

    # Fetch all past term sessions
    past_sessions = db.execute(
        "SELECT session_date, session_type FROM term_sessions "
        "WHERE session_date <= ? ORDER BY session_date DESC",
        (today,)
    ).fetchall()

    # Build per-type ordered lists (most recent first)
    from collections import defaultdict
    sessions_by_type = defaultdict(list)
    for s in past_sessions:
        sessions_by_type[s['session_type']].append(s['session_date'])

    # Fetch all active (non-leaver, non-at-risk) youth members, scoped where applicable
    scoped = _assigned_session()
    if scoped is not None:
        members = db.execute(
            "SELECT id, member_id, first_name, surname, session FROM members "
            "WHERE status NOT IN ('Leaver', 'At Risk') AND member_type = 'member' AND session = ?",
            (scoped,)
        ).fetchall()
    else:
        members = db.execute(
            "SELECT id, member_id, first_name, surname, session FROM members "
            "WHERE status NOT IN ('Leaver', 'At Risk') AND member_type = 'member'"
        ).fetchall()

    candidates = []
    for m in members:
        assigned  = m['session']
        threshold = thresholds.get(assigned, 5)
        relevant  = sessions_by_type[assigned][:threshold]
        if not checks:
            continue

        for day, relevant, threshold in checks:
            if len(relevant) < threshold:
                continue  # Not enough history yet to flag

            attended = db.execute(
                f"SELECT COUNT(*) AS n FROM attendance WHERE member_id = ? "
                f"AND session_date IN ({','.join('?' * len(relevant))})",
                [m['id']] + relevant
            ).fetchone()['n']

            if attended == 0:
                last = db.execute(
                    "SELECT MAX(session_date) AS last FROM attendance WHERE member_id = ?",
                    (m['id'],)
                ).fetchone()['last']
                candidates.append({
                    'id':              m['id'],
                    'member_id':       m['member_id'],
                    'first_name':      m['first_name'],
                    'surname':         m['surname'],
                    'session':         assigned,
                    'trigger_session': day,
                    'last_attendance': last,
                    'missed_sessions': threshold,
                })

    candidates.sort(key=lambda x: (x['last_attendance'] or '', x['surname']))
    return jsonify(candidates)


@app.route('/api/attendance/mark-at-risk', methods=['POST'])
@permission_required('register.at_risk')
def api_attendance_mark_at_risk():
    """Flag a list of members as At Risk, with a mandatory note from the core leader."""
    data       = request.get_json() or {}
    member_ids = data.get('member_ids', [])
    note       = data.get('note', '').strip()
    if not member_ids:
        return jsonify({'error': 'No member IDs provided'}), 400
    if not note:
        return jsonify({'error': 'A note is required when flagging members as At Risk'}), 400

    db     = get_db()
    scoped = _assigned_session()
    count  = 0
    for mid in member_ids:
        member = db.execute('SELECT * FROM members WHERE id = ?', (mid,)).fetchone()
        if not member:
            continue
        # Enforce session scope for non-admin roles
        if scoped is not None and member['session'] != scoped:
            continue
        if member['status'] not in ('Leaver', 'At Risk'):
            db.execute(
                "UPDATE members SET status = 'At Risk', status_note = ?, "
                "updated_at = datetime('now'), updated_by = ? WHERE id = ?",
                (note, session['user_id'], mid)
            )
            log_action('mark_at_risk', 'members', mid, {
                'member': f"{member['first_name']} {member['surname']}",
                'note':   note,
            })
            count += 1
    db.commit()
    return jsonify({'success': True, 'marked_count': count})


@app.route('/api/attendance/history/<int:member_id>')
@login_required
def api_attendance_history(member_id):
    """Return last 20 attendance records for a member."""
    db = get_db()
    # Enforce session scope — non-admin users can only view history for members in their session
    scoped = _assigned_session()
    if scoped is not None:
        member = db.execute('SELECT session FROM members WHERE id = ?', (member_id,)).fetchone()
        if not member or member['session'] != scoped:
            return jsonify({'error': 'Forbidden'}), 403

    rows = db.execute(
        'SELECT session_date, session_type, signed_in_at, signed_out_at'
        ' FROM attendance WHERE member_id = ?'
        ' ORDER BY session_date DESC LIMIT 20',
        (member_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ── BLUEPRINT: reception display (public, read-only) ──────────────────────────

@app.route('/display')
def display_page():
    """Full-screen reception TV display — no login required."""
    return render_template('display.html',
                           current_session=session.get('session_assigned', ''),
                           session_types=get_session_types(),
                           club_name=CLUB_NAME, club_short_name=CLUB_SHORT_NAME)


@app.route('/api/display/<session_type>')
def api_display(session_type):
    """
    Return names of members currently signed IN (not yet signed out) for
    today's session, plus on-duty leaders and active activities.
    No login required — returns first name + surname only, no sensitive data.
    """
    if session_type not in get_valid_session_names():
        return jsonify({'error': 'Invalid session'}), 400

    today = datetime.now().strftime('%Y-%m-%d')
    db    = get_db()

    rows = db.execute('''
        SELECT  m.first_name, m.surname,
                a.signed_in_at
        FROM    attendance a
        JOIN    members m ON m.id = a.member_id
        WHERE   a.session_date  = ?
          AND   a.session_type  = ?
          AND   a.signed_in_at  IS NOT NULL
          AND   a.signed_out_at IS NULL
          AND   m.member_type   = "member"
        ORDER   BY a.signed_in_at ASC
    ''', (today, session_type)).fetchall()

    # Staff who have signed in today and not yet signed out — these are "on duty"
    leader_rows = db.execute('''
        SELECT  m.first_name, m.surname, m.staff_role
        FROM    attendance a
        JOIN    members m ON m.id = a.member_id
        WHERE   a.session_date  = ?
          AND   a.session_type  = ?
          AND   a.signed_in_at  IS NOT NULL
          AND   a.signed_out_at IS NULL
          AND   m.member_type   = "staff"
        ORDER   BY a.signed_in_at ASC
    ''', (today, session_type)).fetchall()

    # Active activities for this session
    activity_rows = db.execute('''
        SELECT id, activity
        FROM   session_activities
        WHERE  session_type = ? AND active = 1
        ORDER  BY created_at ASC
    ''', (session_type,)).fetchall()

    return jsonify({
        'session':    session_type,
        'date':       today,
        'members':    [{'first_name': r['first_name'], 'surname': r['surname'],
                        'signed_in_at': r['signed_in_at']} for r in rows],
        'leaders':    [{'name': f"{r['first_name']} {r['surname']}", 'role': r['staff_role'] or ''} for r in leader_rows],
        'activities': [{'id': r['id'], 'activity': r['activity']} for r in activity_rows],
    })


@app.route('/api/activities/<session_type>', methods=['GET'])
@login_required
def api_activities_list(session_type):
    """List active activities for a session."""
    if session_type not in get_valid_session_names():
        return jsonify({'error': 'Invalid session'}), 400
    db   = get_db()
    rows = db.execute('''
        SELECT id, activity, created_at
        FROM   session_activities
        WHERE  session_type = ? AND active = 1
        ORDER  BY created_at ASC
    ''', (session_type,)).fetchall()
    return jsonify([{'id': r['id'], 'activity': r['activity'],
                     'created_at': r['created_at']} for r in rows])


@app.route('/api/activities', methods=['POST'])
@permission_required('activities.manage')
def api_activity_add():
    """Add an activity to the display board."""
    data     = request.get_json() or {}
    sess     = data.get('session_type', '').strip()
    activity = data.get('activity', '').strip()
    if sess not in get_valid_session_names():
        return jsonify({'error': 'Invalid session'}), 400
    if not activity:
        return jsonify({'error': 'Activity text is required'}), 400
    if len(activity) > 120:
        return jsonify({'error': 'Activity text is too long (max 120 characters)'}), 400
    db = get_db()
    cur = db.execute(
        'INSERT INTO session_activities (session_type, activity, added_by) VALUES (?,?,?)',
        (sess, activity, session.get('user_id'))
    )
    db.commit()
    return jsonify({'id': cur.lastrowid, 'activity': activity}), 201


@app.route('/api/activities/<int:activity_id>', methods=['DELETE'])
@permission_required('activities.manage')
def api_activity_delete(activity_id):
    """Remove an activity from the display board."""
    db = get_db()
    db.execute('UPDATE session_activities SET active = 0 WHERE id = ?', (activity_id,))
    db.commit()
    return jsonify({'ok': True})


# ── BLUEPRINT: calendar (Phase 5) ────────────────────────────────────────────

VALID_STATUSES = ('planned', 'cancelled', 'special')


@app.route('/calendar')
@login_required
def calendar_page():
    return render_template('calendar.html', **tpl_ctx(), active_page='calendar')


@app.route('/api/calendar', methods=['GET'])
@login_required
def api_calendar_list():
    """Return term sessions, optionally filtered by year/month or term."""
    db    = get_db()
    year  = request.args.get('year')
    month = request.args.get('month')
    term  = request.args.get('term')

    query  = 'SELECT * FROM term_sessions WHERE 1=1'
    params = []

    if year and month:
        prefix = f"{int(year):04d}-{int(month):02d}-"
        query += ' AND session_date LIKE ?'
        params.append(prefix + '%')
    elif term:
        query += ' AND term_name = ?'
        params.append(term)

    query += ' ORDER BY session_date ASC, session_type ASC'
    rows   = db.execute(query, params).fetchall()

    return jsonify([dict(r) for r in rows])


@app.route('/api/calendar/terms', methods=['GET'])
@login_required
def api_calendar_terms():
    """Return distinct term names present in the database."""
    db   = get_db()
    rows = db.execute(
        "SELECT DISTINCT term_name FROM term_sessions WHERE term_name IS NOT NULL ORDER BY term_name"
    ).fetchall()
    return jsonify([r['term_name'] for r in rows])


@app.route('/api/calendar', methods=['POST'])
@permission_required('calendar.create')
def api_calendar_add():
    """Add a single session to the calendar."""
    data         = request.get_json() or {}
    session_date = data.get('session_date', '').strip()
    session_type = data.get('session_type', '').strip()
    status       = data.get('status', 'planned').strip()
    notes        = data.get('notes', '').strip() or None
    term_name    = data.get('term_name', '').strip() or None

    if not session_date:
        return jsonify({'error': 'Session date is required'}), 400
    if session_type not in get_valid_session_names():
        return jsonify({'error': 'Invalid session type'}), 400

    # Editors can only add sessions for their own session type
    scoped = _assigned_session()
    if scoped is not None and session_type != scoped:
        return jsonify({'error': f'You can only add {scoped} sessions'}), 403
    if status not in VALID_STATUSES:
        return jsonify({'error': 'Invalid status'}), 400

    # Validate date and check day-of-week matches session type
    try:
        from datetime import date as dt_date
        d            = dt_date.fromisoformat(session_date)
        wday_map     = session_to_weekday_map()
        expected_day = wday_map.get(session_type)
        if expected_day is None:
            return jsonify({'error': 'Unknown session type'}), 400
        if d.weekday() != expected_day:
            return jsonify({'error': f'{session_date} is not a {session_type}'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

    db = get_db()
    try:
        cur = db.execute(
            '''INSERT INTO term_sessions (session_date, session_type, term_name, status, notes, created_by)
               VALUES (?,?,?,?,?,?)''',
            (session_date, session_type, term_name, status, notes, session.get('user_id'))
        )
        db.commit()
        log_action('add_term_session', 'term_sessions', cur.lastrowid,
                   {'date': session_date, 'type': session_type, 'term': term_name})
        row = db.execute('SELECT * FROM term_sessions WHERE id = ?', (cur.lastrowid,)).fetchone()
        return jsonify(dict(row)), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A {session_type} session on {session_date} already exists'}), 409


@app.route('/api/calendar/bulk', methods=['POST'])
@permission_required('calendar.create')
def api_calendar_bulk():
    """
    Bulk-generate sessions between two dates.
    Body: { start_date, end_date, days ['Tuesday','Thursday'], term_name, exclude_dates[] }
    """
    from datetime import date as dt_date, timedelta as dt_timedelta

    data          = request.get_json() or {}
    start_str     = data.get('start_date', '').strip()
    end_str       = data.get('end_date', '').strip()
    days          = data.get('days', [])
    term_name     = data.get('term_name', '').strip() or None
    exclude_dates = set(data.get('exclude_dates', []))

    if not start_str or not end_str:
        return jsonify({'error': 'start_date and end_date are required'}), 400
    if not days:
        return jsonify({'error': 'At least one day must be selected'}), 400

    # Editors can only bulk-generate their own session type
    scoped = _assigned_session()
    if scoped is not None:
        if any(d != scoped for d in days):
            return jsonify({'error': f'You can only generate {scoped} sessions'}), 403
        days = [scoped]   # enforce — discard any other values

    try:
        start = dt_date.fromisoformat(start_str)
        end   = dt_date.fromisoformat(end_str)
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

    if end < start:
        return jsonify({'error': 'end_date must be on or after start_date'}), 400
    if (end - start).days > 365:
        return jsonify({'error': 'Date range cannot exceed 365 days'}), 400

    # Map day names to Python weekday numbers using DB-driven session types
    s2w = session_to_weekday_map()
    # weekday -> session_name for days that were requested
    target_weekdays = {}
    for d in days:
        if d in s2w:
            target_weekdays[s2w[d]] = d

    # Walk the date range
    created, skipped = 0, 0
    db = get_db()
    current = start
    while current <= end:
        if current.weekday() in target_weekdays:
            date_str     = current.isoformat()
            session_type = target_weekdays[current.weekday()]
            if date_str not in exclude_dates:
                try:
                    db.execute(
                        '''INSERT INTO term_sessions
                               (session_date, session_type, term_name, status, created_by)
                           VALUES (?,?,?,?,?)''',
                        (date_str, session_type, term_name, 'planned', session.get('user_id'))
                    )
                    created += 1
                except sqlite3.IntegrityError:
                    skipped += 1  # already exists
        current += dt_timedelta(days=1)

    db.commit()
    log_action('bulk_term_sessions', 'term_sessions', None,
               {'term': term_name, 'created': created, 'skipped': skipped})
    return jsonify({'created': created, 'skipped': skipped})


@app.route('/api/calendar/<int:session_id>', methods=['PUT'])
@permission_required('calendar.edit')
def api_calendar_update(session_id):
    """Update status or notes on a session."""
    data   = request.get_json() or {}
    status = data.get('status')
    notes  = data.get('notes')
    term   = data.get('term_name')
    db     = get_db()

    row = db.execute('SELECT * FROM term_sessions WHERE id = ?', (session_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    # Editors can only update sessions for their own session type
    scoped = _assigned_session()
    if scoped is not None and row['session_type'] != scoped:
        return jsonify({'error': 'You can only edit your own session entries'}), 403

    updates, params = [], []
    if status is not None:
        if status not in VALID_STATUSES:
            return jsonify({'error': 'Invalid status'}), 400
        updates.append('status = ?'); params.append(status)
    if notes is not None:
        updates.append('notes = ?'); params.append(notes.strip() or None)
    if term is not None:
        updates.append('term_name = ?'); params.append(term.strip() or None)

    if updates:
        params.append(session_id)
        db.execute(f"UPDATE term_sessions SET {', '.join(updates)} WHERE id = ?", params)
        db.commit()
        log_action('update_term_session', 'term_sessions', session_id,
                   {'status': status, 'notes': notes})

    return jsonify(dict(db.execute('SELECT * FROM term_sessions WHERE id = ?', (session_id,)).fetchone()))


@app.route('/api/calendar/<int:session_id>', methods=['DELETE'])
@permission_required('calendar.delete')
def api_calendar_delete(session_id):
    """Delete a session from the calendar."""
    db  = get_db()
    row = db.execute('SELECT * FROM term_sessions WHERE id = ?', (session_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    # Editors can only delete sessions for their own session type
    scoped = _assigned_session()
    if scoped is not None and row['session_type'] != scoped:
        return jsonify({'error': 'You can only delete your own session entries'}), 403

    db.execute('DELETE FROM term_sessions WHERE id = ?', (session_id,))
    db.commit()
    log_action('delete_term_session', 'term_sessions', session_id,
               {'date': row['session_date'], 'type': row['session_type']})
    return jsonify({'ok': True})


@app.route('/api/calendar/upcoming', methods=['GET'])
@login_required
def api_calendar_upcoming():
    """Return the next N planned sessions from today (used by dashboard)."""
    limit = min(int(request.args.get('limit', 6)), 20)
    today = datetime.now().strftime('%Y-%m-%d')
    db    = get_db()
    rows  = db.execute('''
        SELECT * FROM term_sessions
        WHERE  session_date >= ? AND status != 'cancelled'
        ORDER  BY session_date ASC, session_type ASC
        LIMIT  ?
    ''', (today, limit)).fetchall()
    return jsonify([dict(r) for r in rows])


# ── Page routes for Phase 2 & 3 ───────────────────────────────────────────────

# (approvals_page and register_page already defined above — no change needed)

# ── BLUEPRINT: documents ──────────────────────────────────────────────────────

CATEGORY_LABELS = ('policy', 'template', 'form', 'general')
# Numeric rank used to gate document access.
# readonly=0, leader=1, editor=2, admin=3
# When uploading a doc, set access_role to the minimum rank required.
ROLE_RANK = {'readonly': 0, 'leader': 1, 'editor': 2, 'admin': 3}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def user_can_access_doc(doc):
    """Return True if the current session role meets the document's access_role."""
    user_rank = ROLE_RANK.get(session.get('role', 'readonly'), 0)
    req_rank  = ROLE_RANK.get(doc['access_role'] or 'readonly', 0)
    return user_rank >= req_rank


@app.route('/api/documents')
@permission_required('documents.view')
def api_documents_list():
    db   = get_db()
    rows = db.execute('''
        SELECT d.*, u.username AS uploaded_by_name
        FROM   documents d
        LEFT JOIN users u ON u.id = d.uploaded_by
        WHERE  d.active = 1
        ORDER  BY d.category, d.title
    ''').fetchall()
    # Filter by access_role
    docs = [dict(r) for r in rows if user_can_access_doc(r)]
    return jsonify(docs)


@app.route('/api/documents', methods=['POST'])
@permission_required('documents.upload')
def api_documents_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'No file selected'}), 400
    if not allowed_file(f.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    title       = request.form.get('title', '').strip() or f.filename
    category    = request.form.get('category', 'general')
    access_role = request.form.get('access_role', 'readonly')

    if category    not in CATEGORY_LABELS:  category    = 'general'
    if access_role not in ROLE_RANK:        access_role = 'readonly'

    safe_name = secure_filename(f.filename)
    # Prefix with timestamp to avoid collisions
    stored_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{safe_name}"
    encrypted_data = encrypt_file(f.read())
    with open(os.path.join(UPLOAD_DIR, stored_name), 'wb') as fh:
        fh.write(encrypted_data)

    mime = f.mimetype or 'application/octet-stream'
    db   = get_db()
    cur  = db.execute(
        'INSERT INTO documents (title, filename, file_path, mime_type, category, access_role, uploaded_by)'
        ' VALUES (?,?,?,?,?,?,?)',
        (title, safe_name, stored_name, mime, category, access_role, session['user_id'])
    )
    db.commit()
    log_action('upload_document', 'documents', cur.lastrowid, {'title': title, 'category': category})
    return jsonify({'success': True})


@app.route('/api/documents/<int:doc_id>/download')
@login_required
def api_documents_download(doc_id):
    db  = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)).fetchone()
    if not doc:
        return jsonify({'error': 'Not found'}), 404
    if not user_can_access_doc(doc):
        return jsonify({'error': 'Forbidden'}), 403
    log_action('download_document', 'documents', doc_id, {'title': doc['title']})
    with open(os.path.join(UPLOAD_DIR, doc['file_path']), 'rb') as fh:
        decrypted = decrypt_file(fh.read())
    return app.response_class(
        decrypted,
        mimetype=doc['mime_type'] or 'application/octet-stream',
        headers={'Content-Disposition': f'attachment; filename="{doc["filename"]}"'},
    )


@app.route('/api/documents/<int:doc_id>/view')
@login_required
def api_documents_view(doc_id):
    """Serve the document inline so the browser can render it directly."""
    db  = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)).fetchone()
    if not doc:
        return jsonify({'error': 'Not found'}), 404
    if not user_can_access_doc(doc):
        return jsonify({'error': 'Forbidden'}), 403
    log_action('view_document', 'documents', doc_id, {'title': doc['title']})
    with open(os.path.join(UPLOAD_DIR, doc['file_path']), 'rb') as fh:
        decrypted = decrypt_file(fh.read())
    return app.response_class(
        decrypted,
        mimetype=doc['mime_type'] or 'application/octet-stream',
        headers={'Content-Disposition': f'inline; filename="{doc["filename"]}"'},
    )


@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
@permission_required('documents.delete')
def api_documents_delete(doc_id):
    db  = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)).fetchone()
    if not doc:
        return jsonify({'error': 'Not found'}), 404
    db.execute('UPDATE documents SET active = 0 WHERE id = ?', (doc_id,))
    db.commit()
    # Remove the encrypted file from disk — no point keeping it once deleted from the repo
    file_path = os.path.join(UPLOAD_DIR, doc['file_path'])
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except OSError:
        pass  # File already gone — not a reason to fail the request
    log_action('delete_document', 'documents', doc_id, {'title': doc['title']})
    return jsonify({'success': True})


# ── BLUEPRINT: email templates ────────────────────────────────────────────────

@app.route('/api/email-templates')
@permission_required('mailshots.templates')
def api_email_templates_list():
    db   = get_db()
    rows = db.execute(
        'SELECT et.*, u.username AS created_by_name FROM email_templates et'
        ' LEFT JOIN users u ON u.id = et.created_by ORDER BY et.name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/email-templates', methods=['POST'])
@permission_required('mailshots.templates')
def api_email_templates_create():
    data    = request.get_json() or {}
    name    = data.get('name', '').strip()
    subject = data.get('subject', '').strip()
    body    = data.get('body_html', '').strip()
    if not name or not subject or not body:
        return jsonify({'error': 'Name, subject and body are required'}), 400
    db = get_db()
    db.execute(
        'INSERT INTO email_templates (name, subject, body_html, created_by) VALUES (?,?,?,?)',
        (name, subject, body, session['user_id'])
    )
    db.commit()
    log_action('create_email_template', 'email_templates', None, {'name': name})
    return jsonify({'success': True})


@app.route('/api/email-templates/<int:tmpl_id>', methods=['PUT'])
@permission_required('mailshots.templates')
def api_email_templates_update(tmpl_id):
    data    = request.get_json() or {}
    name    = data.get('name', '').strip()
    subject = data.get('subject', '').strip()
    body    = data.get('body_html', '').strip()
    if not name or not subject or not body:
        return jsonify({'error': 'Name, subject and body are required'}), 400
    db = get_db()
    db.execute(
        'UPDATE email_templates SET name=?, subject=?, body_html=?, updated_at=datetime("now")'
        ' WHERE id=?',
        (name, subject, body, tmpl_id)
    )
    db.commit()
    log_action('edit_email_template', 'email_templates', tmpl_id, {'name': name})
    return jsonify({'success': True})


@app.route('/api/email-templates/<int:tmpl_id>', methods=['DELETE'])
@permission_required('mailshots.templates')
def api_email_templates_delete(tmpl_id):
    db = get_db()
    db.execute('DELETE FROM email_templates WHERE id = ?', (tmpl_id,))
    db.commit()
    return jsonify({'success': True})


# ── BLUEPRINT: mailshots ───────────────────────────────────────────────────────

def _get_recipients(session_filter, status_filter):
    """
    Return a deduplicated list of (email, member_name) tuples from
    member_contacts (contact_order=1) matching the given filters.
    Editors are automatically scoped to their own session.
    """
    db = get_db()
    conditions = ["m.status != 'Leaver'"]
    params     = []

    if status_filter and status_filter != 'all':
        conditions.append('m.status = ?')
        params.append(status_filter)

    # Editors are scoped to their session; admins can filter freely
    scoped = _assigned_session()
    if scoped is not None:
        conditions.append('m.session = ?')
        params.append(scoped)
    elif session_filter and session_filter != 'all':
        conditions.append('m.session = ?')
        params.append(session_filter)

    where = ' AND '.join(conditions)
    rows  = db.execute(f'''
        SELECT  DISTINCT c.contact_email,
                m.first_name || " " || m.surname AS member_name
        FROM    members m
        JOIN    member_contacts c ON c.member_id = m.id AND c.contact_order = 1
        WHERE   {where}
          AND   c.contact_email IS NOT NULL
          AND   trim(c.contact_email) != ""
        ORDER   BY m.first_name
    ''', params).fetchall()
    return [{'email': r['contact_email'], 'name': r['member_name']} for r in rows]


@app.route('/api/mailshots/preview', methods=['POST'])
@permission_required('mailshots.send')
def api_mailshots_preview():
    """Return how many unique recipient emails a mailshot would reach."""
    data       = request.get_json() or {}
    recipients = _get_recipients(data.get('session_filter'), data.get('status_filter'))
    return jsonify({'count': len(recipients), 'recipients': recipients})


@app.route('/api/mailshots/send', methods=['POST'])
@permission_required('mailshots.send')
def api_mailshots_send():
    """Send a mailshot via Gmail SMTP and log it."""
    data           = request.get_json() or {}
    subject        = data.get('subject', '').strip()
    body           = data.get('body_html', '').strip()
    template_id    = data.get('template_id')
    explicit_recip = data.get('recipients')        # list of {email, name} from frontend checklist
    document_ids   = data.get('document_ids', [])  # list of document IDs to attach

    if not subject or not body:
        return jsonify({'error': 'Subject and body are required'}), 400
    if not SMTP_USER or not SMTP_PASS:
        return jsonify({'error': 'Email not configured — add MAIL_USERNAME and MAIL_PASSWORD to your .env file'}), 503

    # Use explicit selection from the frontend checklist; fall back to filter query
    if explicit_recip and isinstance(explicit_recip, list):
        recipients = [r for r in explicit_recip if r.get('email')]
    else:
        session_filter = data.get('session_filter', 'all')
        recipients = _get_recipients(session_filter, 'Active')

    if not recipients:
        return jsonify({'error': 'No recipients selected'}), 400

    # Resolve and validate attachments from the document repository
    db          = get_db()
    attachments = []   # list of {filename, mime_type, data (bytes)}
    if document_ids:
        for doc_id in document_ids:
            doc = db.execute(
                'SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)
            ).fetchone()
            if not doc:
                return jsonify({'error': f'Document ID {doc_id} not found in repository'}), 400
            if not user_can_access_doc(doc):
                return jsonify({'error': f'Access denied to document: {doc["title"]}'}), 403
            file_path = os.path.join(UPLOAD_DIR, doc['file_path'])
            if not os.path.exists(file_path):
                return jsonify({'error': f'File not found on server for: {doc["title"]}'}), 500
            with open(file_path, 'rb') as f:
                attachments.append({
                    'filename':  doc['filename'],
                    'mime_type': doc['mime_type'] or 'application/octet-stream',
                    'data':      decrypt_file(f.read()),
                })
            log_action('attach_to_mailshot', 'documents', doc_id, {'title': doc['title'], 'subject': subject})

    emails_sent = 0
    errors      = []
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(SMTP_USER, SMTP_PASS)
            for r in recipients:
                try:
                    # Use 'mixed' when there are attachments, 'alternative' for body-only
                    msg = MIMEMultipart('mixed') if attachments else MIMEMultipart('alternative')
                    msg['Subject'] = subject
                    msg['From']    = SMTP_FROM
                    msg['To']      = r['email']
                    msg.attach(MIMEText(body, 'html', 'utf-8'))

                    for att in attachments:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(att['data'])
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            'attachment',
                            filename=att['filename'],
                        )
                        part.set_type(att['mime_type'])
                        msg.attach(part)

                    srv.sendmail(SMTP_FROM, [r['email']], msg.as_string())
                    emails_sent += 1
                except Exception as e:
                    errors.append({'email': r['email'], 'error': str(e)})
    except smtplib.SMTPAuthenticationError:
        return jsonify({'error': 'Gmail authentication failed — check your App Password in .env'}), 503
    except Exception as e:
        return jsonify({'error': f'SMTP error: {str(e)}'}), 503

    # Log mailshot — store document IDs in filter_criteria for audit trail
    log_meta = {
        'recipients':       len(recipients),
        'manual_selection': bool(explicit_recip),
        'document_ids':     list(document_ids) if document_ids else [],
    }
    db.execute(
        'INSERT INTO mailshot_log (template_id, subject, sent_by, recipient_count, filter_criteria, notes)'
        ' VALUES (?,?,?,?,?,?)',
        (
            template_id,
            subject,
            session['user_id'],
            emails_sent,
            json.dumps(log_meta),
            f'{len(errors)} error(s)' if errors else None,
        )
    )
    db.commit()
    log_action('send_mailshot', 'mailshot_log', None, {
        'subject': subject, 'sent': emails_sent, 'errors': len(errors),
        'attachments': len(attachments),
    })
    return jsonify({'success': True, 'sent': emails_sent, 'errors': errors})


@app.route('/api/mailshots')
@permission_required('mailshots.send')
def api_mailshots_history():
    db   = get_db()
    rows = db.execute('''
        SELECT  ml.*, u.username AS sent_by_name,
                et.name AS template_name
        FROM    mailshot_log ml
        LEFT JOIN users u ON u.id = ml.sent_by
        LEFT JOIN email_templates et ON et.id = ml.template_id
        ORDER   BY ml.sent_at DESC
        LIMIT   50
    ''').fetchall()
    return jsonify([dict(r) for r in rows])


# ── BLUEPRINT: maintenance (admin only) ───────────────────────────────────────

@app.route('/api/admin/maintenance/counts')
@permission_required('admin.maintenance')
def api_maintenance_counts():
    """Return record counts for each clearable data category."""
    db = get_db()
    return jsonify({
        'audit_log':      db.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0],
        'attendance':     db.execute('SELECT COUNT(*) FROM attendance').fetchone()[0],
        'mailshot_log':   db.execute('SELECT COUNT(*) FROM mailshot_log').fetchone()[0],
        'registrations':  db.execute('SELECT COUNT(*) FROM pending_registrations').fetchone()[0],
    })


@app.route('/api/admin/maintenance/audit-log', methods=['DELETE'])
@permission_required('admin.maintenance')
def api_maintenance_clear_audit():
    db = get_db()
    n  = db.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    db.execute('DELETE FROM audit_log')
    db.commit()
    # Write a single fresh entry so the log is never completely empty
    log_action('maintenance_clear', 'audit_log', None,
               {'cleared': n, 'by': session['username']})
    return jsonify({'success': True, 'deleted': n})


@app.route('/api/admin/maintenance/attendance', methods=['DELETE'])
@permission_required('admin.maintenance')
def api_maintenance_clear_attendance():
    db = get_db()
    n  = db.execute('SELECT COUNT(*) FROM attendance').fetchone()[0]
    db.execute('DELETE FROM attendance')
    db.commit()
    log_action('maintenance_clear', 'attendance', None,
               {'cleared': n, 'by': session['username']})
    return jsonify({'success': True, 'deleted': n})


@app.route('/api/admin/maintenance/mailshot-log', methods=['DELETE'])
@permission_required('admin.maintenance')
def api_maintenance_clear_mailshots():
    db = get_db()
    n  = db.execute('SELECT COUNT(*) FROM mailshot_log').fetchone()[0]
    db.execute('DELETE FROM mailshot_log')
    db.commit()
    log_action('maintenance_clear', 'mailshot_log', None,
               {'cleared': n, 'by': session['username']})
    return jsonify({'success': True, 'deleted': n})


@app.route('/api/admin/maintenance/registrations', methods=['DELETE'])
@permission_required('admin.maintenance')
def api_maintenance_clear_registrations():
    db = get_db()
    n  = db.execute('SELECT COUNT(*) FROM pending_registrations').fetchone()[0]
    db.execute('DELETE FROM pending_registrations')
    db.commit()
    log_action('maintenance_clear', 'pending_registrations', None,
               {'cleared': n, 'by': session['username']})
    return jsonify({'success': True, 'deleted': n})


# ── BLUEPRINT: roles + permissions (v6.0) ─────────────────────────────────────

@app.route('/api/admin/permissions')
@permission_required('admin.settings')
def api_permissions_list():
    """Return all permission codes grouped by category."""
    db   = get_db()
    rows = db.execute(
        'SELECT code, name, description, category FROM permissions ORDER BY category, code'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/admin/roles')
@permission_required('admin.settings')
def api_roles_list():
    """Return all roles with their permission sets."""
    db   = get_db()
    rows = db.execute(
        'SELECT id, name, is_default, permissions, created_at FROM roles ORDER BY name'
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d['permissions'] = json.loads(d['permissions'])
        except (TypeError, ValueError):
            d['permissions'] = []
        result.append(d)
    return jsonify(result)


@app.route('/api/admin/roles', methods=['POST'])
@permission_required('admin.settings')
def api_roles_create():
    """Create a new custom role."""
    data  = request.get_json() or {}
    name  = data.get('name', '').strip()
    perms = data.get('permissions', [])

    if not name:
        return jsonify({'error': 'Role name is required'}), 400
    if not isinstance(perms, list):
        return jsonify({'error': 'permissions must be a list'}), 400

    # Validate all permission codes exist
    db         = get_db()
    valid_codes = {r['code'] for r in db.execute('SELECT code FROM permissions').fetchall()}
    bad = [p for p in perms if p not in valid_codes]
    if bad:
        return jsonify({'error': f'Unknown permission code(s): {", ".join(bad)}'}), 400

    # Only users with users.create.admin can include that permission in a new role
    if 'users.create.admin' in perms and not has_permission('users.create.admin'):
        return jsonify({'error': 'You do not have permission to assign users.create.admin'}), 403

    try:
        cur = db.execute(
            'INSERT INTO roles (name, permissions, is_default) VALUES (?,?,0)',
            (name, json.dumps(perms))
        )
        db.commit()
        log_action('create_role', 'roles', cur.lastrowid, {'name': name, 'permissions': perms})
        row = db.execute('SELECT id, name, is_default, permissions, created_at FROM roles WHERE id = ?',
                         (cur.lastrowid,)).fetchone()
        d = dict(row)
        d['permissions'] = json.loads(d['permissions'])
        return jsonify(d), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A role named "{name}" already exists'}), 409


@app.route('/api/admin/roles/<int:role_id>', methods=['PUT'])
@permission_required('admin.settings')
def api_roles_update(role_id):
    """Update a role's name and/or permission set."""
    data  = request.get_json() or {}
    db    = get_db()
    role  = db.execute('SELECT * FROM roles WHERE id = ?', (role_id,)).fetchone()
    if not role:
        return jsonify({'error': 'Role not found'}), 404

    name  = data.get('name', role['name']).strip()
    perms = data.get('permissions', json.loads(role['permissions']))

    if not name:
        return jsonify({'error': 'Role name is required'}), 400
    if not isinstance(perms, list):
        return jsonify({'error': 'permissions must be a list'}), 400

    # Validate all permission codes exist
    valid_codes = {r['code'] for r in db.execute('SELECT code FROM permissions').fetchall()}
    bad = [p for p in perms if p not in valid_codes]
    if bad:
        return jsonify({'error': f'Unknown permission code(s): {", ".join(bad)}'}), 400

    # Only users with users.create.admin can add that permission to a role
    old_perms = json.loads(role['permissions'])
    if 'users.create.admin' in perms and 'users.create.admin' not in old_perms:
        if not has_permission('users.create.admin'):
            return jsonify({'error': 'You do not have permission to assign users.create.admin'}), 403

    try:
        db.execute(
            'UPDATE roles SET name = ?, permissions = ? WHERE id = ?',
            (name, json.dumps(perms), role_id)
        )
        db.commit()
        log_action('update_role', 'roles', role_id, {'name': name, 'permissions': perms})
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A role named "{name}" already exists'}), 409

    # Refresh session permissions if the user's own role was updated
    # (so changes take effect on their next page load rather than next login)
    row = db.execute('SELECT id, name, is_default, permissions, created_at FROM roles WHERE id = ?',
                     (role_id,)).fetchone()
    d = dict(row)
    d['permissions'] = json.loads(d['permissions'])
    return jsonify(d)


@app.route('/api/admin/roles/<int:role_id>', methods=['DELETE'])
@permission_required('admin.settings')
def api_roles_delete(role_id):
    """Delete a custom role. Default roles and roles with assigned users cannot be deleted."""
    db   = get_db()
    role = db.execute('SELECT * FROM roles WHERE id = ?', (role_id,)).fetchone()
    if not role:
        return jsonify({'error': 'Role not found'}), 404

    if role['is_default']:
        return jsonify({'error': 'Default roles cannot be deleted'}), 400

    # Prevent deletion if any users are assigned to this role
    user_count = db.execute(
        'SELECT COUNT(*) FROM users WHERE role_id = ?', (role_id,)
    ).fetchone()[0]
    if user_count:
        return jsonify({'error': f'Cannot delete — {user_count} user(s) are assigned to this role'}), 400

    db.execute('DELETE FROM roles WHERE id = ?', (role_id,))
    db.commit()
    log_action('delete_role', 'roles', role_id, {'name': role['name']})
    return jsonify({'success': True})


# ── Run ────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # Auto-init DB on first run if it doesn't exist
    if not os.path.exists(DATABASE):
        print('First run — initialising database…')
        init_db()
    _debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=_debug, host='127.0.0.1', port=5001, threaded=True)
