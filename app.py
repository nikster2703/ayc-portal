"""
AYC Portal — Flask Application  v3.6
Phases 1-5: Auth, members, audit, user admin, approvals, register,
            documents, comms, term calendar, staff registrations.

Phase roadmap (this file grows into blueprints as phases are added):
  Phase 1 — Auth, members lookup, edit/delete, audit log, user admin  ✓
  Phase 2 — Approvals: review pending registrations                   ✓
  Phase 3 — Digital session register + attendance history + auto-leaver ✓
  Phase 4 — Document repository, email templates, mailshots           ✓
  Phase 5 — Term calendar, staff registrations, user permanent delete ✓
  Phase 6 — Duke of Edinburgh module

To split into blueprints later, each section marked ## BLUEPRINT: <name>
can be extracted to blueprints/<name>.py and registered with app.register_blueprint().
"""

import os
import json
import secrets
import sqlite3
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

APP_VERSION = 'v4.7'  # Full responsive overhaul: 5-tier breakpoints (desktop / tablet-landscape / tablet-portrait / mobile-landscape / mobile-portrait); scrollable nav on iPad portrait

# ── Postcode lookup (getaddress.io) ──────────────────────────────────────────
GETADDRESS_KEY = os.environ.get('GETADDRESS_KEY', '')

# ── SMTP config (set in .env) ─────────────────────────────────────────────────
SMTP_HOST = os.environ.get('MAIL_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('MAIL_PORT', 587))
SMTP_USER = os.environ.get('MAIL_USERNAME', '')
SMTP_PASS = os.environ.get('MAIL_PASSWORD', '')
SMTP_FROM = os.environ.get('MAIL_FROM', SMTP_USER)

# ── Database helpers ───────────────────────────────────────────────────────────

def get_db():
    """Return a request-scoped DB connection."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
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
    db = sqlite3.connect(DATABASE)
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
    """Create any tables added after initial deploy without requiring a full init-db."""
    db = sqlite3.connect(DATABASE)
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
        CREATE TABLE IF NOT EXISTS settings (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            updated_at TEXT,
            updated_by INTEGER REFERENCES users(id)
        );
    ''')
    # Seed default settings if they don't exist yet
    settings_db = sqlite3.connect(DATABASE)
    settings_db.row_factory = sqlite3.Row
    for key, val in [('at_risk_threshold_tuesday', '5'), ('at_risk_threshold_thursday', '5')]:
        existing = settings_db.execute('SELECT key FROM settings WHERE key = ?', (key,)).fetchone()
        if not existing:
            settings_db.execute('INSERT INTO settings (key, value) VALUES (?, ?)', (key, val))
    settings_db.commit()
    settings_db.close()
    # ALTER TABLE migrations — each wrapped individually so existing columns don't abort the rest
    alter_stmts = [
        "ALTER TABLE members ADD COLUMN member_type TEXT NOT NULL DEFAULT 'member'",
        "ALTER TABLE members ADD COLUMN staff_role TEXT",
        "ALTER TABLE pending_registrations ADD COLUMN registration_type TEXT NOT NULL DEFAULT 'member'",
        "ALTER TABLE pending_registrations ADD COLUMN applicant_role TEXT",
        "ALTER TABLE pending_registrations ADD COLUMN mobile TEXT",
        "ALTER TABLE pending_registrations ADD COLUMN email TEXT",
        "ALTER TABLE members ADD COLUMN status_note TEXT",
    ]
    for stmt in alter_stmts:
        try:
            db.execute(stmt)
        except Exception:
            pass  # Column already exists — safe to ignore

    db.commit()
    db.close()

# Run migration on startup
with app.app_context():
    if os.path.exists(DATABASE):
        ensure_tables()

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

def role_required(*roles):
    """Restrict access to users with one of the specified roles."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            if session.get('role') not in roles:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Forbidden'}), 403
                return redirect(url_for('dashboard_page'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def tpl_ctx():
    """Inject current user info into every protected template."""
    return {
        'current_user':    session.get('username', ''),
        'current_role':    session.get('role', ''),
        'current_session': session.get('session_assigned', ''),
        'app_version':     APP_VERSION,
    }

# ── Page routes ────────────────────────────────────────────────────────────────

@app.route('/')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard_page'))
    return render_template('index.html', app_version=APP_VERSION)

@app.route('/dashboard')
@login_required
def dashboard_page():
    return render_template('dashboard.html', active_page='dashboard', **tpl_ctx())

@app.route('/members')
@role_required('admin', 'editor', 'leader')
def members_page():
    return render_template('members.html', active_page='members', **tpl_ctx())

@app.route('/approvals')
@role_required('admin', 'editor')
def approvals_page():
    return render_template('approvals.html', active_page='approvals', **tpl_ctx())

@app.route('/register')
@login_required
def register_page():
    return render_template('register.html', active_page='register', **tpl_ctx())

@app.route('/registration')
def registration_page():
    """Landing page — choose member or staff registration."""
    return render_template('registration_landing.html')

@app.route('/registration/member')
def registration_member_page():
    """Full member self-registration form — no login required."""
    return render_template('registration.html', version=APP_VERSION)

@app.route('/registration/staff')
def registration_staff_page():
    """Simplified staff/volunteer registration form — no login required."""
    return render_template('registration_staff.html', version=APP_VERSION)

@app.route('/documents')
@role_required('admin', 'editor', 'leader', 'readonly')
def documents_page():
    return render_template('documents.html', active_page='documents', **tpl_ctx())

@app.route('/communications')
@role_required('admin', 'editor')
def communications_page():
    return render_template('communications.html', active_page='communications', **tpl_ctx())

@app.route('/admin/users')
@role_required('admin', 'editor')
def users_page():
    return render_template('admin/users.html', active_page='users', **tpl_ctx())

@app.route('/admin/audit')
@role_required('admin', 'editor')
def audit_page():
    return render_template('admin/audit.html', active_page='audit', **tpl_ctx())

@app.route('/admin/settings')
@role_required('admin', 'editor')
def settings_page():
    return render_template('admin/settings.html', active_page='settings', **tpl_ctx())

@app.route('/api/settings')
@role_required('admin', 'editor')
def api_settings_get():
    """Return all settings as a key/value dict."""
    db   = get_db()
    rows = db.execute('SELECT key, value FROM settings').fetchall()
    return jsonify({r['key']: r['value'] for r in rows})

@app.route('/api/settings', methods=['POST'])
@role_required('admin', 'editor')
def api_settings_save():
    """Save one or more settings. Body: {key: value, ...}"""
    data = request.get_json() or {}
    allowed_keys = {'at_risk_threshold_tuesday', 'at_risk_threshold_thursday'}

    # Editors can only update the threshold for their own session
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
        session.permanent = True
        session['user_id']          = user['id']
        session['username']         = user['username']
        session['role']             = user['role']
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
                'role':             user['role'],
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
    })

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def api_change_password():
    data         = request.get_json() or {}
    current_pw   = data.get('current_password', '')
    new_pw       = data.get('new_password', '')

    if not current_pw or not new_pw:
        return jsonify({'error': 'Both current and new passwords are required'}), 400
    if len(new_pw) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400

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
@role_required('admin', 'editor', 'leader')
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
@role_required('admin', 'editor', 'leader')
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
@role_required('admin', 'editor', 'leader')
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
@role_required('admin', 'editor')
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
@role_required('admin', 'editor')
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
@role_required('admin')
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
                SUM(CASE WHEN member_type = "member" AND status != "Leaver" AND session = "Tuesday"  THEN 1 ELSE 0 END) AS tuesday,
                SUM(CASE WHEN member_type = "member" AND status != "Leaver" AND session = "Thursday" THEN 1 ELSE 0 END) AS thursday,
                SUM(CASE WHEN member_type = "staff"  AND status != "Leaver" THEN 1 ELSE 0 END) AS staff_active,
                SUM(CASE WHEN member_type = "staff"  AND status != "Leaver" AND session = "Tuesday"  THEN 1 ELSE 0 END) AS staff_tuesday,
                SUM(CASE WHEN member_type = "staff"  AND status != "Leaver" AND session = "Thursday" THEN 1 ELSE 0 END) AS staff_thursday
            FROM members
        ''').fetchone()
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
                SUM(CASE WHEN member_type = "member" AND status != "Leaver" AND session = "Tuesday"  THEN 1 ELSE 0 END) AS tuesday,
                SUM(CASE WHEN member_type = "member" AND status != "Leaver" AND session = "Thursday" THEN 1 ELSE 0 END) AS thursday,
                SUM(CASE WHEN member_type = "staff"  AND status != "Leaver" THEN 1 ELSE 0 END) AS staff_active,
                SUM(CASE WHEN member_type = "staff"  AND status != "Leaver" AND session = "Tuesday"  THEN 1 ELSE 0 END) AS staff_tuesday,
                SUM(CASE WHEN member_type = "staff"  AND status != "Leaver" AND session = "Thursday" THEN 1 ELSE 0 END) AS staff_thursday
            FROM members
            WHERE session = ?
        ''', (scoped,)).fetchone()
        pending = db.execute(
            'SELECT COUNT(*) AS n FROM pending_registrations WHERE status = "pending"'
            ' AND (assigned_session = ? OR assigned_session IS NULL OR assigned_session = "")',
            (scoped,)
        ).fetchone()['n']

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
        'pending_approvals': pending,
        'today_attendance': [dict(r) for r in today_att],
        'recent_activity':  [dict(r) for r in recent],
        'scoped_session':   scoped,   # lets the frontend know which session tile to highlight
    })


@app.route('/api/admin/audit')
@role_required('admin', 'editor')
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
        if applicant_role not in ('Volunteer', 'Youth Volunteer', 'Leader'):
            return jsonify({'error': 'Invalid role'}), 400
        session_pref = data.get('assigned_session', '').strip()
        if session_pref not in ('Tuesday', 'Thursday'):
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

VALID_ROLES = ('admin', 'editor', 'leader', 'readonly')

@app.route('/api/admin/users')
@role_required('admin', 'editor')
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
@role_required('admin', 'editor')
def api_users_create():
    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role     = data.get('role', 'readonly')
    email    = data.get('email', '').strip()
    sess     = data.get('session_assigned', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if role not in VALID_ROLES:
        return jsonify({'error': 'Invalid role'}), 400
    # Leaders cannot create admin accounts — only admins can grant admin role
    if role == 'admin' and session.get('role') != 'admin':
        return jsonify({'error': 'Only admins can create admin accounts'}), 403
    # Non-admin roles must have a session assigned
    if role != 'admin' and not sess:
        return jsonify({'error': 'A session must be assigned for non-admin users'}), 400
    if sess and sess not in ('Tuesday', 'Thursday'):
        return jsonify({'error': 'Invalid session — must be Tuesday or Thursday'}), 400
    # Editors can only create users for their own session
    scoped = _assigned_session()
    if scoped is not None and sess != scoped:
        return jsonify({'error': 'You can only create users for your own session'}), 403

    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db = get_db()
    try:
        db.execute(
            'INSERT INTO users (username, email, password_hash, role, session_assigned)'
            ' VALUES (?,?,?,?,?)',
            (username, email, pw_hash, role, sess)
        )
        db.commit()
        log_action('create_user', 'users', None,
                   {'username': username, 'role': role, 'created_by': session.get('username')})
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@role_required('admin', 'editor')
def api_users_update(user_id):
    data    = request.get_json() or {}
    db      = get_db()
    updates = []
    params  = []

    # Safety: cannot deactivate your own account
    if user_id == session['user_id'] and data.get('active') is False:
        return jsonify({'error': 'You cannot deactivate your own account'}), 400
    # Leaders cannot elevate any account to admin
    if 'role' in data and data['role'] == 'admin' and session.get('role') != 'admin':
        return jsonify({'error': 'Only admins can assign the admin role'}), 403

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
        if data['role'] not in VALID_ROLES:
            return jsonify({'error': 'Invalid role'}), 400
        updates.append('role = ?')
        params.append(data['role'])

    if 'session_assigned' in data:
        updates.append('session_assigned = ?')
        params.append(data['session_assigned'])

    if 'active' in data:
        updates.append('active = ?')
        params.append(1 if data['active'] else 0)

    if 'password' in data and data['password']:
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
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
@role_required('admin')
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
    """Generate the next sequential AYC member ID, e.g. AYC042."""
    row = db.execute(
        "SELECT member_id FROM members WHERE member_id LIKE 'AYC%'"
        " ORDER BY CAST(SUBSTR(member_id, 4) AS INTEGER) DESC LIMIT 1"
    ).fetchone()
    if row:
        try:
            num = int(row['member_id'][3:]) + 1
        except (ValueError, AttributeError):
            num = 1
    else:
        num = 1
    return f'AYC{num:03d}'


@app.route('/api/approvals')
@role_required('admin', 'editor')
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
@role_required('admin', 'editor')
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
            if portal_role not in VALID_ROLES:
                return jsonify({'error': 'Invalid portal role'}), 400
            existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            if existing:
                return jsonify({'error': f'Username "{username}" is already taken'}), 409
            pw_hash = bcrypt.hashpw(temp_password.encode(), bcrypt.gensalt()).decode()
            cur = db.execute(
                'INSERT INTO users (username, email, password_hash, role, session_assigned, active)'
                ' VALUES (?,?,?,?,?,1)',
                (username, reg['email'] or '', pw_hash, portal_role, assigned_session)
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
@role_required('admin', 'editor')
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
    if session_type not in ('Tuesday', 'Thursday'):
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
@login_required
def api_attendance_signin():
    # Readonly users may view the register but cannot sign members in
    if session.get('role') == 'readonly':
        return jsonify({'error': 'Read-only users cannot sign members in'}), 403

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
@login_required
def api_attendance_signout():
    if session.get('role') == 'readonly':
        return jsonify({'error': 'Read-only users cannot sign members out'}), 403

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


def _assigned_session():
    """
    Return the session this user is scoped to, or None for admin (unscoped).
    All non-admin roles MUST have a session_assigned.
    """
    if session.get('role') == 'admin':
        return None
    return session.get('session_assigned') or ''


@app.route('/api/attendance/check-at-risk')
@role_required('admin', 'editor')
def api_attendance_check_at_risk():
    """
    Return active members who have missed their last N consecutive sessions,
    where N is the configurable per-session threshold from settings.
    Uses term_sessions to determine what sessions have occurred.
    """
    db    = get_db()
    today = datetime.now().strftime('%Y-%m-%d')

    threshold_tue = int(get_setting('at_risk_threshold_tuesday',  '5'))
    threshold_thu = int(get_setting('at_risk_threshold_thursday', '5'))

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
        assigned = m['session']  # 'Tuesday' or 'Thursday'

        if assigned == 'Tuesday':
            checks = [('Tuesday', sessions_by_type['Tuesday'][:threshold_tue], threshold_tue)]
        elif assigned == 'Thursday':
            checks = [('Thursday', sessions_by_type['Thursday'][:threshold_thu], threshold_thu)]
        else:
            continue  # skip any legacy Both records

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
@role_required('admin', 'editor')
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
    return render_template('display.html', current_session=session.get('session_assigned', ''))


@app.route('/api/display/<session_type>')
def api_display(session_type):
    """
    Return names of members currently signed IN (not yet signed out) for
    today's session, plus on-duty leaders and active activities.
    No login required — returns first name + surname only, no sensitive data.
    """
    if session_type not in ('Tuesday', 'Thursday'):
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
    if session_type not in ('Tuesday', 'Thursday'):
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
@login_required
def api_activity_add():
    """Add an activity to the display board."""
    data     = request.get_json() or {}
    sess     = data.get('session_type', '').strip()
    activity = data.get('activity', '').strip()
    if sess not in ('Tuesday', 'Thursday'):
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
@login_required
def api_activity_delete(activity_id):
    """Remove an activity from the display board."""
    db = get_db()
    db.execute('UPDATE session_activities SET active = 0 WHERE id = ?', (activity_id,))
    db.commit()
    return jsonify({'ok': True})


# ── BLUEPRINT: calendar (Phase 5) ────────────────────────────────────────────

VALID_SESSION_TYPES = ('Tuesday', 'Thursday')
VALID_STATUSES      = ('planned', 'cancelled', 'special')
WEEKDAY_NAMES       = {1: 'Tuesday', 3: 'Thursday'}  # Python weekday(): Mon=0


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
@role_required('admin', 'editor')
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
    if session_type not in VALID_SESSION_TYPES:
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
        d = dt_date.fromisoformat(session_date)
        expected_day = 1 if session_type == 'Tuesday' else 3  # Mon=0
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
@role_required('admin', 'editor')
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

    # Map day names to Python weekday numbers
    target_weekdays = set()
    for d in days:
        if d == 'Tuesday':  target_weekdays.add(1)
        elif d == 'Thursday': target_weekdays.add(3)

    # Walk the date range
    created, skipped = 0, 0
    db = get_db()
    current = start
    while current <= end:
        if current.weekday() in target_weekdays:
            date_str     = current.isoformat()
            session_type = 'Tuesday' if current.weekday() == 1 else 'Thursday'
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
@role_required('admin', 'editor')
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
@role_required('admin', 'editor')
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
@login_required
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
@role_required('admin', 'editor')
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
    f.save(os.path.join(UPLOAD_DIR, stored_name))

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
    return send_from_directory(UPLOAD_DIR, doc['file_path'],
                               download_name=doc['filename'], as_attachment=True)


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
    return send_from_directory(UPLOAD_DIR, doc['file_path'],
                               download_name=doc['filename'], as_attachment=False)


@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
@role_required('admin', 'editor')
def api_documents_delete(doc_id):
    db  = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)).fetchone()
    if not doc:
        return jsonify({'error': 'Not found'}), 404
    db.execute('UPDATE documents SET active = 0 WHERE id = ?', (doc_id,))
    db.commit()
    log_action('delete_document', 'documents', doc_id, {'title': doc['title']})
    return jsonify({'success': True})


# ── BLUEPRINT: email templates ────────────────────────────────────────────────

@app.route('/api/email-templates')
@role_required('admin', 'editor')
def api_email_templates_list():
    db   = get_db()
    rows = db.execute(
        'SELECT et.*, u.username AS created_by_name FROM email_templates et'
        ' LEFT JOIN users u ON u.id = et.created_by ORDER BY et.name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/email-templates', methods=['POST'])
@role_required('admin', 'editor')
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
@role_required('admin', 'editor')
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
@role_required('admin', 'editor')
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
@role_required('admin', 'editor')
def api_mailshots_preview():
    """Return how many unique recipient emails a mailshot would reach."""
    data       = request.get_json() or {}
    recipients = _get_recipients(data.get('session_filter'), data.get('status_filter'))
    return jsonify({'count': len(recipients), 'recipients': recipients})


@app.route('/api/mailshots/send', methods=['POST'])
@role_required('admin', 'editor')
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
                    'data':      f.read(),
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
@role_required('admin', 'editor')
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
@role_required('admin')
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
@role_required('admin')
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
@role_required('admin')
def api_maintenance_clear_attendance():
    db = get_db()
    n  = db.execute('SELECT COUNT(*) FROM attendance').fetchone()[0]
    db.execute('DELETE FROM attendance')
    db.commit()
    log_action('maintenance_clear', 'attendance', None,
               {'cleared': n, 'by': session['username']})
    return jsonify({'success': True, 'deleted': n})


@app.route('/api/admin/maintenance/mailshot-log', methods=['DELETE'])
@role_required('admin')
def api_maintenance_clear_mailshots():
    db = get_db()
    n  = db.execute('SELECT COUNT(*) FROM mailshot_log').fetchone()[0]
    db.execute('DELETE FROM mailshot_log')
    db.commit()
    log_action('maintenance_clear', 'mailshot_log', None,
               {'cleared': n, 'by': session['username']})
    return jsonify({'success': True, 'deleted': n})


@app.route('/api/admin/maintenance/registrations', methods=['DELETE'])
@role_required('admin')
def api_maintenance_clear_registrations():
    db = get_db()
    n  = db.execute('SELECT COUNT(*) FROM pending_registrations').fetchone()[0]
    db.execute('DELETE FROM pending_registrations')
    db.commit()
    log_action('maintenance_clear', 'pending_registrations', None,
               {'cleared': n, 'by': session['username']})
    return jsonify({'success': True, 'deleted': n})


# ── Run ────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # Auto-init DB on first run if it doesn't exist
    if not os.path.exists(DATABASE):
        print('First run — initialising database…')
        init_db()
    _debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=_debug, host='127.0.0.1', port=5001, threaded=True)
