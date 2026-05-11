"""
AYC Portal — Shared helper functions.
Imported by every blueprint.  No route definitions live here.
"""

import os
import re
import json
import time
import base64
import colorsys
import hashlib
import secrets
from datetime import datetime
from functools import wraps

import bcrypt
import sqlcipher3 as sqlite3
from cryptography.fernet import Fernet
from flask import g, has_request_context, jsonify, redirect, request, session, url_for

from config import (
    DATABASE, UPLOAD_DIR, BRANDING_DIR, ALLOWED_EXTENSIONS,
    BRAND_KEYS, CLUB_NAME, CLUB_SHORT_NAME,
    ROLE_ADMIN,
    SESSION_IDLE_TIMEOUT, LOGIN_MAX_FAILURES, LOGIN_LOCKOUT_SECONDS,
)

# ── Database ───────────────────────────────────────────────────────────────────

def _validate_encryption_key(key: str) -> None:
    """Guard against SQLCipher PRAGMA key injection."""
    if not key:
        raise RuntimeError(
            'DB_ENCRYPTION_KEY is not set in .env — refusing to start. '
            'Add the key to .env and restart the portal.'
        )
    if "'" in key:
        raise RuntimeError(
            "DB_ENCRYPTION_KEY must not contain a single-quote character (') "
            "as this would break the SQLCipher PRAGMA key statement. "
            'Generate a safe key with: python -c "import secrets; print(secrets.token_hex(32))"'
        )


def _connect_db(path=None):
    """Open a SQLCipher-encrypted DB connection."""
    if path is None:
        path = DATABASE
    key = os.environ.get('DB_ENCRYPTION_KEY', '')
    _validate_encryption_key(key)
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA key='{key}'")
    conn.execute('SELECT count(*) FROM sqlite_master')
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA busy_timeout=5000')
    return conn


def get_db():
    """Return a request-scoped DB connection with SQLCipher encryption."""
    if 'db' not in g:
        g.db = _connect_db()
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


def close_db(error=None):
    """Tear down the request-scoped DB connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def log_action(action, table_name=None, record_id=None, details=None,
               user_id=None, ip_address=None):
    """Write an entry to the audit log.  Never raises.

    Safe to call from both request context (normal use) and background tasks
    (scheduler, CLI).  When called outside a request context pass user_id and
    ip_address explicitly, or they will default to None / 'system'.
    """
    try:
        in_request = has_request_context()
        uid = user_id if user_id is not None else (session.get('user_id') if in_request else None)
        ip  = ip_address if ip_address is not None else (request.remote_addr if in_request else 'system')

        db = get_db() if in_request else _connect_db()
        own_conn = not in_request
        try:
            db.execute(
                'INSERT INTO audit_log (user_id, action, table_name, record_id, details, ip_address)'
                ' VALUES (?,?,?,?,?,?)',
                (
                    uid,
                    action,
                    table_name,
                    record_id,
                    json.dumps(details) if details else None,
                    ip,
                )
            )
            db.commit()
        finally:
            if own_conn:
                db.close()
    except Exception as _audit_exc:
        import sys
        print(
            f'AUDIT LOG FAILED — action={action} table={table_name} record={record_id}: {_audit_exc}',
            file=sys.stderr,
        )


# ── Document encryption ────────────────────────────────────────────────────────

def _doc_fernet():
    """Return a Fernet instance for document encryption.

    Uses DOCUMENT_ENCRYPTION_KEY if set, otherwise falls back to a SHA-256
    derivation of DB_ENCRYPTION_KEY for backward-compatibility with existing
    encrypted files.

    IMPORTANT: Set DOCUMENT_ENCRYPTION_KEY to a fresh Fernet key and run the
    document re-encryption script (scripts/reencrypt_documents.py) to fully
    decouple document encryption from the database key.

    Generate a new Fernet key:
        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    """
    doc_key = os.environ.get('DOCUMENT_ENCRYPTION_KEY', '').strip()
    if doc_key:
        try:
            return Fernet(doc_key.encode())
        except Exception:
            raise RuntimeError(
                'DOCUMENT_ENCRYPTION_KEY in .env is not a valid Fernet key. '
                'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            )

    # Fallback: derive from DB key (legacy behaviour — only used when
    # DOCUMENT_ENCRYPTION_KEY is not yet configured)
    db_key = os.environ.get('DB_ENCRYPTION_KEY', '').strip()
    if not db_key:
        raise RuntimeError(
            'Neither DOCUMENT_ENCRYPTION_KEY nor DB_ENCRYPTION_KEY is set in .env '
            '— cannot encrypt/decrypt documents.'
        )
    derived    = hashlib.sha256(db_key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(derived)
    return Fernet(fernet_key)


def encrypt_file(data: bytes) -> bytes:
    return _doc_fernet().encrypt(data)


def decrypt_file(token: bytes) -> bytes:
    return _doc_fernet().decrypt(token)


# ── Notifications ──────────────────────────────────────────────────────────────

def send_notification(sender_id, title, body, notification_type='Info',
                      target_type='all', target_value=None, is_system=0,
                      related_table=None, related_id=None, _db=None):
    """Create a notification record.  Works inside and outside request context."""
    own_conn = _db is None
    db       = _db if _db is not None else _connect_db()
    try:
        db.execute(
            'INSERT INTO notifications '
            '(sender_id, title, body, notification_type, target_type, target_value, '
            ' is_system, related_table, related_id) '
            'VALUES (?,?,?,?,?,?,?,?,?)',
            (
                sender_id, title, body, notification_type, target_type,
                json.dumps(target_value) if isinstance(target_value, (list, dict)) else target_value,
                is_system, related_table, related_id,
            )
        )
        if own_conn:
            db.commit()
    finally:
        if own_conn:
            db.close()
    log_action('notification.sent', 'notifications', None,
               {'title': title, 'type': notification_type, 'target': target_type, 'is_system': is_system})


# ── Auth decorators ────────────────────────────────────────────────────────────

def login_required(f):
    """Redirect to login (or return 401) if user is not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorised'}), 401
            return redirect(url_for('auth.login_page'))
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
                return redirect(url_for('pages.dashboard_page'))
            return f(*args, **kwargs)
        return decorated
    return decorator


def has_permission(permission_code):
    """Return True if the current session user has the given permission."""
    return permission_code in session.get('permissions', [])


# ── Password policy ────────────────────────────────────────────────────────────

def validate_password(password):
    """Return an error string if password fails policy, else None."""
    if len(password) < 8:
        return 'Password must be at least 8 characters'
    if not re.search(r'[A-Z]', password):
        return 'Password must contain at least one uppercase letter'
    if not re.search(r'[0-9]', password):
        return 'Password must contain at least one number'
    if not re.search(r'[^A-Za-z0-9]', password):
        return 'Password must contain at least one special character'
    return None


# ── Branding ───────────────────────────────────────────────────────────────────

def _hex_to_hls(hex_color):
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16)/255, int(h[2:4], 16)/255, int(h[4:6], 16)/255
    return colorsys.rgb_to_hls(r, g, b)


def _hls_to_hex(h, l, s):
    r, g, b = colorsys.hls_to_rgb(h, l, s)
    return '#{:02x}{:02x}{:02x}'.format(int(r*255), int(g*255), int(b*255))


def derive_palette(accent_hex):
    try:
        h, l, s = _hex_to_hls(accent_hex)
        dark  = _hls_to_hex(h, max(0.0, l * 0.80), min(1.0, s * 1.1))
        light = _hls_to_hex(h, min(0.96, l * 2.8 + 0.55), min(1.0, s * 0.6))
        return {'accent': accent_hex, 'accent_dark': dark, 'accent_light': light}
    except Exception:
        return {'accent': '#0096b4', 'accent_dark': '#007a96', 'accent_light': '#e0f6fb'}


_brand_cache = None


def _invalidate_brand_cache():
    global _brand_cache
    _brand_cache = None


def get_brand_settings():
    """Return brand settings dict, pulling from DB and caching in memory."""
    global _brand_cache
    if _brand_cache is not None:
        return _brand_cache

    db   = _connect_db()
    db.row_factory = sqlite3.Row
    rows = db.execute(
        "SELECT key, value FROM settings WHERE key LIKE 'brand_%'"
    ).fetchall()
    db.close()

    result = dict(BRAND_KEYS)
    for row in rows:
        result[row['key']] = row['value']

    palette   = derive_palette(result['brand_accent'])
    nav_style = result['brand_nav_style']
    if nav_style == 'accent':
        h, l, s  = _hex_to_hls(result['brand_accent'])
        nav_text = '#ffffff' if l < 0.55 else '#1a202c'
        nav_bg   = result['brand_accent']
        nav_border = palette['accent_dark']
    elif nav_style == 'white':
        nav_bg     = '#ffffff'
        nav_text   = '#1b2d4f'
        nav_border = '#dce3ef'
    else:
        nav_bg     = '#1b2d4f'
        nav_text   = '#ffffff'
        nav_border = 'transparent'

    result['_palette']    = palette
    result['_nav_bg']     = nav_bg
    result['_nav_text']   = nav_text
    result['_nav_border'] = nav_border
    result['_logo_url']   = f'/branding/logo?v={int(time.time())}' if result['brand_logo_file'] else ''

    _brand_cache = result
    return result


# ── Template context ───────────────────────────────────────────────────────────

def tpl_ctx():
    """Return a dict of template variables for every protected view."""
    from config import APP_VERSION
    brand = get_brand_settings()
    club  = brand.get('brand_club_name')  or CLUB_NAME
    short = brand.get('brand_short_name') or CLUB_SHORT_NAME
    return {
        'current_user':         session.get('username', ''),
        'current_role':         session.get('role', ''),
        'current_role_display': session.get('role_display', session.get('role', '')),
        'current_session':      session.get('session_assigned', ''),
        'app_version':          APP_VERSION,
        'session_types':        get_session_types(),
        'user_permissions':     session.get('permissions', []),
        'club_name':            club,
        'club_short_name':      short,
        'brand':                brand,
    }


# ── Settings ───────────────────────────────────────────────────────────────────

def get_setting(key, default=None):
    """Return a value from the settings table, or default if not found."""
    db  = get_db()
    row = db.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
    return row['value'] if row else default


# ── Session types ──────────────────────────────────────────────────────────────

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
    return tuple(s['name'] for s in get_session_types())


def weekday_to_session_map():
    return {s['weekday']: s['name'] for s in get_session_types()}


def session_to_weekday_map():
    return {s['name']: s['weekday'] for s in get_session_types()}


# ── Register helpers ───────────────────────────────────────────────────────────

def _is_register_locked(sess_type, sess_date):
    db  = get_db()
    row = db.execute(
        'SELECT id FROM session_completions WHERE session_date = ? AND session_type = ?',
        (sess_date, sess_type)
    ).fetchone()
    return row is not None


def _assigned_session():
    """Return the session this user is scoped to, or None for unscoped admin."""
    if session.get('role') == ROLE_ADMIN:
        return None
    return session.get('session_assigned') or ''


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


# ── Document helpers ───────────────────────────────────────────────────────────

def _fts5_available(db):
    try:
        db.execute('SELECT fts5(?)', ('test',))
        return True
    except Exception:
        pass
    try:
        db.execute("SELECT highlight(documents_fts, 0, '', '') FROM documents_fts LIMIT 0")
        return True
    except Exception:
        return False


def _rebuild_doc_fts(db, doc_id):
    """Rebuild the FTS5 index entry for a document."""
    if not _fts5_available(db):
        return
    doc = db.execute(
        'SELECT id, filename, description, active FROM documents WHERE id = ?',
        (doc_id,)
    ).fetchone()
    if not doc or not doc['active']:
        try:
            db.execute('DELETE FROM documents_fts WHERE doc_id = ?', (doc_id,))
        except Exception:
            pass
        return
    content = ' '.join(filter(None, [doc['filename'], doc['description']]))
    try:
        db.execute('DELETE FROM documents_fts WHERE doc_id = ?', (doc_id,))
        if content.strip():
            db.execute(
                'INSERT INTO documents_fts (doc_id, content) VALUES (?, ?)',
                (doc_id, content)
            )
    except Exception:
        pass


def resolve_doc_path(doc):
    """Return the filesystem path for a document row."""
    stored = doc['stored_filename'] if 'stored_filename' in doc.keys() else None
    if stored:
        bucket = doc['bucket'] if 'bucket' in doc.keys() and doc['bucket'] else 'store'
        return os.path.join(UPLOAD_DIR, bucket, stored)
    return doc['file_path']


def user_can_access_doc(doc):
    """Return True if the current session user can access this document."""
    db = get_db()
    allowed_rows = db.execute(
        'SELECT role_id FROM document_role_access WHERE document_id = ?',
        (doc['id'],)
    ).fetchall()
    if not allowed_rows:
        return True
    allowed_ids = {str(r['role_id']) for r in allowed_rows}
    user_role_id = str(session.get('role_id', ''))
    return user_role_id in allowed_ids


def _user_can_access_from_group_concat(allowed_role_ids_str):
    """Check access using a group_concat string from a query result."""
    if not allowed_role_ids_str:
        return True
    allowed = set(allowed_role_ids_str.split(','))
    return str(session.get('role_id', '')) in allowed


# ── Member helpers ─────────────────────────────────────────────────────────────

def _fetch_tags_for_members(db, member_ids):
    """Return a dict {member_id: [tag_dict, ...]} for a list of member IDs."""
    if not member_ids:
        return {}
    placeholders = ','.join('?' * len(member_ids))
    rows = db.execute(
        f'''SELECT mt.member_id, td.id, td.name, td.icon, td.colour, td.category,
                   mt.expires_at, mt.notes
            FROM   member_tags mt
            JOIN   tag_definitions td ON td.id = mt.tag_id
            WHERE  mt.member_id IN ({placeholders}) AND td.active = 1
            ORDER  BY td.sort_order, td.name''',
        member_ids
    ).fetchall()
    result = {}
    for r in rows:
        result.setdefault(r['member_id'], []).append(dict(r))
    return result


def _next_member_id(db):
    """Generate the next sequential member ID using prefix+padding from settings."""
    prefix_row  = db.execute("SELECT value FROM settings WHERE key='member_id_prefix'").fetchone()
    padding_row = db.execute("SELECT value FROM settings WHERE key='member_id_padding'").fetchone()

    from config import CLUB_SHORT_NAME as _csn
    if prefix_row is not None and padding_row is not None:
        prefix  = prefix_row['value']
        padding = int(padding_row['value'])
    else:
        prefix  = _csn
        padding = 3

    all_ids   = db.execute('SELECT member_id FROM members').fetchall()
    max_num   = 0
    suffix_re = re.compile(r'(\d+)$')
    for r in all_ids:
        mid = r['member_id'] or ''
        if not mid.startswith(prefix):
            continue
        m = suffix_re.search(mid)
        if m:
            max_num = max(max_num, int(m.group(1)))

    return f'{prefix}{max_num + 1:0{padding}d}'


def _save_id_format_from_import(db, imported_ids):
    """Detect and persist the member ID prefix/padding from imported IDs."""
    if not imported_ids:
        return
    pattern  = re.compile(r'^([^0-9]*)(\d+)$')
    prefixes = []
    paddings = []
    for mid in imported_ids:
        m = pattern.match(str(mid).strip())
        if not m:
            return
        prefixes.append(m.group(1))
        paddings.append(len(m.group(2)))
    if len(set(prefixes)) != 1:
        return
    prefix  = prefixes[0]
    padding = max(paddings)
    db.execute(
        "INSERT INTO settings (key,value) VALUES ('member_id_prefix',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')",
        (prefix,)
    )
    db.execute(
        "INSERT INTO settings (key,value) VALUES ('member_id_padding',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')",
        (str(padding),)
    )


# ── General utilities ──────────────────────────────────────────────────────────

_HEX_COLOUR_RE = re.compile(r'^#[0-9a-fA-F]{6}$')


def _validate_hex_colour(value: str, default: str) -> tuple:
    val = (value or '').strip()
    if not val:
        return default, None
    if not _HEX_COLOUR_RE.match(val):
        return default, f'Invalid colour "{val}" — must be a 6-digit hex code (e.g. #3b82f6)'
    return val, None


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _slugify(text):
    text  = text.lower().strip()
    text  = re.sub(r'[^\w\s-]', '', text)
    text  = re.sub(r'[\s_-]+', '-', text)
    return re.sub(r'^-+|-+$', '', text)


# ── QR token helpers ──────────────────────────────────────────────────────────

def _get_or_create_qr_token(session_type: str) -> str:
    """Return today's active QR token for session_type, creating one if needed."""
    today = datetime.now().strftime('%Y-%m-%d')
    db    = get_db()
    row   = db.execute(
        '''SELECT token FROM quick_signin_tokens
           WHERE session_type = ? AND session_date = ? AND invalidated_at IS NULL''',
        (session_type, today),
    ).fetchone()
    if row:
        return row['token']
    token = secrets.token_urlsafe(32)
    db.execute(
        'INSERT INTO quick_signin_tokens (token, session_type, session_date) VALUES (?,?,?)',
        (token, session_type, today),
    )
    db.commit()
    return token


def _ensure_qr_tokens_for_today():
    """Pre-create tokens for every active session type."""
    for st in get_session_types():
        _get_or_create_qr_token(st['name'])


def _validate_qr_token(token: str):
    """Return the token row if valid for today and not invalidated, else None."""
    today = datetime.now().strftime('%Y-%m-%d')
    db    = get_db()
    row   = db.execute(
        '''SELECT * FROM quick_signin_tokens
           WHERE token = ? AND session_date = ? AND invalidated_at IS NULL''',
        (token, today),
    ).fetchone()
    return row


def _invalidate_qr_token_for_session(session_type: str, session_date: str):
    """Stamp invalidated_at on all active tokens for this session."""
    db = get_db()
    db.execute(
        '''UPDATE quick_signin_tokens
           SET invalidated_at = datetime('now')
           WHERE session_type = ? AND session_date = ? AND invalidated_at IS NULL''',
        (session_type, session_date),
    )
    db.commit()


# ── General utilities ──────────────────────────────────────────────────────────

def _bool_val(v):
    """Coerce a spreadsheet value to a boolean."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    s = str(v).strip().lower()
    return s in ('yes', 'true', '1', 'y', 'on')


def _fmt_cell(v):
    """Format a spreadsheet cell value for display."""
    if v is None:
        return ''
    if isinstance(v, float) and v == int(v):
        return str(int(v))
    return str(v).strip()
