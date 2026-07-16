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

import sqlcipher3 as sqlite3
from cryptography.fernet import Fernet
from flask import g, has_request_context, jsonify, redirect, request, session, url_for

from config import (
    DATABASE, UPLOAD_DIR, ALLOWED_EXTENSIONS,
    BRAND_KEYS, CLUB_NAME, CLUB_SHORT_NAME,
    ROLE_ADMIN, ROLE_DISPLAY_NAMES,
    LOGIN_MAX_FAILURES, LOGIN_LOCKOUT_SECONDS,
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
        # v12.42: client_ip() not remote_addr — behind Caddy the latter logged
        # the proxy's IP for every audit entry.
        ip  = ip_address if ip_address is not None else (client_ip() if in_request else 'system')

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


def refresh_session_grants(max_age_seconds=60):
    """Re-sync role, permissions and session names from the DB into the Flask
    session (v12.41). Previously grants were loaded only at login, so role edits,
    session reassignments and account deactivation didn't take effect until the
    user logged out. Throttled via session['grants_synced_at'] so it costs at
    most a few queries per user per minute.

    Returns False if the user no longer exists or is inactive — the caller
    should clear the session and treat them as logged out.
    """
    now = time.time()
    if now - session.get('grants_synced_at', 0) < max_age_seconds:
        return True

    db   = get_db()
    user = db.execute(
        'SELECT id, role, role_id, active_session_id FROM users WHERE id = ? AND active = 1',
        (session['user_id'],)
    ).fetchone()
    if not user:
        return False

    # Resolve role + permissions (mirrors the login flow: role_id first, name fallback)
    perms, role_name, role_id = [], user['role'], user['role_id']
    role_row = None
    if user['role_id']:
        role_row = db.execute(
            'SELECT id, name, permissions, display_name FROM roles WHERE id = ?',
            (user['role_id'],)
        ).fetchone()
    if not role_row:
        role_row = db.execute(
            'SELECT id, name, permissions, display_name FROM roles WHERE name = ?',
            (user['role'],)
        ).fetchone()
    role_display = ROLE_DISPLAY_NAMES.get(role_name, role_name)
    if role_row:
        role_id      = role_row['id']
        role_name    = role_row['name']
        role_display = role_row['display_name'] or ROLE_DISPLAY_NAMES.get(role_name, role_name)
        try:
            perms = json.loads(role_row['permissions'])
        except (TypeError, ValueError):
            perms = []

    sess_rows = db.execute(
        'SELECT st.name FROM user_sessions us '
        'JOIN session_types st ON st.id = us.session_type_id '
        'WHERE us.user_id = ? AND st.active = 1 '
        'ORDER BY st.sort_order, st.name',
        (user['id'],)
    ).fetchall()
    session_names = [r['name'] for r in sess_rows]

    # Keep active_session valid for scoped users; admins are never constrained.
    active_session = session.get('active_session')
    if role_name != ROLE_ADMIN and session_names and active_session not in session_names:
        active_session = session_names[0]

    session['role']             = role_name
    session['role_display']    = role_display
    session['role_id']          = role_id
    session['permissions']      = perms
    session['session_names']    = session_names
    session['active_session']   = active_session
    session['grants_synced_at'] = now
    return True


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
        'current_session':      session.get('active_session', ''),
        'session_names':        session.get('session_names', []),
        'app_version':          APP_VERSION,
        'session_types':        get_session_types(),
        'member_types':         get_member_types(),
        'user_permissions':     session.get('permissions', []),
        'club_name':            club,
        'club_short_name':      short,
        'brand':                brand,
    }


def club_slug():
    """Filename-safe slug of the club short name, preferring the branded value
    over the .env CLUB_SHORT_NAME (v12.42 — export filenames were inconsistent:
    some used the brand name, some the .env constant)."""
    brand = get_brand_settings()
    short = brand.get('brand_short_name') or CLUB_SHORT_NAME
    return short.lower().replace(' ', '_')


# ── Settings ───────────────────────────────────────────────────────────────────

def get_setting(key, default=None):
    """Return a value from the settings table, or default if not found."""
    db  = get_db()
    row = db.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
    return row['value'] if row else default


# ── Session types ──────────────────────────────────────────────────────────────

# v12.63: default calendar palette — deterministic per session type by id so
# every screen shows the same colour before an admin picks one explicitly.
SESSION_COLOUR_PALETTE = (
    '#3b82f6', '#8b5cf6', '#ec4899', '#f43f5e', '#f97316', '#f59e0b',
    '#10b981', '#14b8a6', '#06b6d4', '#6366f1', '#84cc16', '#a855f7',
)


def default_session_colour(session_id):
    """Deterministic fallback colour for a session type with no explicit colour."""
    try:
        return SESSION_COLOUR_PALETTE[int(session_id) % len(SESSION_COLOUR_PALETTE)]
    except (TypeError, ValueError):
        return SESSION_COLOUR_PALETTE[0]


def get_session_types():
    """Return active session types from the DB, cached per request in Flask g.
    Each row carries a 'colour' — the admin-set hex, or a deterministic palette
    fallback (v12.63) so the calendar/legend always have a stable colour."""
    if 'session_types' not in g:
        db   = get_db()
        rows = db.execute(
            'SELECT id, name, weekday, description, colour FROM session_types '
            'WHERE active = 1 ORDER BY sort_order, name'
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d['colour'] = (d.get('colour') or '').strip() or default_session_colour(d['id'])
            result.append(d)
        g.session_types = result
    return g.session_types


def get_member_types():
    """Return active member types from the DB, cached per request in Flask g."""
    if 'member_types' not in g:
        db   = get_db()
        rows = db.execute(
            'SELECT slug, name, icon, registration_style FROM member_types '
            'WHERE active = 1 ORDER BY sort_order, name'
        ).fetchall()
        g.member_types = [dict(r) for r in rows]
    return g.member_types


def get_valid_session_names():
    return tuple(s['name'] for s in get_session_types())


def weekday_to_session_map():
    """Return {weekday_int: session_name} — only includes sessions that have a weekday set."""
    return {s['weekday']: s['name'] for s in get_session_types() if s['weekday'] is not None}


def session_to_weekday_map():
    """Return {session_name: weekday_int} — only includes sessions that have a weekday set."""
    return {s['name']: s['weekday'] for s in get_session_types() if s['weekday'] is not None}


# ── Multi-session membership helpers (v12.50 Phase A) ─────────────────────────
# A member belongs to N sessions via the member_sessions junction table.
# members.session is kept as a read-only echo (first assigned session by
# sort_order) so not-yet-converted readers keep working; never treat it as
# authoritative in new code.

def get_member_session_names(member_id):
    """Return the member's assigned session names, ordered by session sort order."""
    db   = get_db()
    rows = db.execute(
        'SELECT st.name FROM member_sessions ms '
        'JOIN session_types st ON st.id = ms.session_type_id '
        'WHERE ms.member_id = ? ORDER BY st.sort_order, st.name',
        (member_id,)
    ).fetchall()
    return [r['name'] for r in rows]


def get_sessions_for_members(member_ids):
    """Batch version: {member_id: [session names…]} for a list of member ids."""
    if not member_ids:
        return {}
    db = get_db()
    ph = ','.join('?' * len(member_ids))
    rows = db.execute(
        f'SELECT ms.member_id, st.name FROM member_sessions ms '
        f'JOIN session_types st ON st.id = ms.session_type_id '
        f'WHERE ms.member_id IN ({ph}) ORDER BY st.sort_order, st.name',
        list(member_ids)
    ).fetchall()
    out = {}
    for r in rows:
        out.setdefault(r['member_id'], []).append(r['name'])
    return out


def set_member_sessions(member_id, names):
    """Replace a member's session assignments with the given session names.

    Validates names against ALL session_types — active AND inactive (v12.65:
    `active` governs UI visibility, not data validity; validating against
    active types only meant editing any member assigned to a deactivated
    session silently dropped that assignment, because the edit modal can't
    render a chip for it). Assignments to inactive types that the caller
    doesn't mention are PRESERVED for the same reason — the UI can't send
    what it can't show. Rewrites member_sessions and keeps the
    members.session echo column in sync (first assigned session by
    sort_order; empty string when none). Caller commits.
    Returns the cleaned, ordered list actually stored.
    """
    db        = get_db()
    all_types = db.execute(
        'SELECT id, name, active FROM session_types ORDER BY sort_order, name'
    ).fetchall()
    type_id   = {t['name']: t['id'] for t in all_types}
    order     = {t['name']: i for i, t in enumerate(all_types)}
    inactive  = {t['name'] for t in all_types if not t['active']}

    clean = [n for n in dict.fromkeys(names or []) if n in type_id]  # dedupe, validate

    # v12.65: carry over existing assignments to inactive session types that the
    # caller omitted — UI callers only render active types, so omission there
    # means "invisible", not "remove".
    existing_inactive = [r['name'] for r in db.execute(
        'SELECT st.name FROM member_sessions ms '
        'JOIN session_types st ON st.id = ms.session_type_id '
        'WHERE ms.member_id = ? AND st.active = 0', (member_id,)
    ).fetchall()]
    for n in existing_inactive:
        if n not in clean and n in inactive:
            clean.append(n)

    clean.sort(key=lambda n: order[n])

    db.execute('DELETE FROM member_sessions WHERE member_id = ?', (member_id,))
    for n in clean:
        db.execute(
            'INSERT OR IGNORE INTO member_sessions (member_id, session_type_id) VALUES (?,?)',
            (member_id, type_id[n])
        )
    db.execute('UPDATE members SET session = ? WHERE id = ?',
               (clean[0] if clean else '', member_id))
    return clean


def member_in_scope(member_id, scoped=None):
    """True if the user may access this member: any of the member's sessions
    intersects the user's session scope. Admins (scoped None) always pass.

    Falls back to the members.session echo when the member has no junction rows
    (defensive — the startup reconcile should prevent this)."""
    if scoped is None:
        scoped = _assigned_session()
    if scoped is None:            # unscoped admin
        return True
    if not scoped:                # scoped user with no sessions
        return False
    db = get_db()
    ph = ','.join('?' * len(scoped))
    hit = db.execute(
        f'SELECT 1 FROM member_sessions ms '
        f'JOIN session_types st ON st.id = ms.session_type_id '
        f'WHERE ms.member_id = ? AND st.name IN ({ph}) LIMIT 1',
        [member_id] + list(scoped)
    ).fetchone()
    if hit:
        return True
    row = db.execute('SELECT session FROM members WHERE id = ?', (member_id,)).fetchone()
    return bool(row) and (row['session'] or '') in scoped


# ── Register helpers ───────────────────────────────────────────────────────────

def _is_register_locked(sess_type, sess_date):
    db  = get_db()
    row = db.execute(
        'SELECT id FROM session_completions WHERE session_date = ? AND session_type = ?',
        (sess_date, sess_type)
    ).fetchone()
    return row is not None


def _assigned_session():
    """Return the list of session names this user can access, or None for unscoped admin.

    Return values:
        None         — admin, no filter (sees all sessions)
        ['Tuesday']  — non-admin scoped to one or more specific sessions
        []           — non-admin with no sessions assigned (locked out; should not happen
                       after v10.3 validation but handled defensively)
    """
    if session.get('role') == ROLE_ADMIN:
        return None
    return session.get('session_names', [])


def get_active_session():
    """Return the session name the user is currently working in, or None for admin.

    For admins there is no active session concept — they see all data unfiltered.
    For non-admins this is the session they last selected (or their only session),
    persisted to users.active_session_id and loaded into the Flask cookie session at login.
    """
    if session.get('role') == ROLE_ADMIN:
        return None
    return session.get('active_session') or None


def _attendance_marker_path():
    """Path to the lightweight file whose mtime signals an attendance change.
    Lives in the same data directory as the database."""
    return os.path.join(os.path.dirname(DATABASE), '.attendance_changed')


def _touch_attendance():
    """Signal that attendance changed so the display SSE stream can refresh.

    Writes a timestamp to settings (kept for back-compat) AND bumps the mtime of
    a marker file.  The display stream polls the marker file's mtime via a cheap
    os.stat, which means the long-lived stream never has to open or hold a
    database connection just to check for changes — important because unlocking
    the SQLCipher database on every poll would be expensive.
    """
    db  = get_db()
    now = datetime.now().isoformat()
    db.execute(
        'INSERT INTO settings (key, value) VALUES (?,?) '
        'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
        ('last_attendance_change', now)
    )
    db.commit()
    # Bump the marker file's mtime (create it if missing). Best-effort only —
    # never let a marker-file problem break a sign-in/out.
    marker = _attendance_marker_path()
    try:
        with open(marker, 'a'):
            pass
        os.utime(marker, None)
    except OSError:
        pass


def _read_attendance_marker():
    """Return the attendance marker file's mtime (float), or None if it does not
    exist yet.  Used by the display SSE stream to detect changes without opening
    a database connection."""
    try:
        return os.path.getmtime(_attendance_marker_path())
    except OSError:
        return None


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


def client_ip():
    """Return the real client IP for rate limiting and audit (v12.42).

    Behind the reverse proxy (Caddy) every request reaches the container from
    the proxy's IP, so per-IP rate limits (login lockout, registration, QR)
    would share ONE bucket across all users — a handful of failures would lock
    everyone out. The real client IP arrives in X-Forwarded-For.

    Trusting that header is only safe when a proxy we control sets it, so it is
    gated on TRUST_PROXY_HEADERS (default '1' — matches the standard Caddy
    deployment). Set TRUST_PROXY_HEADERS=0 in .env if the app port is exposed
    directly, where a client could spoof the header to dodge rate limits.
    """
    if os.environ.get('TRUST_PROXY_HEADERS', '1') == '1':
        xff = request.headers.get('X-Forwarded-For', '')
        if xff:
            return xff.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


# ── Rate limiting (DB-backed, shared across worker processes) ──────────────────
# These replace the old per-process in-memory dicts so the limits stay accurate
# regardless of how many gunicorn workers are running.  Each limiter uses its own
# short-lived connection so it never entangles the request's main transaction.

def rate_limit_touch(bucket_key, max_count, window_seconds):
    """Sliding-window limiter that counts the current attempt.

    Returns (allowed: bool, retry_after_seconds: int).  Used by the public
    registration and QR endpoints.  Shared across workers via the rate_limits
    table, so N workers can't multiply the effective limit.
    """
    db  = _connect_db()
    now = time.time()
    try:
        db.row_factory = sqlite3.Row
        row = db.execute(
            'SELECT window_start, count FROM rate_limits WHERE bucket_key = ?',
            (bucket_key,)
        ).fetchone()

        # Fresh window (no row yet, or the previous window has elapsed)
        if row is None or (now - row['window_start']) >= window_seconds:
            db.execute(
                'INSERT INTO rate_limits (bucket_key, window_start, count, locked_until, updated_at) '
                "VALUES (?,?,1,0,datetime('now')) "
                'ON CONFLICT(bucket_key) DO UPDATE SET '
                'window_start=excluded.window_start, count=1, locked_until=0, updated_at=excluded.updated_at',
                (bucket_key, now)
            )
            # Opportunistic cleanup so the table can't grow without bound
            db.execute(
                'DELETE FROM rate_limits WHERE locked_until < ? AND window_start < ?',
                (now, now - 86400)
            )
            db.commit()
            return True, 0

        new_count = row['count'] + 1
        db.execute(
            "UPDATE rate_limits SET count=?, updated_at=datetime('now') WHERE bucket_key=?",
            (new_count, bucket_key)
        )
        db.commit()
        if new_count > max_count:
            retry = int(window_seconds - (now - row['window_start']))
            return False, max(retry, 1)
        return True, 0
    finally:
        db.close()


def login_rate_status(ip):
    """Return (allowed, retry_after_seconds) for a login attempt from this IP."""
    db  = _connect_db()
    now = time.time()
    try:
        db.row_factory = sqlite3.Row
        row = db.execute(
            'SELECT locked_until FROM rate_limits WHERE bucket_key = ?', (f'login:{ip}',)
        ).fetchone()
        if row and row['locked_until'] and now < row['locked_until']:
            return False, int(row['locked_until'] - now) + 1
        return True, 0
    finally:
        db.close()


def record_login_failure(ip):
    """Count a failed login from this IP; lock the IP out once the threshold is hit."""
    db  = _connect_db()
    now = time.time()
    key = f'login:{ip}'
    try:
        db.row_factory = sqlite3.Row
        row   = db.execute('SELECT count FROM rate_limits WHERE bucket_key = ?', (key,)).fetchone()
        count = (row['count'] if row else 0) + 1
        if count >= LOGIN_MAX_FAILURES:
            # Lock out and reset the counter (mirrors the previous in-memory behaviour)
            db.execute(
                'INSERT INTO rate_limits (bucket_key, window_start, count, locked_until, updated_at) '
                "VALUES (?,?,0,?,datetime('now')) "
                'ON CONFLICT(bucket_key) DO UPDATE SET count=0, locked_until=excluded.locked_until, '
                'updated_at=excluded.updated_at',
                (key, now, now + LOGIN_LOCKOUT_SECONDS)
            )
        else:
            db.execute(
                'INSERT INTO rate_limits (bucket_key, window_start, count, locked_until, updated_at) '
                "VALUES (?,?,?,0,datetime('now')) "
                'ON CONFLICT(bucket_key) DO UPDATE SET count=excluded.count, updated_at=excluded.updated_at',
                (key, now, count)
            )
        db.commit()
    finally:
        db.close()


def clear_login_failures(ip):
    """Clear the failure counter / lockout for this IP after a successful login."""
    db = _connect_db()
    try:
        db.execute('DELETE FROM rate_limits WHERE bucket_key = ?', (f'login:{ip}',))
        db.commit()
    finally:
        db.close()


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
