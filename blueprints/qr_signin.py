"""
AYC Portal — QR quick-session blueprint (v8.3).
Routes: /quick-session, /api/quick-signin/*

Public mobile page + API for self sign-in / sign-out via QR code.
A session token (quick_signin_tokens table) is the sole gate.
All public API endpoints are CSRF-exempt; they validate via the token instead.
"""

import secrets
from datetime import datetime

from flask import Blueprint, jsonify, request

from extensions import csrf
from helpers import (
    get_db, log_action, login_required, permission_required, get_setting,
    get_valid_session_names,
    _is_register_locked, _touch_attendance,
    _get_or_create_qr_token,
    _validate_qr_token,
)

bp = Blueprint('qr_signin', __name__)

# Simple in-memory rate limiter — (ip, endpoint, minute_bucket) → request count.
_rl_store: dict = {}


def _rl_check(endpoint: str, max_per_min: int) -> bool:
    """Return True if the request is within rate limit, False if exceeded."""
    ip     = request.remote_addr or 'unknown'
    bucket = datetime.now().strftime('%Y%m%d%H%M')
    key    = (ip, endpoint, bucket)
    count  = _rl_store.get(key, 0) + 1
    _rl_store[key] = count
    # Prune old buckets (keep store small)
    if len(_rl_store) > 2000:
        cur = datetime.now().strftime('%Y%m%d%H%M')
        for k in list(_rl_store.keys()):
            if k[2] != cur:
                del _rl_store[k]
    return count <= max_per_min


# ── Authenticated: token management (called by register page JS) ──────────────

@bp.route('/api/quick-signin/token/<session_type>')
@login_required
def api_qr_token_get(session_type):
    """Return (or create) today's QR token + full URL for the given session."""
    if session_type not in get_valid_session_names():
        return jsonify({'error': 'Invalid session type'}), 400
    token    = _get_or_create_qr_token(session_type)
    base_url = request.host_url.rstrip('/')
    qr_url   = f'{base_url}/quick-session?t={token}'
    db       = get_db()
    today    = datetime.now().strftime('%Y-%m-%d')
    qr_in    = db.execute(
        "SELECT COUNT(*) FROM attendance WHERE session_date=? AND session_type=?"
        " AND source='qr-self' AND signed_in_at IS NOT NULL",
        (today, session_type),
    ).fetchone()[0]
    qr_out   = db.execute(
        "SELECT COUNT(*) FROM attendance WHERE session_date=? AND session_type=?"
        " AND source='qr-self' AND signed_out_at IS NOT NULL",
        (today, session_type),
    ).fetchone()[0]
    return jsonify({
        'token':             token,
        'qr_url':            qr_url,
        'qr_signin_count':   qr_in,
        'qr_signout_count':  qr_out,
    })


@bp.route('/api/quick-signin/token/<session_type>/regenerate', methods=['POST'])
@permission_required('register.qr_manage')
def api_qr_token_regenerate(session_type):
    """Invalidate existing token and issue a fresh one."""
    if session_type not in get_valid_session_names():
        return jsonify({'error': 'Invalid session type'}), 400
    today = datetime.now().strftime('%Y-%m-%d')
    db    = get_db()
    db.execute(
        '''UPDATE quick_signin_tokens SET invalidated_at = datetime('now')
           WHERE session_type = ? AND session_date = ? AND invalidated_at IS NULL''',
        (session_type, today),
    )
    db.commit()
    token    = _get_or_create_qr_token(session_type)
    base_url = request.host_url.rstrip('/')
    qr_url   = f'{base_url}/quick-session?t={token}'
    log_action('qr_token_regenerated', 'quick_signin_tokens', None,
               {'session_type': session_type})
    return jsonify({'token': token, 'qr_url': qr_url})


# ── Public display-token endpoint (unauthenticated, for the TV display) ───────

@bp.route('/api/quick-signin/display-token/<session_type>')
@csrf.exempt
def api_qr_display_token(session_type):
    """Return the current QR URL for the TV display, or null if none active."""
    if session_type not in get_valid_session_names():
        return jsonify({'qr_url': None})
    today = datetime.now().strftime('%Y-%m-%d')
    db    = get_db()
    row   = db.execute(
        '''SELECT token FROM quick_signin_tokens
           WHERE session_type = ? AND session_date = ? AND invalidated_at IS NULL''',
        (session_type, today),
    ).fetchone()
    if not row:
        return jsonify({'qr_url': None})
    # Suppress if register is locked
    if _is_register_locked(session_type, today):
        return jsonify({'qr_url': None})
    base_url = request.host_url.rstrip('/')
    return jsonify({'qr_url': f'{base_url}/quick-session?t={row["token"]}'})


# ── Public API: verify / search / signin / signout ────────────────────────────

@bp.route('/api/quick-signin/verify')
@csrf.exempt
def api_qr_verify():
    """Validate a QR token and return which modes are enabled."""
    token = request.args.get('t', '').strip()
    if not token:
        return jsonify({'valid': False, 'reason': 'No token provided.'})
    row = _validate_qr_token(token)
    if not row:
        return jsonify({
            'valid':  False,
            'reason': 'This sign-in link has expired or is no longer valid.',
        })
    sess_type = row['session_type']
    sess_date = row['session_date']
    if _is_register_locked(sess_type, sess_date):
        return jsonify({
            'valid':  False,
            'reason': 'The session register has been completed and is now locked.',
        })
    return jsonify({
        'valid':           True,
        'session_type':    sess_type,
        'session_date':    sess_date,
        'signin_enabled':  get_setting('quick_signin_enabled',  'true')  == 'true',
        'signout_enabled': get_setting('quick_signout_enabled', 'false') == 'true',
    })


@bp.route('/api/quick-signin/search')
@csrf.exempt
def api_qr_search():
    """Search members by first name for the QR session page."""
    if not _rl_check('qr_search', 15):
        return jsonify({'error': 'Too many requests — please slow down.'}), 429

    token = request.args.get('t', '').strip()
    q     = request.args.get('q', '').strip()
    mode  = request.args.get('mode', 'signin').strip()   # 'signin' | 'signout'

    if len(q) < 2:
        return jsonify([])
    tok_row = _validate_qr_token(token)
    if not tok_row:
        return jsonify({'error': 'Invalid or expired token.'}), 403

    sess_type = tok_row['session_type']
    sess_date = tok_row['session_date']

    if _is_register_locked(sess_type, sess_date):
        return jsonify({'error': 'Register is locked.'}), 403

    db = get_db()

    if mode == 'signout':
        # Only show members currently signed IN (not yet signed out)
        rows = db.execute(
            '''SELECT m.id, m.first_name, m.surname,
                      1 AS already_signed_in
               FROM members m
               JOIN attendance a ON a.member_id = m.id
                 AND a.session_date = ? AND a.session_type = ?
                 AND a.signed_in_at IS NOT NULL AND a.signed_out_at IS NULL
               WHERE EXISTS (SELECT 1 FROM member_statuses ms WHERE ms.name = m.status AND ms.behaviour = 'active')
                 AND LOWER(m.first_name) LIKE LOWER(?)
               ORDER BY m.first_name, m.surname
               LIMIT 20''',
            (sess_date, sess_type, q + '%'),
        ).fetchall()
    else:
        # Sign-in: all active members for this session, flag those already signed in
        rows = db.execute(
            '''SELECT m.id, m.first_name, m.surname,
                      CASE WHEN a.signed_in_at IS NOT NULL THEN 1 ELSE 0 END AS already_signed_in
               FROM members m
               LEFT JOIN attendance a ON a.member_id = m.id
                 AND a.session_date = ? AND a.session_type = ?
               JOIN member_types mt ON mt.slug = m.member_type
               WHERE EXISTS (SELECT 1 FROM member_statuses ms WHERE ms.name = m.status AND ms.behaviour = 'active')
                 AND (m.session = ? OR mt.registration_style = 'staff')
                 AND LOWER(m.first_name) LIKE LOWER(?)
               ORDER BY m.first_name, m.surname
               LIMIT 20''',
            (sess_date, sess_type, sess_type, q + '%'),
        ).fetchall()

    return jsonify([dict(r) for r in rows])


@bp.route('/api/quick-signin/signin', methods=['POST'])
@csrf.exempt
def api_qr_signin():
    """Sign a member in via QR token. Bulletproof against duplicates and races."""
    if not _rl_check('qr_signin', 10):
        return jsonify({'error': 'Too many requests — please slow down.'}), 429

    data      = request.get_json() or {}
    token     = data.get('token', '').strip()
    member_id = data.get('member_id')

    if get_setting('quick_signin_enabled', 'true') != 'true':
        return jsonify({'error': 'QR sign-in is not enabled.'}), 403

    tok_row = _validate_qr_token(token)
    if not tok_row:
        return jsonify({'error': 'Invalid or expired token.'}), 403

    sess_type = tok_row['session_type']
    sess_date = tok_row['session_date']

    if _is_register_locked(sess_type, sess_date):
        return jsonify({'error': 'Register is locked.'}), 403

    db     = get_db()
    member = db.execute(
        "SELECT id, first_name FROM members WHERE id = ? "
        "AND EXISTS (SELECT 1 FROM member_statuses ms WHERE ms.name = members.status AND ms.behaviour = 'active')",
        (member_id,),
    ).fetchone()
    if not member:
        return jsonify({'error': 'Member not found.'}), 404

    first_name = member['first_name'] or 'there'
    now        = datetime.now().strftime('%H:%M')

    # Check if already signed in
    existing = db.execute(
        'SELECT id, signed_in_at FROM attendance '
        'WHERE member_id=? AND session_date=? AND session_type=?',
        (member_id, sess_date, sess_type),
    ).fetchone()

    if existing and existing['signed_in_at']:
        msg = get_setting('quick_signin_already_msg',
                          "You're already signed in, {name}! See you inside 👋")
        return jsonify({
            'success':           True,
            'already_signed_in': True,
            'first_name':        first_name,
            'welcome_message':   msg.replace('{name}', first_name),
        })

    # INSERT OR IGNORE protects against concurrent double-taps
    db.execute(
        '''INSERT OR IGNORE INTO attendance
               (member_id, session_date, session_type, signed_in_at, recorded_by, source)
           VALUES (?,?,?,?,NULL,'qr-self')''',
        (member_id, sess_date, sess_type, now),
    )
    if db.execute('SELECT changes()').fetchone()[0] == 0:
        # Row already existed (race) — treat as already signed in
        msg = get_setting('quick_signin_already_msg',
                          "You're already signed in, {name}! See you inside 👋")
        db.commit()
        return jsonify({
            'success':           True,
            'already_signed_in': True,
            'first_name':        first_name,
            'welcome_message':   msg.replace('{name}', first_name),
        })

    # Auto-resolve attendance alert flags (mirrors api_attendance_signin logic)
    att_flags = db.execute(
        "SELECT mf.id FROM member_flags mf "
        "JOIN alert_rules ar ON ar.id = mf.rule_id "
        "WHERE mf.member_id = ? AND mf.resolved_at IS NULL "
        "AND ar.rule_type = 'attendance' AND ar.auto_resolve = 1",
        (member_id,),
    ).fetchall()
    for flag in att_flags:
        db.execute(
            "UPDATE member_flags SET resolved_at = datetime('now'), resolved_by = 'auto' "
            "WHERE id = ?",
            (flag['id'],),
        )

    db.commit()
    _touch_attendance()

    msg = get_setting('quick_signin_welcome_msg',
                      'Welcome, {name}! Great to see you tonight! 🎉')
    return jsonify({
        'success':           True,
        'already_signed_in': False,
        'first_name':        first_name,
        'welcome_message':   msg.replace('{name}', first_name),
    })


@bp.route('/api/quick-signin/signout', methods=['POST'])
@csrf.exempt
def api_qr_signout():
    """Sign a member out via QR token. Only active when quick_signout_enabled = true."""
    if not _rl_check('qr_signout', 10):
        return jsonify({'error': 'Too many requests — please slow down.'}), 429

    if get_setting('quick_signout_enabled', 'false') != 'true':
        return jsonify({'error': 'QR sign-out is not enabled for this organisation.'}), 403

    data      = request.get_json() or {}
    token     = data.get('token', '').strip()
    member_id = data.get('member_id')

    tok_row = _validate_qr_token(token)
    if not tok_row:
        return jsonify({'error': 'Invalid or expired token.'}), 403

    sess_type = tok_row['session_type']
    sess_date = tok_row['session_date']

    if _is_register_locked(sess_type, sess_date):
        return jsonify({'error': 'Register is locked.'}), 403

    db     = get_db()
    member = db.execute(
        "SELECT id, first_name FROM members WHERE id = ? "
        "AND EXISTS (SELECT 1 FROM member_statuses ms WHERE ms.name = members.status AND ms.behaviour = 'active')",
        (member_id,),
    ).fetchone()
    if not member:
        return jsonify({'error': 'Member not found.'}), 404

    first_name = member['first_name'] or 'there'
    now        = datetime.now().strftime('%H:%M')

    existing = db.execute(
        'SELECT id, signed_in_at, signed_out_at FROM attendance '
        'WHERE member_id=? AND session_date=? AND session_type=?',
        (member_id, sess_date, sess_type),
    ).fetchone()

    if not existing or not existing['signed_in_at']:
        return jsonify({'error': 'This member is not currently signed in.'}), 400

    if existing['signed_out_at']:
        msg = get_setting('quick_signout_already_msg',
                          "You're already signed out, {name}. Safe journey home!")
        return jsonify({
            'success':            True,
            'already_signed_out': True,
            'first_name':         first_name,
            'goodbye_message':    msg.replace('{name}', first_name),
        })

    # UPDATE … WHERE signed_out_at IS NULL protects against concurrent races
    db.execute(
        '''UPDATE attendance SET signed_out_at = ?, source = 'qr-self'
           WHERE id = ? AND signed_out_at IS NULL''',
        (now, existing['id']),
    )
    if db.execute('SELECT changes()').fetchone()[0] == 0:
        msg = get_setting('quick_signout_already_msg',
                          "You're already signed out, {name}. Safe journey home!")
        db.commit()
        return jsonify({
            'success':            True,
            'already_signed_out': True,
            'first_name':         first_name,
            'goodbye_message':    msg.replace('{name}', first_name),
        })

    db.commit()
    _touch_attendance()

    msg = get_setting('quick_signout_goodbye_msg',
                      'Goodbye, {name}! See you next time 👋')
    return jsonify({
        'success':            True,
        'already_signed_out': False,
        'first_name':         first_name,
        'goodbye_message':    msg.replace('{name}', first_name),
    })
