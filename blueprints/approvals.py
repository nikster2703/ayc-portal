"""
AYC Portal — Approvals blueprint.
Routes: /api/approvals/*, /api/registration, /api/staff-roles
"""

import json
import time
import threading

import bcrypt
from flask import Blueprint, jsonify, request, session

from helpers import (
    get_db, log_action, permission_required, has_permission,
    _assigned_session, _next_member_id, validate_password,
    get_valid_session_names,
)

bp = Blueprint('approvals', __name__)

# ── Simple IP-based rate limiter for the public registration endpoint ──────────
# Max 5 submissions per IP per hour.  Stored in-process (resets on restart),
# which is acceptable for a single-worker deployment.  Upgrade to Redis-backed
# Flask-Limiter if running multiple workers.
_REG_RATE_LIMIT   = 5          # max requests
_REG_RATE_WINDOW  = 3600       # per N seconds
_reg_rl_store: dict = {}
_reg_rl_lock  = threading.Lock()


def _registration_rate_limit(ip: str) -> bool:
    """Return True if the IP is within limit, False if it should be blocked."""
    now = time.time()
    with _reg_rl_lock:
        # Prune expired entries every time we touch the store
        expired = [k for k, v in _reg_rl_store.items()
                   if now - v['window_start'] >= _REG_RATE_WINDOW]
        for k in expired:
            del _reg_rl_store[k]

        entry = _reg_rl_store.get(ip)
        if entry is None or now - entry['window_start'] >= _REG_RATE_WINDOW:
            _reg_rl_store[ip] = {'window_start': now, 'count': 1}
            return True
        if entry['count'] >= _REG_RATE_LIMIT:
            return False
        entry['count'] += 1
        return True


# ── Public: staff roles (read-only, used by registration form) ────────────────

@bp.route('/api/staff-roles')
def api_staff_roles_public():
    """Return active staff roles ordered by display_order — no auth required."""
    db   = get_db()
    rows = db.execute(
        'SELECT id, name, display_order FROM staff_roles WHERE active = 1 ORDER BY display_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ── Public: registration submission ──────────────────────────────────────────

from extensions import csrf

@bp.route('/api/registration', methods=['POST'])
@csrf.exempt
def api_registration():
    """Accept a public self-registration and store it as pending.
    Fully field-driven — no hardcoded member/staff branching.
    Supports both legacy (registration_type) and new dynamic (member_type_slug) payloads.
    """
    # Rate limit: 5 submissions per IP per hour
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
    if not _registration_rate_limit(client_ip):
        return jsonify({'error': 'Too many registration attempts. Please try again later.'}), 429

    data = request.get_json() or {}
    db   = get_db()

    # Determine member type and registration style
    slug  = (data.get('member_type_slug') or data.get('registration_type') or 'member').strip()
    mtype = db.execute(
        'SELECT * FROM member_types WHERE slug = ? AND active = 1', (slug,)
    ).fetchone()

    if mtype:
        style         = mtype['registration_style'] or 'member'
        type_slug_val = mtype['slug']
        rtype         = 'staff' if style == 'staff' else 'member'
    else:
        rtype         = 'staff' if slug == 'staff' else 'member'
        style         = rtype
        type_slug_val = slug

    # Validate staff role if provided
    applicant_role = (data.get('applicant_role') or data.get('staff_role') or '').strip()
    if applicant_role:
        valid_roles = [r['name'] for r in db.execute(
            'SELECT name FROM staff_roles WHERE active = 1'
        ).fetchall()]
        if applicant_role not in valid_roles:
            return jsonify({'error': 'Invalid role'}), 400

    # Validate session if provided
    session_pref   = (data.get('assigned_session') or data.get('session') or '').strip()
    valid_sessions = get_valid_session_names()
    if session_pref and session_pref not in valid_sessions:
        return jsonify({'error': 'Invalid session preference'}), 400

    # Serialize any custom fields submitted by the dynamic form
    raw_custom         = data.get('custom_fields')
    custom_fields_json = json.dumps(raw_custom) if isinstance(raw_custom, dict) and raw_custom else None

    db.execute('''
        INSERT INTO pending_registrations
            (first_name, surname, date_of_birth, address, postcode,
             ethnicity_religion, medical_sen, gp_contact,
             unattended_exit, gdpr_consent, comms_consent,
             contact1_name, contact1_phone, contact1_email,
             contact2_name, contact2_phone, contact2_email,
             mobile, email,
             declarations, registration_type,
             custom_fields, member_type_slug,
             applicant_role, assigned_session)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
        data.get('mobile', '').strip(),
        data.get('email', '').strip(),
        json.dumps(data.get('declarations', {})),
        rtype,
        custom_fields_json,
        type_slug_val,
        applicant_role,
        session_pref,
    ))

    db.commit()
    return jsonify({'success': True})


# ── Approvals list ────────────────────────────────────────────────────────────

@bp.route('/api/approvals')
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


# ── Approve ───────────────────────────────────────────────────────────────────

@bp.route('/api/approvals/<int:reg_id>/approve', methods=['POST'])
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

    scoped = _assigned_session()
    if scoped is not None and assigned_session != scoped:
        return jsonify({'error': 'You can only approve registrations for your own session'}), 403

    rtype          = reg['registration_type'] or 'member'
    mid            = _next_member_id(db)
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

        full_name = f"{reg['first_name']} {reg['surname']}".strip()
        if reg['mobile'] or reg['email']:
            db.execute(
                'INSERT INTO member_contacts'
                ' (member_id, contact_order, contact_name, contact_phone, contact_email)'
                ' VALUES (?,1,?,?,?)',
                (member_db_id, full_name, reg['mobile'] or '', reg['email'] or '')
            )

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

    # Write custom fields from registration into member_field_values
    custom_raw = reg['custom_fields'] if 'custom_fields' in reg.keys() else None
    if custom_raw:
        try:
            custom_fields = json.loads(custom_raw)
            for key, val in custom_fields.items():
                if val is None or val == '':
                    continue
                fd = db.execute(
                    'SELECT id FROM field_definitions WHERE key = ?', (key,)
                ).fetchone()
                if fd:
                    db.execute(
                        'INSERT OR REPLACE INTO member_field_values'
                        ' (member_id, field_id, value, updated_at)'
                        ' VALUES (?, ?, ?, datetime("now"))',
                        (member_db_id, fd['id'], str(val))
                    )
        except (json.JSONDecodeError, TypeError):
            pass

    db.execute(
        'UPDATE pending_registrations'
        ' SET status = "approved", assigned_session = ?, reviewed_by = ?, reviewed_at = datetime("now")'
        ' WHERE id = ?',
        (assigned_session, session['user_id'], reg_id)
    )
    db.commit()

    log_action('approve_registration', 'pending_registrations', reg_id, {
        'new_member_id':  mid,
        'name':           f"{reg['first_name']} {reg['surname']}",
        'type':           rtype,
        'session':        assigned_session,
        'portal_user_id': portal_user_id,
        'approved_by':    session['username'],
    })
    return jsonify({
        'success':      True,
        'member_id':    mid,
        'user_created': portal_user_id is not None,
    })


# ── Reject ────────────────────────────────────────────────────────────────────

@bp.route('/api/approvals/<int:reg_id>/reject', methods=['POST'])
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
        'name':        f"{reg['first_name']} {reg['surname']}",
        'notes':       notes,
        'rejected_by': session['username'],
    })
    return jsonify({'success': True})
