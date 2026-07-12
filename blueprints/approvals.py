"""
AYC Portal — Approvals blueprint.
Routes: /api/approvals/*, /api/registration, /api/staff-roles
"""

import json

import bcrypt
from flask import Blueprint, jsonify, request, session

from helpers import (
    get_db, log_action, permission_required, has_permission,
    _assigned_session, _next_member_id, validate_password,
    get_valid_session_names, rate_limit_touch, client_ip, set_member_sessions,
)

bp = Blueprint('approvals', __name__)

# ── Rate limit for the public registration endpoint ────────────────────────────
# Max 5 submissions per IP per hour.  Backed by the rate_limits table so the
# limit is shared across all worker processes (see helpers.rate_limit_touch).
_REG_RATE_LIMIT   = 5          # max requests
_REG_RATE_WINDOW  = 3600       # per N seconds


def _registration_rate_limit(ip: str) -> bool:
    """Return True if the IP is within limit, False if it should be blocked."""
    allowed, _ = rate_limit_touch(f'register:{ip}', _REG_RATE_LIMIT, _REG_RATE_WINDOW)
    return allowed


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
    # Rate limit: 5 submissions per IP per hour.
    # v12.42: X-Forwarded-For handling centralised in helpers.client_ip(),
    # gated on TRUST_PROXY_HEADERS so the header can't be spoofed when the
    # app port is exposed directly.
    if not _registration_rate_limit(client_ip()):
        return jsonify({'error': 'Too many registration attempts. Please try again later.'}), 429

    data = request.get_json() or {}
    db   = get_db()

    # Determine member type and registration style.
    # Default to the club's primary active non-staff type rather than a hardcoded
    # 'member' slug — on clubs whose type was renamed (e.g. 'ara-members') the
    # literal 'member' resolves to nothing, producing an orphaned registration.
    default_mt = db.execute('''
        SELECT slug FROM member_types
        WHERE active = 1 AND registration_style != 'staff'
        ORDER BY sort_order LIMIT 1
    ''').fetchone()
    default_slug = default_mt['slug'] if default_mt else 'member'

    slug  = (data.get('member_type_slug') or data.get('registration_type') or default_slug).strip()
    mtype = db.execute(
        'SELECT * FROM member_types WHERE slug = ? AND active = 1', (slug,)
    ).fetchone()

    if mtype:
        style         = mtype['registration_style'] or 'member'
        type_slug_val = mtype['slug']
        rtype         = 'staff' if style == 'staff' else 'member'
    elif slug == 'staff':
        # Explicit staff registration with no active 'staff' type configured.
        rtype         = 'staff'
        style         = 'staff'
        type_slug_val = slug
    else:
        # Unknown slug — fall back to the club's primary type to avoid orphans.
        rtype         = 'member'
        style         = 'member'
        type_slug_val = default_slug

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
        if not scoped:
            rows = []
        else:
            placeholders = ','.join('?' * len(scoped))
            if status == 'all':
                rows = db.execute(
                    base_query +
                    f' WHERE (pr.assigned_session IN ({placeholders})'
                    ' OR pr.assigned_session IS NULL OR pr.assigned_session = "")'
                    ' ORDER BY pr.submitted_at DESC',
                    scoped
                ).fetchall()
            else:
                rows = db.execute(
                    base_query +
                    ' WHERE pr.status = ?'
                    f' AND (pr.assigned_session IN ({placeholders})'
                    ' OR pr.assigned_session IS NULL OR pr.assigned_session = "")'
                    ' ORDER BY pr.submitted_at DESC',
                    [status] + list(scoped)
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

    # v12.51 Phase B: approval can assign one or MORE sessions. New UI sends
    # sessions_assigned (list); legacy callers send session_assigned (string).
    raw_list = data.get('sessions_assigned')
    if isinstance(raw_list, list):
        assigned_sessions = [str(s).strip() for s in raw_list if str(s).strip()]
    else:
        single = (data.get('session_assigned') or '').strip()
        assigned_sessions = [single] if single else []
    # dedupe, preserve order
    assigned_sessions = list(dict.fromkeys(assigned_sessions))
    if not assigned_sessions:
        return jsonify({'error': 'At least one session must be assigned when approving'}), 400

    valid_sessions = get_valid_session_names()
    bad = [s for s in assigned_sessions if s not in valid_sessions]
    if bad:
        return jsonify({'error': f'Invalid session(s): {", ".join(bad)}'}), 400

    scoped = _assigned_session()  # None or list
    if scoped is not None and any(s not in (scoped or []) for s in assigned_sessions):
        return jsonify({'error': 'You can only approve registrations into your own sessions'}), 403

    # Echo value for legacy columns (members.session, pending_registrations.assigned_session)
    assigned_session = assigned_sessions[0]

    # Validate initial status (member registrations only; staff always Active)
    initial_status = (data.get('initial_status') or 'Active').strip()
    valid_statuses = [r['name'] for r in db.execute('SELECT name FROM member_statuses').fetchall()]
    if valid_statuses and initial_status not in valid_statuses:
        return jsonify({'error': f'Invalid member status: {initial_status}'}), 400
    if not valid_statuses:
        initial_status = 'Active'  # fallback if member_statuses table is empty

    rtype          = reg['registration_type'] or 'member'
    mid            = _next_member_id(db)
    portal_user_id = None

    if rtype == 'staff':
        # ── Staff/volunteer approval ──────────────────────────────
        staff_role = data.get('staff_role', reg['applicant_role'] or '').strip()
        if not staff_role:
            return jsonify({'error': 'Staff role is required'}), 400

        # v12.41: resolve the staff member-type slug instead of hardcoding 'staff' —
        # a club that renamed its staff type slug was getting orphaned staff members
        # (invisible to every registration_style join). Same class of bug as v12.34/35.
        staff_mt = db.execute(
            "SELECT slug FROM member_types WHERE active = 1 AND registration_style = 'staff' "
            "ORDER BY sort_order LIMIT 1"
        ).fetchone()
        staff_slug = staff_mt['slug'] if staff_mt else 'staff'

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
            staff_slug,
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
            # Resolve session_type_id for the first assigned session (active default)
            _st_row = db.execute(
                'SELECT id FROM session_types WHERE name = ?', (assigned_session,)
            ).fetchone()
            _st_id = _st_row['id'] if _st_row else None
            cur = db.execute(
                'INSERT INTO users (username, email, password_hash, role, role_id, active_session_id, active)'
                ' VALUES (?,?,?,?,?,?,1)',
                (username, reg['email'] or '', pw_hash, portal_role, role_row['id'], _st_id)
            )
            portal_user_id = cur.lastrowid
            # v12.51: grant the new login access to EVERY assigned session
            for _sname in assigned_sessions:
                _sr = db.execute('SELECT id FROM session_types WHERE name = ?', (_sname,)).fetchone()
                if _sr:
                    db.execute(
                        'INSERT OR IGNORE INTO user_sessions (user_id, session_type_id) VALUES (?,?)',
                        (portal_user_id, _sr['id'])
                    )
            log_action('create_user', 'users', portal_user_id, {
                'username': username, 'role': portal_role,
                'created_by': session.get('username'),
                'via': 'staff_approval',
            })

    else:
        # ── Standard member approval ──────────────────────────────
        # Use the member type slug from the registration — never hardcode 'member'
        member_type_slug = (reg['member_type_slug'] or 'member').strip()
        db.execute('''
            INSERT INTO members
                (member_id, first_name, surname, date_of_birth, address, postcode,
                 ethnicity_religion, medical_sen, gp_contact,
                 unattended_exit, gdpr_consent, mobile, email,
                 status, session, member_type, date_registered)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,date("now"))
        ''', (
            mid,
            reg['first_name'], reg['surname'], reg['date_of_birth'],
            reg['address'], reg['postcode'],
            reg['ethnicity_religion'], reg['medical_sen'], reg['gp_contact'],
            reg['unattended_exit'], reg['gdpr_consent'],
            reg['mobile'], reg['email'],
            initial_status,
            assigned_session,
            member_type_slug,
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

    # v12.51: junction rows for every assigned session (echo column already set
    # by the INSERT above; set_member_sessions re-sorts it consistently).
    set_member_sessions(member_db_id, assigned_sessions)

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
        'sessions':       assigned_sessions,   # v12.51: full multi-assignment
        'initial_status': initial_status,
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

    scoped = _assigned_session()  # None or list
    if scoped is not None:
        reg_session = reg['assigned_session'] or ''
        if reg_session and reg_session not in (scoped or []):
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
