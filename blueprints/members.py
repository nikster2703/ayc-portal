"""
AYC Portal — Members blueprint.
Routes: /api/members/*, /api/field-config, /api/public/field-config/*, /api/public/session-types,
        /api/postcode/*, /api/dashboard
"""

import json

from flask import Blueprint, current_app, jsonify, request, session

from helpers import (
    get_db, log_action, permission_required,
    _assigned_session, get_session_types, rate_limit_touch, client_ip,
    get_member_session_names, get_sessions_for_members, set_member_sessions,
    member_in_scope,
)
from config import GETADDRESS_KEY

import urllib.request
import urllib.error
import urllib.parse

bp = Blueprint('members', __name__)


@bp.route('/api/members')
@permission_required('members.view')
def api_members():
    from helpers import get_setting
    db = get_db()

    status_filter  = request.args.get('status', 'active')
    session_filter = request.args.get('session', 'all')
    flag_filter    = request.args.get('flag_rule_id')
    paid_filter    = request.args.get('paid', '')   # '1' = paid, '0' = unpaid, '' = all

    # Current membership period for paid_current calculation
    current_period = get_setting('current_membership_period', '')

    conditions = ['1=1']
    params     = []

    if status_filter == 'all':
        pass  # no status restriction
    elif status_filter in ('active', 'inactive', 'leaver'):
        # behaviour-based filter — works regardless of what the status name is called
        conditions.append(
            "EXISTS (SELECT 1 FROM member_statuses ms "
            "WHERE ms.name = m.status AND ms.behaviour = ?)"
        )
        params.append(status_filter)
    elif status_filter not in ('flagged',):
        # exact status name (for future custom statuses passed by name)
        conditions.append('m.status = ?')
        params.append(status_filter)

    # v12.50 Phase A: session filter + scope run against the member_sessions
    # junction table — a member assigned to N sessions matches any of them.
    _MS_EXISTS = ('EXISTS (SELECT 1 FROM member_sessions ms_f '
                  'JOIN session_types st_f ON st_f.id = ms_f.session_type_id '
                  'WHERE ms_f.member_id = m.id AND st_f.name IN ({ph}))')

    if session_filter != 'all':
        conditions.append(_MS_EXISTS.format(ph='?'))
        params.append(session_filter)

    scoped = _assigned_session()  # None (admin) or list of session names
    if scoped is not None:
        if not scoped:
            return jsonify([])
        conditions.append(_MS_EXISTS.format(ph=','.join('?' * len(scoped))))
        params.extend(scoped)

    # v12.53: the paid filter is applied in Python after per-session coverage
    # is computed (see below) — SQL no longer joins a paid subquery.

    # v12.42: rule_id is now a bound parameter (was interpolated — safe since it
    # was int()-cast, but parameterised for consistency with everything else).
    flag_join, flag_params = '', []
    if status_filter == 'flagged' or flag_filter:
        flag_join = 'INNER JOIN member_flags mf ON mf.member_id = m.id AND mf.resolved_at IS NULL'
        if flag_filter:
            try:
                rule_id_int = int(flag_filter)
            except (ValueError, TypeError):
                rule_id_int = None
            if rule_id_int:
                flag_join = ('INNER JOIN member_flags mf ON mf.member_id = m.id '
                             'AND mf.rule_id = ? AND mf.resolved_at IS NULL')
                flag_params = [rule_id_int]

    where = ' AND '.join(conditions)

    rows = db.execute(f'''
        SELECT  DISTINCT m.*,
                mt.registration_style,
                c1.contact_name  AS contact1_name,
                c1.contact_phone AS contact1_phone,
                c1.contact_email AS contact1_email,
                c2.contact_name  AS contact2_name,
                c2.contact_phone AS contact2_phone,
                c2.contact_email AS contact2_email
        FROM    members m
        LEFT JOIN member_types mt ON mt.slug = m.member_type
        {flag_join}
        LEFT JOIN member_contacts c1
               ON c1.member_id = m.id AND c1.contact_order = 1
        LEFT JOIN member_contacts c2
               ON c2.member_id = m.id AND c2.contact_order = 2
        WHERE   {where}
        ORDER   BY m.first_name, m.surname
    ''', flag_params + params).fetchall()

    member_ids        = [r['id'] for r in rows]
    custom_fields_map = {}
    flags_map         = {}
    sessions_map      = get_sessions_for_members(member_ids)   # v12.50: N sessions per member

    # v12.53: per-session paid coverage for the current period. One batch query;
    # a NULL session_type_id payment (whole club) covers all assigned sessions.
    whole_club_paid = set()      # member_ids with a whole-club current payment
    session_paid    = {}         # member_id -> {covered session names}
    if member_ids and current_period:
        _ph = ','.join('?' * len(member_ids))
        for pr in db.execute(f'''
            SELECT mp.member_id, mp.session_type_id, st.name AS session_name
            FROM   member_payments mp
            JOIN   payment_types pt ON pt.id = mp.payment_type_id
            LEFT JOIN session_types st ON st.id = mp.session_type_id
            WHERE  pt.is_membership = 1 AND mp.period = ? AND mp.voided_at IS NULL
              AND  mp.member_id IN ({_ph})
        ''', [current_period] + member_ids).fetchall():
            if pr['session_type_id'] is None:
                whole_club_paid.add(pr['member_id'])
            elif pr['session_name']:
                session_paid.setdefault(pr['member_id'], set()).add(pr['session_name'])

    if member_ids:
        placeholders = ','.join('?' * len(member_ids))
        cfv_rows = db.execute(
            f'SELECT mfv.member_id, fd.key, mfv.value '
            f'FROM member_field_values mfv '
            f'JOIN field_definitions fd ON fd.id = mfv.field_id '
            f'WHERE mfv.member_id IN ({placeholders})',
            member_ids
        ).fetchall()
        for cfv in cfv_rows:
            custom_fields_map.setdefault(cfv['member_id'], {})[cfv['key']] = cfv['value']

        flag_rows = db.execute(
            f'SELECT mf.member_id, mf.id AS flag_id, mf.flagged_at, '
            f'ar.id AS rule_id, ar.flag_label, ar.flag_colour '
            f'FROM member_flags mf '
            f'JOIN alert_rules ar ON ar.id = mf.rule_id '
            f'WHERE mf.member_id IN ({placeholders}) AND mf.resolved_at IS NULL',
            member_ids
        ).fetchall()
        for f in flag_rows:
            flags_map.setdefault(f['member_id'], []).append({
                'flag_id':    f['flag_id'],
                'rule_id':    f['rule_id'],
                'flag_label': f['flag_label'],
                'flag_colour': f['flag_colour'],
                'flagged_at': f['flagged_at'],
            })

    result = []
    for r in rows:
        d = dict(r)
        d['custom_fields'] = custom_fields_map.get(r['id'], {})
        d['flags']         = flags_map.get(r['id'], [])
        # v12.50: authoritative session list; falls back to the echo column so a
        # member missed by the reconcile still renders somewhere sensible.
        d['sessions']      = sessions_map.get(r['id']) or ([d['session']] if d.get('session') else [])
        # v12.53: paid_sessions = sessions covered this period; paid_current =
        # fully covered (whole-club payment, or every assigned session covered).
        if r['id'] in whole_club_paid:
            d['paid_sessions'] = list(d['sessions'])
            d['paid_current']  = 1
        else:
            covered = session_paid.get(r['id'], set())
            d['paid_sessions'] = [s for s in d['sessions'] if s in covered]
            d['paid_current']  = 1 if (d['sessions'] and len(d['paid_sessions']) == len(d['sessions'])) else 0
        result.append(d)

    # v12.53: paid filter applied post-coverage ('1' = fully paid; '0' = not
    # fully paid, staff excluded — same semantics as the old SQL filter).
    if paid_filter == '1':
        result = [d for d in result if d['paid_current'] == 1]
    elif paid_filter == '0':
        result = [d for d in result
                  if d['paid_current'] != 1 and (d.get('registration_style') or '') != 'staff']

    return jsonify(result)


@bp.route('/api/members/<int:member_id>')
@permission_required('members.view')
def api_member_detail(member_id):
    db     = get_db()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Not found'}), 404

    if not member_in_scope(member_id):   # v12.50: any-session intersection
        return jsonify({'error': 'Forbidden'}), 403

    contacts           = db.execute(
        'SELECT * FROM member_contacts WHERE member_id = ? ORDER BY contact_order',
        (member_id,)
    ).fetchall()
    result             = dict(member)
    result['contacts'] = [dict(c) for c in contacts]
    result['sessions'] = get_member_session_names(member_id)
    return jsonify(result)


@bp.route('/api/members/<int:member_id>/viewed', methods=['POST'])
@permission_required('members.view')
def api_member_viewed(member_id):
    db     = get_db()
    member = db.execute(
        'SELECT first_name, surname, session FROM members WHERE id = ?', (member_id,)
    ).fetchone()
    if not member:
        return jsonify({'error': 'Not found'}), 404

    if not member_in_scope(member_id):   # v12.50: any-session intersection
        return jsonify({'error': 'Forbidden'}), 403

    log_action('view_member', 'members', member_id, {
        'member':    f"{member['first_name'] or ''} {member['surname'] or ''}".strip(),
        'viewed_by': session['username'],
    })
    return jsonify({'ok': True})


@bp.route('/api/field-config')
@permission_required('members.view')
def api_field_config():
    db    = get_db()
    types = db.execute(
        'SELECT * FROM member_types WHERE active = 1 ORDER BY sort_order'
    ).fetchall()

    result = {}
    for mtype in types:
        rows = db.execute('''
            SELECT  fd.id, fd.key, fd.label, fd.field_type,
                    fd.column_name, fd.system_field,
                    fd.placeholder, fd.help_text, fd.options, fd.use_lookup,
                    mtf.required,
                    mtf.show_on_registration, mtf.show_on_list,
                    mtf.show_on_attendance, mtf.show_on_card,
                    mtf.show_on_print, mtf.show_on_export,
                    mtf.sort_order
            FROM    member_type_fields mtf
            JOIN    field_definitions fd ON fd.id = mtf.field_id
            WHERE   mtf.member_type_id = ? AND fd.active = 1
            ORDER   BY mtf.sort_order
        ''', (mtype['id'],)).fetchall()

        all_fields = [dict(r) for r in rows]
        result[mtype['slug']] = {
            'type':         dict(mtype),
            'all':          all_fields,
            'list':         [f for f in all_fields if f['show_on_list']],
            'attendance':   [f for f in all_fields if f['show_on_attendance']],
            'card':         [f for f in all_fields if f['show_on_card']],
            'print':        [f for f in all_fields if f['show_on_print']],
            'export':       [f for f in all_fields if f['show_on_export']],
            'registration': [f for f in all_fields if f['show_on_registration']],
        }
    return jsonify(result)


@bp.route('/api/public/field-config/<slug>')
def api_public_field_config(slug):
    db    = get_db()
    mtype = db.execute(
        'SELECT * FROM member_types WHERE slug = ? AND active = 1', (slug,)
    ).fetchone()
    if not mtype:
        return jsonify({'error': 'Not found'}), 404

    rows = db.execute('''
        SELECT  fd.id, fd.key, fd.label, fd.field_type,
                fd.column_name, fd.system_field,
                fd.placeholder, fd.help_text, fd.options, fd.use_lookup,
                mtf.required, mtf.sort_order
        FROM    member_type_fields mtf
        JOIN    field_definitions fd ON fd.id = mtf.field_id
        WHERE   mtf.member_type_id = ? AND fd.active = 1
          AND   mtf.show_on_registration = 1
        ORDER   BY mtf.sort_order
    ''', (mtype['id'],)).fetchall()

    return jsonify({'type': dict(mtype), 'fields': [dict(r) for r in rows]})


@bp.route('/api/public/session-types')
def api_public_session_types():
    return jsonify(get_session_types())


@bp.route('/api/members/<int:member_id>', methods=['PUT'])
@permission_required('members.edit')
def api_member_update(member_id):
    data   = request.get_json() or {}
    db     = get_db()
    before = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not before:
        return jsonify({'error': 'Not found'}), 404

    if not member_in_scope(member_id):   # v12.50: any-session intersection
        return jsonify({'error': 'Forbidden'}), 403

    # v12.50: 'session' removed from text_fields — session assignment now goes
    # through set_member_sessions() below (junction table + echo column).
    text_fields = ['first_name', 'surname', 'date_of_birth', 'address', 'postcode',
                   'ethnicity_religion', 'medical_sen', 'gp_contact',
                   'comments', 'date_registered', 'staff_role']
    # NOTE: status is intentionally excluded — use POST /api/members/<id>/status
    bool_fields = ['unattended_exit', 'gdpr_consent']

    updates, params = [], []
    changes = {}

    # v12.50 Phase A: multi-session assignment. Accepts 'sessions' (list) from
    # the new UI, or legacy 'session' (single string) from any older caller.
    if 'sessions' in data or 'session' in data:
        wanted = data['sessions'] if 'sessions' in data else (
            [data['session']] if (data.get('session') or '').strip() else []
        )
        if not isinstance(wanted, list):
            return jsonify({'error': 'sessions must be a list of session names'}), 400
        old_sessions = get_member_session_names(member_id)
        new_sessions = set_member_sessions(member_id, wanted)
        if old_sessions != new_sessions:
            changes['sessions'] = {'from': old_sessions, 'to': new_sessions}
        # Scoped users must not edit themselves out of reach accidentally —
        # they may only save a session set that still intersects their scope
        # (or an empty set, which admins can later reassign).
        scoped = _assigned_session()
        if scoped is not None and new_sessions and not (set(new_sessions) & set(scoped)):
            db.rollback()
            return jsonify({'error': 'You cannot remove a member from all of your sessions'}), 400

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

    if 'custom_fields' in data:
        for cf_key, cf_val in (data['custom_fields'] or {}).items():
            cf_fd = db.execute(
                'SELECT id FROM field_definitions WHERE key = ?', (cf_key,)
            ).fetchone()
            if not cf_fd:
                continue
            if cf_val is None or cf_val == '':
                db.execute(
                    'DELETE FROM member_field_values WHERE member_id = ? AND field_id = ?',
                    (member_id, cf_fd['id'])
                )
            else:
                db.execute(
                    'INSERT OR REPLACE INTO member_field_values (member_id, field_id, value) VALUES (?,?,?)',
                    (member_id, cf_fd['id'], str(cf_val))
                )

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
        'member':  f"{before['first_name'] or ''} {before['surname'] or ''}".strip(),
        'editor':  session['username'],
        'changes': changes,
    })
    return jsonify({'success': True})


@bp.route('/api/member-statuses')
@permission_required('members.view')
def api_member_statuses():
    """Return all configured member statuses, ordered for UI display."""
    db   = get_db()
    rows = db.execute(
        'SELECT * FROM member_statuses ORDER BY sort_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/members/<int:member_id>/status', methods=['POST'])
@permission_required('members.edit')
def api_member_status_change(member_id):
    """Change a member's status. Requires a mandatory reason.
    Auto-resolves all open alert flags when transitioning to inactive or leaver behaviour."""
    data       = request.get_json() or {}
    new_status = (data.get('status') or '').strip()
    reason     = (data.get('reason') or '').strip()

    if not new_status:
        return jsonify({'error': 'status is required'}), 400
    if not reason:
        return jsonify({'error': 'A reason is required for all status changes'}), 400

    db = get_db()

    # Validate against the member_statuses table
    status_row = db.execute(
        'SELECT id, behaviour FROM member_statuses WHERE name = ?', (new_status,)
    ).fetchone()
    if not status_row:
        return jsonify({'error': f'"{new_status}" is not a valid status'}), 400

    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Not found'}), 404

    if not member_in_scope(member_id):   # v12.50: any-session intersection
        return jsonify({'error': 'Forbidden'}), 403

    old_status    = member['status']
    new_behaviour = status_row['behaviour']

    if old_status == new_status:
        return jsonify({'error': f'Member already has status "{new_status}"'}), 400

    db.execute(
        "UPDATE members SET status = ?, status_note = ?, "
        "updated_at = datetime('now'), updated_by = ? WHERE id = ?",
        (new_status, reason, session['user_id'], member_id)
    )

    # Auto-resolve all open flags when moving to inactive or leaver behaviour
    resolved_flags = 0
    if new_behaviour in ('inactive', 'leaver'):
        open_flags = db.execute(
            'SELECT id FROM member_flags WHERE member_id = ? AND resolved_at IS NULL',
            (member_id,)
        ).fetchall()
        for flag in open_flags:
            db.execute(
                "UPDATE member_flags SET resolved_at = datetime('now'), resolved_by = ? "
                "WHERE id = ?",
                (f'status_change:{session["username"]}', flag['id'])
            )
        resolved_flags = len(open_flags)

    db.commit()

    full_name = f"{member['first_name'] or ''} {member['surname'] or ''}".strip()
    log_action('status_change', 'members', member_id, {
        'member':         full_name,
        'from':           old_status,
        'to':             new_status,
        'reason':         reason,
        'by':             session['username'],
        'flags_resolved': resolved_flags,
    })
    return jsonify({'success': True, 'flags_resolved': resolved_flags})


@bp.route('/api/members/<int:member_id>/permanent', methods=['DELETE'])
@permission_required('members.hard_delete')
def api_member_permanent_delete(member_id):
    data  = request.get_json() or {}
    token = data.get('confirm_name', '').strip()

    db     = get_db()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Member not found'}), 404

    # v12.42: session-scope check for consistency with every other member
    # endpoint (hard_delete is admin-only by default, but a custom role could
    # grant it to a scoped user). v12.50: any-session intersection.
    if not member_in_scope(member_id):
        return jsonify({'error': 'Forbidden'}), 403

    expected = f"{member['first_name']} {member['surname']}"
    if token.lower() != expected.lower():
        return jsonify({'error': 'Confirmation name does not match — deletion cancelled'}), 400

    att_count = db.execute(
        'SELECT COUNT(*) AS n FROM attendance WHERE member_id = ?', (member_id,)
    ).fetchone()['n']
    dofe_count = db.execute(
        'SELECT COUNT(*) AS n FROM dofe_participants WHERE member_id = ?', (member_id,)
    ).fetchone()['n']
    contact_count = db.execute(
        'SELECT COUNT(*) AS n FROM member_contacts WHERE member_id = ?', (member_id,)
    ).fetchone()['n']

    try:
        db.execute('BEGIN')
        db.execute('DELETE FROM attendance WHERE member_id = ?', (member_id,))
        db.execute('DELETE FROM dofe_participants WHERE member_id = ?', (member_id,))
        db.execute('DELETE FROM member_contacts WHERE member_id = ?', (member_id,))
        db.execute(
            "UPDATE pending_registrations SET notes = COALESCE(notes || ' ', '') || '[Member record permanently deleted]'"
            " WHERE id IN ("
            "  SELECT id FROM pending_registrations WHERE status = 'approved'"
            "  AND first_name = ? AND surname = ?"
            ")",
            (member['first_name'], member['surname'])
        )
        db.execute(
            'INSERT INTO audit_log (user_id, action, table_name, record_id, details, ip_address)'
            ' VALUES (?,?,?,?,?,?)',
            (
                session.get('user_id'),
                'permanent_delete_member',
                'members',
                member_id,
                json.dumps({
                    'member':           expected,
                    'member_id':        member['member_id'],
                    'session':          member['session'],
                    'deleted_by':       session.get('username'),
                    'att_deleted':      att_count,
                    'dofe_deleted':     dofe_count,
                    'contacts_deleted': contact_count,
                }),
                request.remote_addr,
            )
        )
        db.execute('DELETE FROM members WHERE id = ?', (member_id,))
        db.execute('COMMIT')
    except Exception as e:
        db.execute('ROLLBACK')
        current_app.logger.error(f'Permanent member delete failed (member_id={member_id}): {e}')
        return jsonify({'error': 'Deletion failed and was rolled back. Check server logs for details.'}), 500

    return jsonify({
        'success': True,
        'deleted': expected,
        'summary': {
            'attendance': att_count,
            'contacts':   contact_count,
            'dofe':       dofe_count,
        }
    })


@bp.route('/api/postcode/<path:postcode>')
def api_postcode_lookup(postcode):
    """Proxy getaddress.io lookups server-side to avoid browser CORS restrictions.

    Public (the registration form uses it pre-auth) but rate-limited per IP
    (v12.41) — previously anyone who found the URL could drain the paid
    getaddress.io lookup quota.
    """
    if not GETADDRESS_KEY:
        return jsonify({'error': 'Address lookup not configured on this server'}), 503

    allowed, _retry = rate_limit_touch(f'postcode:{client_ip()}', 20, 60)   # 20 lookups/min/IP
    if not allowed:
        return jsonify({'error': 'Too many address lookups — please slow down and try again shortly.'}), 429

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
        current_app.logger.error(f'Postcode lookup network error ({postcode}): {e}')
        return jsonify({'error': 'Address lookup failed — please enter your address manually.'}), 502


# ── Member tags ────────────────────────────────────────────────────────────────

@bp.route('/api/members/<int:member_id>/activity')
@permission_required('members.view')
def api_member_activity(member_id):
    """Return audit log entries for a specific member, excluding noisy view events."""
    db     = get_db()
    member = db.execute('SELECT id FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Not found'}), 404
    if not member_in_scope(member_id):   # v12.50: any-session intersection
        return jsonify({'error': 'Forbidden'}), 403

    rows = db.execute('''
        SELECT  al.id, al.action, al.details, al.timestamp,
                u.username AS performed_by
        FROM    audit_log al
        LEFT JOIN users u ON u.id = al.user_id
        WHERE   al.table_name = 'members'
          AND   al.record_id  = ?
          AND   al.action    != 'view_member'
        ORDER   BY al.timestamp DESC
        LIMIT   100
    ''', (member_id,)).fetchall()

    return jsonify([dict(r) for r in rows])


@bp.route('/api/members/<int:member_id>/tags')
@permission_required('members.view')
def api_member_tags_get(member_id):
    db = get_db()

    # v12.42: session-scope check — this was the only member read endpoint
    # without one, letting scoped users read tags for out-of-session members.
    # v12.50: any-session intersection.
    if not member_in_scope(member_id):
        return jsonify({'error': 'Forbidden'}), 403

    rows = db.execute('''
        SELECT  mt.id AS assignment_id, td.id, td.name, td.icon, td.colour, td.category,
                mt.expires_at, mt.notes, mt.created_at
        FROM    member_tags mt
        JOIN    tag_definitions td ON td.id = mt.tag_id
        WHERE   mt.member_id = ? AND td.active = 1
        ORDER   BY td.sort_order, td.name
    ''', (member_id,)).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/members/<int:member_id>/tags', methods=['POST'])
@permission_required('members.tags')
def api_member_tags_add(member_id):
    data    = request.get_json() or {}
    tag_id  = data.get('tag_id')
    expires = data.get('expires_at') or None
    notes   = data.get('notes', '') or None

    if not tag_id:
        return jsonify({'error': 'tag_id is required'}), 400

    db  = get_db()
    tag = db.execute(
        'SELECT id, name FROM tag_definitions WHERE id = ? AND active = 1', (tag_id,)
    ).fetchone()
    if not tag:
        return jsonify({'error': 'Tag not found'}), 404

    member = db.execute('SELECT first_name, surname FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Member not found'}), 404

    try:
        db.execute(
            'INSERT OR IGNORE INTO member_tags (member_id, tag_id, expires_at, notes) VALUES (?,?,?,?)',
            (member_id, tag_id, expires, notes)
        )
        db.commit()
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    log_action('tag_add', 'member_tags', member_id, {
        'tag':    tag['name'],
        'member': f"{member['first_name']} {member['surname']}",
    })
    return jsonify({'success': True})


@bp.route('/api/members/<int:member_id>/tags/<int:tag_id>', methods=['DELETE'])
@permission_required('members.tags')
def api_member_tags_remove(member_id, tag_id):
    db = get_db()
    existing = db.execute(
        'SELECT id FROM member_tags WHERE member_id = ? AND tag_id = ?',
        (member_id, tag_id)
    ).fetchone()
    if not existing:
        return jsonify({'error': 'Tag assignment not found'}), 404

    member = db.execute('SELECT first_name, surname FROM members WHERE id = ?', (member_id,)).fetchone()
    tag    = db.execute('SELECT name FROM tag_definitions WHERE id = ?', (tag_id,)).fetchone()

    db.execute('DELETE FROM member_tags WHERE member_id = ? AND tag_id = ?', (member_id, tag_id))
    db.commit()
    log_action('tag_remove', 'member_tags', member_id, {
        'tag':    tag['name'] if tag else tag_id,
        'member': f"{member['first_name']} {member['surname']}" if member else member_id,
    })
    return jsonify({'success': True})
