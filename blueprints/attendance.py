"""
AYC Portal — Attendance blueprint.
Routes: /api/attendance/*, /api/display/*, /api/activities/*, /api/register/notes
"""

import time
from datetime import datetime

from flask import Blueprint, Response, jsonify, request, session, stream_with_context

import sqlcipher3 as sqlite3

from helpers import (
    get_db, log_action, login_required, permission_required, has_permission,
    _assigned_session, _is_register_locked, _touch_attendance,
    _fetch_tags_for_members, get_valid_session_names, get_setting,
    _invalidate_qr_token_for_session,
)

bp = Blueprint('attendance', __name__)


@bp.route('/api/attendance/<session_type>/<date>')
@login_required
def api_attendance_get(session_type, date):
    db     = get_db()
    scoped = _assigned_session()  # None or list
    if scoped is not None:
        if not scoped:
            return jsonify([])
        if session_type not in scoped:
            return jsonify({'error': 'Access denied for this session'}), 403

    rows = db.execute('''
        SELECT  m.*,
                a.id         AS att_id,
                a.signed_in_at,
                a.signed_out_at
        FROM    members m
        JOIN    member_types mt ON mt.slug = m.member_type
        LEFT JOIN attendance a
               ON  a.member_id   = m.id
               AND a.session_date = ?
               AND a.session_type = ?
        WHERE   EXISTS (SELECT 1 FROM member_statuses ms WHERE ms.name = m.status AND ms.behaviour = 'active')
          AND   mt.registration_style != "staff"
          AND   m.session      = ?
        ORDER   BY m.first_name, m.surname
    ''', (date, session_type, session_type)).fetchall()

    member_ids = [r['id'] for r in rows]
    tags_by_member = _fetch_tags_for_members(db, member_ids)

    custom_map = {}
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
            custom_map.setdefault(cfv['member_id'], {})[cfv['key']] = cfv['value']

    result = []
    for r in rows:
        d = dict(r)
        d['tags']          = tags_by_member.get(r['id'], [])
        d['custom_fields'] = custom_map.get(r['id'], {})
        result.append(d)
    return jsonify(result)


@bp.route('/api/attendance/staff/<session_type>/<date>')
@login_required
def api_attendance_staff_get(session_type, date):
    if session_type not in get_valid_session_names():
        return jsonify({'error': 'Invalid session'}), 400

    scoped = _assigned_session()
    if scoped is not None and session_type not in (scoped or []):
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
        WHERE   EXISTS (SELECT 1 FROM member_statuses ms WHERE ms.name = m.status AND ms.behaviour = 'active')
          AND   m.member_type  = "staff"
          AND   m.session      = ?
        ORDER   BY m.first_name, m.surname
    ''', (date, session_type, session_type)).fetchall()

    member_ids     = [r['id'] for r in rows]
    tags_by_member = _fetch_tags_for_members(db, member_ids)
    result = []
    for r in rows:
        d        = dict(r)
        d['tags'] = tags_by_member.get(r['id'], [])
        result.append(d)
    return jsonify(result)


@bp.route('/api/attendance/signin', methods=['POST'])
@permission_required('register.signin')
def api_attendance_signin():
    data      = request.get_json() or {}
    member_id = data.get('member_id')
    sess_type = data.get('session_type', '').strip()
    sess_date = data.get('date', '').strip()

    if not all([member_id, sess_type, sess_date]):
        return jsonify({'error': 'member_id, session_type and date are required'}), 400

    scoped = _assigned_session()
    if scoped is not None and sess_type not in (scoped or []):
        return jsonify({'error': 'Access denied for this session'}), 403

    if _is_register_locked(sess_type, sess_date):
        return jsonify({'error': 'This register has been completed and is now locked.'}), 403

    db       = get_db()
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

    # Auto-resolve attendance flags
    att_flags = db.execute(
        "SELECT mf.id FROM member_flags mf "
        "JOIN alert_rules ar ON ar.id = mf.rule_id "
        "WHERE mf.member_id = ? AND mf.resolved_at IS NULL "
        "AND ar.rule_type = 'attendance' AND ar.auto_resolve = 1",
        (member_id,)
    ).fetchall()
    for flag in att_flags:
        db.execute(
            "UPDATE member_flags SET resolved_at = datetime('now'), resolved_by = 'auto' WHERE id = ?",
            (flag['id'],)
        )
    if att_flags:
        member_row = db.execute('SELECT first_name, surname FROM members WHERE id = ?',
                                (member_id,)).fetchone()
        log_action('auto_resolve_flags', 'members', member_id, {
            'member': f"{member_row['first_name'] or ''} {member_row['surname'] or ''}".strip(),
            'reason': 'attended session — attendance alert flags auto-resolved',
            'count':  len(att_flags),
        })

    db.commit()
    _touch_attendance()
    return jsonify({'success': True, 'signed_in_at': now})


@bp.route('/api/attendance/signout', methods=['POST'])
@permission_required('register.signout')
def api_attendance_signout():
    data      = request.get_json() or {}
    member_id = data.get('member_id')
    sess_type = data.get('session_type', '').strip()
    sess_date = data.get('date', '').strip()
    clear     = data.get('clear', False)

    if not all([member_id, sess_type, sess_date]):
        return jsonify({'error': 'member_id, session_type and date are required'}), 400

    scoped = _assigned_session()
    if scoped is not None and sess_type not in (scoped or []):
        return jsonify({'error': 'Access denied for this session'}), 403

    if _is_register_locked(sess_type, sess_date):
        return jsonify({'error': 'This register has been completed and is now locked.'}), 403

    db        = get_db()
    out_value = None if clear else datetime.now().strftime('%H:%M')
    result    = db.execute(
        'UPDATE attendance SET signed_out_at = ?, recorded_by = ?'
        ' WHERE member_id = ? AND session_date = ? AND session_type = ?',
        (out_value, session['user_id'], member_id, sess_date, sess_type)
    )
    if result.rowcount == 0:
        return jsonify({'error': 'No sign-in record found — member may not be signed in yet'}), 404
    db.commit()
    _touch_attendance()
    return jsonify({'success': True, 'signed_out_at': out_value})


@bp.route('/api/attendance/complete/<session_type>/<date>')
@login_required
def api_attendance_complete_status(session_type, date):
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


@bp.route('/api/attendance/complete', methods=['POST'])
@permission_required('register.complete')
def api_attendance_complete():
    data      = request.get_json() or {}
    sess_type = data.get('session_type', '').strip()
    sess_date = data.get('date', '').strip()

    if not all([sess_type, sess_date]):
        return jsonify({'error': 'session_type and date are required'}), 400

    scoped = _assigned_session()
    if scoped is not None and sess_type not in (scoped or []):
        return jsonify({'error': 'You can only complete your own session register'}), 403

    db       = get_db()
    existing = db.execute(
        'SELECT id FROM session_completions WHERE session_date = ? AND session_type = ?',
        (sess_date, sess_type)
    ).fetchone()
    if existing:
        return jsonify({'error': 'This register has already been completed'}), 409

    now      = datetime.now().strftime('%H:%M')
    still_in = db.execute(
        '''SELECT id FROM attendance
           WHERE session_date = ? AND session_type = ?
             AND signed_in_at IS NOT NULL AND signed_out_at IS NULL''',
        (sess_date, sess_type)
    ).fetchall()
    auto_count = len(still_in)

    try:
        db.execute('BEGIN IMMEDIATE')
        if auto_count:
            db.execute(
                '''UPDATE attendance SET signed_out_at = ?, recorded_by = ?
                   WHERE session_date = ? AND session_type = ?
                     AND signed_in_at IS NOT NULL AND signed_out_at IS NULL''',
                (now, session['user_id'], sess_date, sess_type)
            )
        db.execute(
            '''INSERT INTO session_completions
                   (session_date, session_type, completed_by, completed_at, auto_signout_count)
               VALUES (?, ?, ?, datetime('now'), ?)''',
            (sess_date, sess_type, session['user_id'], auto_count)
        )
        db.execute('COMMIT')
    except sqlite3.IntegrityError:
        db.execute('ROLLBACK')
        return jsonify({'error': 'This register was already completed by another user'}), 409
    except Exception as exc:
        db.execute('ROLLBACK')
        return jsonify({'error': f'Could not complete register: {exc}'}), 500

    _touch_attendance()
    _invalidate_qr_token_for_session(sess_type, sess_date)

    totals = db.execute(
        '''SELECT
             COUNT(*) AS total,
             SUM(CASE WHEN signed_out_at IS NOT NULL THEN 1 ELSE 0 END) AS signed_out
           FROM attendance
           WHERE session_date = ? AND session_type = ?''',
        (sess_date, sess_type)
    ).fetchone()

    log_action('register_complete', 'session_completions', None, {
        'session_type':       sess_type,
        'session_date':       sess_date,
        'auto_signout_count': auto_count,
    })

    return jsonify({
        'success':           True,
        'auto_signout_count': auto_count,
        'total_members':     totals['total']      if totals else 0,
        'total_signed_out':  totals['signed_out'] if totals else 0,
    })


@bp.route('/api/attendance/reset', methods=['POST'])
@permission_required('register.reset')
def api_attendance_reset():
    data      = request.get_json() or {}
    sess_type = data.get('session_type', '').strip()
    sess_date = data.get('date', '').strip()

    if not all([sess_type, sess_date]):
        return jsonify({'error': 'session_type and date are required'}), 400

    db        = get_db()
    att_count = db.execute(
        'SELECT COUNT(*) AS n FROM attendance WHERE session_date = ? AND session_type = ?',
        (sess_date, sess_type)
    ).fetchone()['n']

    db.execute(
        'DELETE FROM attendance WHERE session_date = ? AND session_type = ?',
        (sess_date, sess_type)
    )
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

    return jsonify({'success': True, 'attendance_deleted': att_count})


@bp.route('/api/attendance/history/<int:member_id>')
@permission_required('members.view')
def api_attendance_history(member_id):
    db     = get_db()
    scoped = _assigned_session()  # None or list
    if scoped is not None:
        member = db.execute('SELECT session FROM members WHERE id = ?', (member_id,)).fetchone()
        if not member or (member['session'] or '') not in (scoped or []):
            return jsonify({'error': 'Forbidden'}), 403

    rows = db.execute(
        'SELECT session_date, session_type, signed_in_at, signed_out_at'
        ' FROM attendance WHERE member_id = ?'
        ' ORDER BY session_date DESC LIMIT 20',
        (member_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ── SSE display stream ─────────────────────────────────────────────────────────

@bp.route('/api/display/stream')
def api_display_stream():
    _SSE_MAX_SECONDS = 4 * 3600
    _SSE_HEARTBEAT_S = 30
    _SSE_POLL_S      = 1

    def generate():
        last     = None
        deadline = time.time() + _SSE_MAX_SECONDS
        last_hb  = time.time()
        while time.time() < deadline:
            if time.time() - last_hb >= _SSE_HEARTBEAT_S:
                yield ': heartbeat\n\n'
                last_hb = time.time()
            current = get_setting('last_attendance_change')
            if current != last:
                last = current
                yield 'data: refresh\n\n'
            time.sleep(_SSE_POLL_S)
        yield 'data: timeout\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@bp.route('/api/display/<session_type>')
def api_display(session_type):
    if session_type not in get_valid_session_names():
        return jsonify({'error': 'Invalid session'}), 400

    today = datetime.now().strftime('%Y-%m-%d')
    db    = get_db()

    rows = db.execute('''
        SELECT  m.first_name, m.surname,
                a.signed_in_at
        FROM    attendance a
        JOIN    members m ON m.id = a.member_id
        JOIN    member_types mt ON mt.slug = m.member_type
        WHERE   a.session_date  = ?
          AND   a.session_type  = ?
          AND   a.signed_in_at  IS NOT NULL
          AND   a.signed_out_at IS NULL
          AND   mt.registration_style != "staff"
        ORDER   BY a.signed_in_at ASC
    ''', (today, session_type)).fetchall()

    leader_rows = db.execute('''
        SELECT  m.first_name, m.surname, m.staff_role
        FROM    attendance a
        JOIN    members m ON m.id = a.member_id
        JOIN    member_types mt ON mt.slug = m.member_type
        WHERE   a.session_date  = ?
          AND   a.session_type  = ?
          AND   a.signed_in_at  IS NOT NULL
          AND   a.signed_out_at IS NULL
          AND   mt.registration_style = "staff"
        ORDER   BY a.signed_in_at ASC
    ''', (today, session_type)).fetchall()

    activity_rows = db.execute('''
        SELECT id, activity
        FROM   session_activities
        WHERE  session_type = ? AND active = 1
        ORDER  BY created_at ASC
    ''', (session_type,)).fetchall()

    return jsonify({
        'session':    session_type,
        'date':       today,
        'members':    [{'first_name': r['first_name'],
                        'signed_in_at': r['signed_in_at']} for r in rows],
        'leaders':    [{'name': r['first_name'] or '', 'role': r['staff_role'] or ''} for r in leader_rows],
        'activities': [{'id': r['id'], 'activity': r['activity']} for r in activity_rows],
    })


# ── Activities board ───────────────────────────────────────────────────────────

@bp.route('/api/activities/<session_type>', methods=['GET'])
@login_required
def api_activities_list(session_type):
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


@bp.route('/api/activities', methods=['POST'])
@permission_required('activities.manage')
def api_activity_add():
    data     = request.get_json() or {}
    sess     = data.get('session_type', '').strip()
    activity = data.get('activity', '').strip()
    if sess not in get_valid_session_names():
        return jsonify({'error': 'Invalid session'}), 400
    if not activity:
        return jsonify({'error': 'Activity text is required'}), 400
    if len(activity) > 120:
        return jsonify({'error': 'Activity text is too long (max 120 characters)'}), 400
    db  = get_db()
    cur = db.execute(
        'INSERT INTO session_activities (session_type, activity, added_by) VALUES (?,?,?)',
        (sess, activity, session.get('user_id'))
    )
    db.commit()
    return jsonify({'id': cur.lastrowid, 'activity': activity}), 201


@bp.route('/api/activities/<int:activity_id>', methods=['PUT'])
@permission_required('activities.manage')
def api_activity_update(activity_id):
    db  = get_db()
    row = db.execute('SELECT id FROM session_activities WHERE id = ? AND active = 1',
                     (activity_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Activity not found'}), 404
    data     = request.get_json() or {}
    activity = data.get('activity', '').strip()
    if not activity:
        return jsonify({'error': 'Activity text is required'}), 400
    if len(activity) > 120:
        return jsonify({'error': 'Activity text is too long (max 120 characters)'}), 400
    db.execute('UPDATE session_activities SET activity = ? WHERE id = ?', (activity, activity_id))
    db.commit()
    return jsonify({'id': activity_id, 'activity': activity})


@bp.route('/api/activities/<int:activity_id>', methods=['DELETE'])
@permission_required('activities.manage')
def api_activity_delete(activity_id):
    db = get_db()
    db.execute('UPDATE session_activities SET active = 0 WHERE id = ?', (activity_id,))
    db.commit()
    return jsonify({'ok': True})


# ── Session notes ──────────────────────────────────────────────────────────────

@bp.route('/api/register/notes/<session_type>/<date>')
@permission_required('register.notes')
def api_notes_get(session_type, date):
    db     = get_db()
    scoped = _assigned_session()
    if scoped is not None and session_type not in (scoped or []):
        return jsonify({'error': 'Access denied'}), 403

    rows = db.execute('''
        SELECT  sn.id, sn.note_type, sn.title, sn.details, sn.created_at,
                u.username   AS added_by_name,
                m.first_name AS member_first, m.surname AS member_surname
        FROM    session_notes sn
        LEFT JOIN users   u ON u.id = sn.added_by
        LEFT JOIN members m ON m.id = sn.member_id
        WHERE   sn.session_date = ? AND sn.session_type = ?
        ORDER   BY sn.created_at
    ''', (date, session_type)).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/register/notes', methods=['POST'])
@permission_required('register.notes')
def api_notes_create():
    data         = request.get_json() or {}
    session_type = data.get('session_type', '').strip()
    session_date = data.get('session_date', '').strip()
    note_type    = data.get('note_type', 'General').strip()
    title        = data.get('title', '').strip() or None
    details      = data.get('details', '').strip() or None
    member_id    = data.get('member_id') or None

    if not session_type or not session_date:
        return jsonify({'error': 'session_type and session_date are required'}), 400
    if not details and not title:
        return jsonify({'error': 'At least a title or details must be provided'}), 400

    scoped = _assigned_session()
    if scoped is not None and session_type not in (scoped or []):
        return jsonify({'error': 'Access denied for this session'}), 403

    db  = get_db()
    cur = db.execute(
        '''INSERT INTO session_notes
               (session_date, session_type, member_id, note_type, title, details, added_by)
           VALUES (?,?,?,?,?,?,?)''',
        (session_date, session_type, member_id, note_type, title, details, session['user_id'])
    )
    db.commit()

    log_action('note_added', 'session_notes', cur.lastrowid, {
        'session_type': session_type,
        'session_date': session_date,
        'note_type':    note_type,
    })

    row = db.execute('''
        SELECT  sn.*, u.username AS added_by_name,
                m.first_name AS member_first, m.surname AS member_surname
        FROM    session_notes sn
        LEFT JOIN users   u ON u.id = sn.added_by
        LEFT JOIN members m ON m.id = sn.member_id
        WHERE   sn.id = ?
    ''', (cur.lastrowid,)).fetchone()
    return jsonify(dict(row)), 201


@bp.route('/api/register/notes/<int:note_id>', methods=['DELETE'])
@permission_required('register.notes')
def api_notes_delete(note_id):
    db   = get_db()
    note = db.execute('SELECT * FROM session_notes WHERE id = ?', (note_id,)).fetchone()
    if not note:
        return jsonify({'error': 'Note not found'}), 404

    scoped = _assigned_session()  # None or list
    if scoped is not None and note['session_type'] not in (scoped or []):
        return jsonify({'error': 'Access denied'}), 403

    # Users can only delete their own notes (admin can delete any)
    if session.get('role') != 'admin' and note['added_by'] != session['user_id']:
        return jsonify({'error': 'You can only delete your own notes'}), 403

    db.execute('DELETE FROM session_notes WHERE id = ?', (note_id,))
    db.commit()
    log_action('note_deleted', 'session_notes', note_id, {
        'session_type': note['session_type'],
        'session_date': note['session_date'],
    })
    return jsonify({'success': True})
