"""
AYC Portal — Calendar blueprint.
Routes: /api/calendar/*, /api/session-types
"""

import sqlcipher3 as sqlite3
from datetime import date as dt_date, timedelta as dt_timedelta

from flask import Blueprint, jsonify, request, session

from helpers import (
    get_db, log_action, login_required, permission_required,
    _assigned_session, get_session_types, get_valid_session_names,
    session_to_weekday_map,
)

bp = Blueprint('calendar', __name__)

VALID_STATUSES = ('planned', 'cancelled', 'extra')


# ── Session types list (authenticated read) ───────────────────────────────────

@bp.route('/api/session-types')
@login_required
def api_session_types_list():
    return jsonify(get_session_types())


# ── Session types admin CRUD ──────────────────────────────────────────────────

@bp.route('/api/admin/session-types', methods=['GET'])
@permission_required('admin.session_types')
def api_admin_session_types_get():
    db   = get_db()
    rows = db.execute(
        'SELECT id, name, weekday, active, sort_order FROM session_types ORDER BY sort_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/session-types', methods=['POST'])
@permission_required('admin.session_types')
def api_admin_session_types_create():
    data    = request.get_json() or {}
    name    = data.get('name', '').strip()
    weekday = data.get('weekday')

    description = (data.get('description') or '').strip() or None

    if not name:
        return jsonify({'error': 'name is required'}), 400
    # weekday is now optional (Phase A) — validate only if supplied
    if weekday is not None and (not isinstance(weekday, int) or weekday < 0 or weekday > 6):
        return jsonify({'error': 'weekday must be an integer 0–6 (Mon=0), or omit for no fixed day'}), 400

    db        = get_db()
    max_order = db.execute('SELECT COALESCE(MAX(sort_order), -1) FROM session_types').fetchone()[0]
    try:
        cur = db.execute(
            'INSERT INTO session_types (name, weekday, description, active, sort_order) VALUES (?,?,?,1,?)',
            (name, weekday, description, max_order + 1)
        )
        db.commit()
        log_action('create_session_type', 'session_types', cur.lastrowid,
                   {'name': name, 'weekday': weekday, 'description': description})
        row = db.execute('SELECT * FROM session_types WHERE id = ?', (cur.lastrowid,)).fetchone()
        return jsonify(dict(row)), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A session type named "{name}" already exists'}), 409


@bp.route('/api/admin/session-types/<int:st_id>', methods=['PUT'])
@permission_required('admin.session_types')
def api_admin_session_types_update(st_id):
    data    = request.get_json() or {}
    db      = get_db()
    current = db.execute('SELECT * FROM session_types WHERE id = ?', (st_id,)).fetchone()
    if not current:
        return jsonify({'error': 'Session type not found'}), 404

    name        = data.get('name', current['name']).strip()
    description = (data.get('description') if 'description' in data else (current['description'] or ''))
    description = (description or '').strip() or None
    active      = int(data.get('active', current['active']))
    # weekday: None means "clear it"; omitting the key means "keep existing"
    if 'weekday' in data:
        weekday = data['weekday']  # may be None (to clear) or int
    else:
        weekday = current['weekday']

    if not name:
        return jsonify({'error': 'name is required'}), 400
    if weekday is not None and (not isinstance(weekday, int) or weekday < 0 or weekday > 6):
        return jsonify({'error': 'weekday must be an integer 0–6, or null to remove'}), 400

    if not active:
        active_count = db.execute(
            'SELECT COUNT(*) FROM session_types WHERE active = 1 AND id != ?', (st_id,)
        ).fetchone()[0]
        if active_count == 0:
            return jsonify({'error': 'Cannot deactivate the only active session type'}), 400

    old_name = current['name']
    try:
        db.execute(
            'UPDATE session_types SET name = ?, weekday = ?, description = ?, active = ? WHERE id = ?',
            (name, weekday, description, active, st_id)
        )
        # Cascade the name change to every table that stores session name as text
        if name != old_name:
            db.execute('UPDATE members              SET session      = ? WHERE session      = ?', (name, old_name))
            db.execute('UPDATE attendance           SET session_type = ? WHERE session_type = ?', (name, old_name))
            db.execute('UPDATE session_completions  SET session_type = ? WHERE session_type = ?', (name, old_name))
            db.execute('UPDATE term_sessions        SET session_type = ? WHERE session_type = ?', (name, old_name))
            db.execute('UPDATE session_activities   SET session_type = ? WHERE session_type = ?', (name, old_name))
        db.commit()
        log_action('update_session_type', 'session_types', st_id,
                   {'name': name, 'old_name': old_name, 'weekday': weekday,
                    'description': description, 'active': active})
        return jsonify(dict(db.execute('SELECT * FROM session_types WHERE id = ?', (st_id,)).fetchone()))
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A session type named "{name}" already exists'}), 409


@bp.route('/api/admin/session-types/<int:st_id>', methods=['DELETE'])
@permission_required('admin.session_types')
def api_admin_session_types_delete(st_id):
    db  = get_db()
    row = db.execute('SELECT * FROM session_types WHERE id = ?', (st_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Session type not found'}), 404

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

    # Block deletion if any user would be left with no sessions at all.
    # (user_sessions rows for this type will be cascade-deleted, so we check
    # for users whose ONLY session_type_id entry is this one.)
    stranded = db.execute(
        '''SELECT COUNT(*) FROM users u
           WHERE EXISTS (
               SELECT 1 FROM user_sessions us WHERE us.user_id = u.id AND us.session_type_id = ?
           )
           AND (
               SELECT COUNT(*) FROM user_sessions us2 WHERE us2.user_id = u.id
           ) = 1''',
        (st_id,)
    ).fetchone()[0]
    if stranded:
        return jsonify({
            'error': f'Cannot delete — {stranded} user(s) would be left with no session access. '
                     f'Reassign them first.'
        }), 400

    # NULL out active_session_id for any users pointing at this session type.
    # The user_sessions rows are handled by ON DELETE CASCADE on the junction table.
    db.execute(
        'UPDATE users SET active_session_id = NULL WHERE active_session_id = ?', (st_id,)
    )
    db.execute('DELETE FROM session_types WHERE id = ?', (st_id,))
    db.commit()
    log_action('delete_session_type', 'session_types', st_id, {'name': row['name']})
    return jsonify({'success': True})


@bp.route('/api/admin/session-types/reorder', methods=['POST'])
@permission_required('admin.session_types')
def api_admin_session_types_reorder():
    items = request.get_json() or []
    db    = get_db()
    for item in items:
        db.execute(
            'UPDATE session_types SET sort_order = ? WHERE id = ?',
            (item.get('sort_order', 0), item.get('id'))
        )
    db.commit()
    return jsonify({'success': True})


# ── Calendar (term sessions) ──────────────────────────────────────────────────

@bp.route('/api/calendar', methods=['GET'])
@login_required
def api_calendar_list():
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


@bp.route('/api/calendar/terms', methods=['GET'])
@login_required
def api_calendar_terms():
    db   = get_db()
    rows = db.execute(
        "SELECT DISTINCT term_name FROM term_sessions WHERE term_name IS NOT NULL ORDER BY term_name"
    ).fetchall()
    return jsonify([r['term_name'] for r in rows])


@bp.route('/api/calendar', methods=['POST'])
@permission_required('calendar.create')
def api_calendar_add():
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

    scoped = _assigned_session()  # None or list
    if scoped is not None and session_type not in (scoped or []):
        return jsonify({'error': 'You can only add sessions you have access to'}), 403
    if status not in VALID_STATUSES:
        return jsonify({'error': 'Invalid status'}), 400

    try:
        d            = dt_date.fromisoformat(session_date)
        wday_map     = session_to_weekday_map()
        expected_day = wday_map.get(session_type)
        # Only validate weekday if this session type has one configured
        if expected_day is not None and d.weekday() != expected_day:
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


@bp.route('/api/calendar/bulk', methods=['POST'])
@permission_required('calendar.create')
def api_calendar_bulk():
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

    scoped = _assigned_session()  # None or list
    if scoped is not None:
        if not scoped:
            return jsonify({'error': 'No sessions assigned'}), 403
        # Filter requested days down to only those the user has access to
        days = [d for d in days if d in scoped]
        if not days:
            return jsonify({'error': 'You do not have access to any of the requested session types'}), 403

    try:
        start = dt_date.fromisoformat(start_str)
        end   = dt_date.fromisoformat(end_str)
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

    if end < start:
        return jsonify({'error': 'end_date must be on or after start_date'}), 400
    if (end - start).days > 365:
        return jsonify({'error': 'Date range cannot exceed 365 days'}), 400

    s2w = session_to_weekday_map()
    target_weekdays = {}
    for d in days:
        if d in s2w:
            target_weekdays[s2w[d]] = d

    created, skipped = 0, 0
    db      = get_db()
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
                    skipped += 1
        current += dt_timedelta(days=1)

    db.commit()
    log_action('bulk_term_sessions', 'term_sessions', None,
               {'term': term_name, 'created': created, 'skipped': skipped})
    return jsonify({'created': created, 'skipped': skipped})


@bp.route('/api/calendar/<int:session_id>', methods=['PUT'])
@permission_required('calendar.edit')
def api_calendar_update(session_id):
    data   = request.get_json() or {}
    status = data.get('status')
    notes  = data.get('notes')
    term   = data.get('term_name')
    db     = get_db()

    row = db.execute('SELECT * FROM term_sessions WHERE id = ?', (session_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    scoped = _assigned_session()  # None or list
    if scoped is not None and row['session_type'] not in (scoped or []):
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


@bp.route('/api/calendar/<int:session_id>', methods=['DELETE'])
@permission_required('calendar.delete')
def api_calendar_delete(session_id):
    db  = get_db()
    row = db.execute('SELECT * FROM term_sessions WHERE id = ?', (session_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    scoped = _assigned_session()  # None or list
    if scoped is not None and row['session_type'] not in (scoped or []):
        return jsonify({'error': 'You can only delete your own session entries'}), 403

    db.execute('DELETE FROM term_sessions WHERE id = ?', (session_id,))
    db.commit()
    log_action('delete_term_session', 'term_sessions', session_id,
               {'date': row['session_date'], 'type': row['session_type']})
    return jsonify({'ok': True})


@bp.route('/api/calendar/upcoming', methods=['GET'])
@login_required
def api_calendar_upcoming():
    from datetime import datetime
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
