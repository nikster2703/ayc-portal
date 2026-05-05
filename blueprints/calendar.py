"""
AYC Portal — Calendar blueprint.
Routes: /api/calendar/*, /api/session-types
"""

import sqlite3
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

    if not name:
        return jsonify({'error': 'name is required'}), 400
    if weekday is None or not isinstance(weekday, int) or weekday < 0 or weekday > 6:
        return jsonify({'error': 'weekday must be an integer 0–6 (Mon=0)'}), 400

    db        = get_db()
    max_order = db.execute('SELECT COALESCE(MAX(sort_order), -1) FROM session_types').fetchone()[0]
    try:
        cur = db.execute(
            'INSERT INTO session_types (name, weekday, active, sort_order) VALUES (?,?,1,?)',
            (name, weekday, max_order + 1)
        )
        db.commit()
        log_action('create_session_type', 'session_types', cur.lastrowid,
                   {'name': name, 'weekday': weekday})
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

    name    = data.get('name', current['name']).strip()
    weekday = data.get('weekday', current['weekday'])
    active  = int(data.get('active', current['active']))

    if not name:
        return jsonify({'error': 'name is required'}), 400
    if not isinstance(weekday, int) or weekday < 0 or weekday > 6:
        return jsonify({'error': 'weekday must be an integer 0–6'}), 400

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

    scoped = _assigned_session()
    if scoped is not None and session_type != scoped:
        return jsonify({'error': f'You can only add {scoped} sessions'}), 403
    if status not in VALID_STATUSES:
        return jsonify({'error': 'Invalid status'}), 400

    try:
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

    scoped = _assigned_session()
    if scoped is not None:
        if any(d != scoped for d in days):
            return jsonify({'error': f'You can only generate {scoped} sessions'}), 403
        days = [scoped]

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


@bp.route('/api/calendar/<int:session_id>', methods=['DELETE'])
@permission_required('calendar.delete')
def api_calendar_delete(session_id):
    db  = get_db()
    row = db.execute('SELECT * FROM term_sessions WHERE id = ?', (session_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    scoped = _assigned_session()
    if scoped is not None and row['session_type'] != scoped:
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
