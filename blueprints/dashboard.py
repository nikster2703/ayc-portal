"""
AYC Portal — Dashboard & audit-log blueprint.
Routes: /api/dashboard, /api/admin/audit*
"""

import csv
import io
from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from config import CLUB_SHORT_NAME
from helpers import (
    get_db, login_required, permission_required, _assigned_session,
)

bp = Blueprint('dashboard', __name__)


@bp.route('/api/dashboard')
@login_required
def api_dashboard():
    """Summary stats for the dashboard home page. Session-scoped for all non-admin roles."""
    db    = get_db()
    today = datetime.now().strftime('%Y-%m-%d')

    scoped = _assigned_session()

    if scoped is None:
        counts = db.execute('''
            SELECT
                SUM(CASE WHEN mt.registration_style != 'staff'                                          THEN 1 ELSE 0 END) AS total,
                SUM(CASE WHEN mt.registration_style != 'staff' AND LOWER(TRIM(m.status)) = 'active'    THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN mt.registration_style != 'staff' AND LOWER(TRIM(m.status)) = 'leaver'    THEN 1 ELSE 0 END) AS leavers,
                SUM(CASE WHEN mt.registration_style  = 'staff' AND LOWER(TRIM(m.status)) != 'leaver'   THEN 1 ELSE 0 END) AS staff_active
            FROM members m
            JOIN member_types mt ON mt.slug = m.member_type
        ''').fetchone()
        session_rows = db.execute('''
            SELECT m.session,
                   SUM(CASE WHEN mt.registration_style != 'staff' AND LOWER(TRIM(m.status)) != 'leaver' THEN 1 ELSE 0 END) AS members,
                   SUM(CASE WHEN mt.registration_style  = 'staff' AND LOWER(TRIM(m.status)) != 'leaver' THEN 1 ELSE 0 END) AS staff
            FROM members m
            JOIN member_types mt ON mt.slug = m.member_type
            GROUP BY m.session
        ''').fetchall()
        pending = db.execute(
            'SELECT COUNT(*) AS n FROM pending_registrations WHERE status = "pending"'
        ).fetchone()['n']
        alert_rows = db.execute('''
            SELECT ar.id, ar.flag_label, ar.flag_colour,
                   COUNT(mf.id) AS flag_count
            FROM alert_rules ar
            LEFT JOIN member_flags mf ON mf.rule_id = ar.id AND mf.resolved_at IS NULL
            WHERE ar.is_active = 1
            GROUP BY ar.id
            ORDER BY flag_count DESC, ar.name
        ''').fetchall()
    else:
        counts = db.execute('''
            SELECT
                SUM(CASE WHEN mt.registration_style != 'staff'                                          THEN 1 ELSE 0 END) AS total,
                SUM(CASE WHEN mt.registration_style != 'staff' AND LOWER(TRIM(m.status)) = 'active'    THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN mt.registration_style != 'staff' AND LOWER(TRIM(m.status)) = 'leaver'    THEN 1 ELSE 0 END) AS leavers,
                SUM(CASE WHEN mt.registration_style  = 'staff' AND LOWER(TRIM(m.status)) != 'leaver'   THEN 1 ELSE 0 END) AS staff_active
            FROM members m
            JOIN member_types mt ON mt.slug = m.member_type
            WHERE m.session = ?
        ''', (scoped,)).fetchone()
        session_rows = db.execute('''
            SELECT m.session,
                   SUM(CASE WHEN mt.registration_style != 'staff' AND LOWER(TRIM(m.status)) != 'leaver' THEN 1 ELSE 0 END) AS members,
                   SUM(CASE WHEN mt.registration_style  = 'staff' AND LOWER(TRIM(m.status)) != 'leaver' THEN 1 ELSE 0 END) AS staff
            FROM members m
            JOIN member_types mt ON mt.slug = m.member_type
            WHERE m.session = ?
            GROUP BY m.session
        ''', (scoped,)).fetchall()
        pending = db.execute(
            'SELECT COUNT(*) AS n FROM pending_registrations WHERE status = "pending"'
            ' AND (assigned_session = ? OR assigned_session IS NULL OR assigned_session = "")',
            (scoped,)
        ).fetchone()['n']
        alert_rows = db.execute('''
            SELECT ar.id, ar.flag_label, ar.flag_colour,
                   COUNT(mf.id) AS flag_count
            FROM alert_rules ar
            LEFT JOIN member_flags mf ON mf.rule_id = ar.id AND mf.resolved_at IS NULL
            LEFT JOIN members m ON m.id = mf.member_id AND m.session = ?
            WHERE ar.is_active = 1
            GROUP BY ar.id
            ORDER BY flag_count DESC, ar.name
        ''', (scoped,)).fetchall()

    session_counts = {r['session']: {'members': r['members'], 'staff': r['staff']}
                      for r in session_rows if r['session'] is not None}

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

    recent = db.execute('''
        SELECT a.action, a.details, a.timestamp, u.username
        FROM   audit_log a
        LEFT JOIN users u ON u.id = a.user_id
        ORDER  BY a.timestamp DESC
        LIMIT  8
    ''').fetchall()

    alerts_last_run = db.execute(
        "SELECT value FROM settings WHERE key = 'alerts_last_run'"
    ).fetchone()

    return jsonify({
        'members':           dict(counts),
        'session_counts':    session_counts,
        'pending_approvals': pending,
        'today_attendance':  [dict(r) for r in today_att],
        'recent_activity':   [dict(r) for r in recent],
        'scoped_session':    scoped,
        'alert_flags':       [dict(r) for r in alert_rows],
        'alerts_last_run':   alerts_last_run['value'] if alerts_last_run else '',
    })


# ── Audit log ─────────────────────────────────────────────────────────────────

@bp.route('/api/admin/audit')
@permission_required('audit.view')
def api_audit_log():
    limit     = min(int(request.args.get('limit', 500)), 2000)
    offset    = int(request.args.get('offset', 0))
    action    = request.args.get('action', '').strip()
    user_id   = request.args.get('user_id', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to   = request.args.get('date_to', '').strip()

    db     = get_db()
    wheres = ['1=1']
    params: list = []

    if action:
        wheres.append('a.action = ?')
        params.append(action)
    if user_id:
        wheres.append('a.user_id = ?')
        params.append(int(user_id))
    if date_from:
        wheres.append("date(a.timestamp) >= date(?)")
        params.append(date_from)
    if date_to:
        wheres.append("date(a.timestamp) <= date(?)")
        params.append(date_to)

    params += [limit, offset]
    rows = db.execute(f'''
        SELECT  a.*, u.username
        FROM    audit_log a
        LEFT JOIN users u ON u.id = a.user_id
        WHERE   {" AND ".join(wheres)}
        ORDER   BY a.timestamp DESC
        LIMIT   ? OFFSET ?
    ''', params).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/audit/users')
@permission_required('audit.view')
def api_audit_log_users():
    db   = get_db()
    rows = db.execute('''
        SELECT DISTINCT u.id, u.username
        FROM   audit_log a
        JOIN   users u ON u.id = a.user_id
        ORDER  BY u.username
    ''').fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/audit/export.csv')
@permission_required('audit.view')
def api_audit_log_export():
    action    = request.args.get('action', '').strip()
    user_id   = request.args.get('user_id', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to   = request.args.get('date_to', '').strip()

    db     = get_db()
    wheres = ['1=1']
    params: list = []

    if action:
        wheres.append('a.action = ?')
        params.append(action)
    if user_id:
        wheres.append('a.user_id = ?')
        params.append(int(user_id))
    if date_from:
        wheres.append("date(a.timestamp) >= date(?)")
        params.append(date_from)
    if date_to:
        wheres.append("date(a.timestamp) <= date(?)")
        params.append(date_to)

    rows = db.execute(f'''
        SELECT  a.timestamp, u.username, a.action, a.table_name,
                a.record_id, a.details, a.ip_address
        FROM    audit_log a
        LEFT JOIN users u ON u.id = a.user_id
        WHERE   {" AND ".join(wheres)}
        ORDER   BY a.timestamp DESC
    ''', params).fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['Timestamp', 'User', 'Action', 'Table', 'Record ID', 'Details', 'IP'])
    for r in rows:
        writer.writerow([r['timestamp'], r['username'] or '—', r['action'],
                         r['table_name'] or '', r['record_id'] or '',
                         r['details'] or '', r['ip_address'] or ''])

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    slug      = CLUB_SHORT_NAME.lower().replace(' ', '_')
    filename  = f'{slug}_audit_log_{timestamp}.csv'

    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )
