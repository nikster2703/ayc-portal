"""
AYC Portal — Dashboard & audit-log blueprint.
Routes: /api/dashboard, /api/admin/audit*
"""

import csv
import io
from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from helpers import (
    get_db, login_required, permission_required, _assigned_session, club_slug,
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
                SUM(CASE WHEN mt.registration_style != 'staff'                                       THEN 1 ELSE 0 END) AS total,
                SUM(CASE WHEN mt.registration_style != 'staff' AND ms.behaviour = 'active'           THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN mt.registration_style != 'staff' AND ms.behaviour = 'inactive'         THEN 1 ELSE 0 END) AS inactive,
                SUM(CASE WHEN mt.registration_style != 'staff' AND ms.behaviour = 'leaver'           THEN 1 ELSE 0 END) AS leavers,
                SUM(CASE WHEN mt.registration_style  = 'staff' AND ms.behaviour != 'leaver'          THEN 1 ELSE 0 END) AS staff_active
            FROM members m
            JOIN member_types mt ON mt.slug = m.member_type
            LEFT JOIN member_statuses ms ON ms.name = m.status
        ''').fetchone()
        # v12.51: per-session counts via the junction — a member assigned to N
        # sessions counts once in EACH session (headline totals above stay
        # member-distinct because they don't join the junction).
        session_rows = db.execute('''
            SELECT st.name AS session,
                   SUM(CASE WHEN mt.registration_style != 'staff' AND ms.behaviour = 'active' THEN 1 ELSE 0 END) AS members,
                   SUM(CASE WHEN mt.registration_style  = 'staff' AND ms.behaviour = 'active' THEN 1 ELSE 0 END) AS staff
            FROM member_sessions msj
            JOIN session_types st ON st.id = msj.session_type_id
            JOIN members m        ON m.id = msj.member_id
            JOIN member_types mt  ON mt.slug = m.member_type
            LEFT JOIN member_statuses ms ON ms.name = m.status
            GROUP BY st.name
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
        # scoped is a non-empty list of session names — build IN placeholders
        ph = ','.join('?' * len(scoped))
        counts = db.execute(f'''
            SELECT
                SUM(CASE WHEN mt.registration_style != 'staff'                                       THEN 1 ELSE 0 END) AS total,
                SUM(CASE WHEN mt.registration_style != 'staff' AND ms.behaviour = 'active'           THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN mt.registration_style != 'staff' AND ms.behaviour = 'inactive'         THEN 1 ELSE 0 END) AS inactive,
                SUM(CASE WHEN mt.registration_style != 'staff' AND ms.behaviour = 'leaver'           THEN 1 ELSE 0 END) AS leavers,
                SUM(CASE WHEN mt.registration_style  = 'staff' AND ms.behaviour != 'leaver'          THEN 1 ELSE 0 END) AS staff_active
            FROM members m
            JOIN member_types mt ON mt.slug = m.member_type
            LEFT JOIN member_statuses ms ON ms.name = m.status
            WHERE EXISTS (SELECT 1 FROM member_sessions ms_x
                          JOIN session_types st_x ON st_x.id = ms_x.session_type_id
                          WHERE ms_x.member_id = m.id AND st_x.name IN ({ph}))
        ''', scoped).fetchone()
        session_rows = db.execute(f'''
            SELECT st.name AS session,
                   SUM(CASE WHEN mt.registration_style != 'staff' AND ms.behaviour = 'active' THEN 1 ELSE 0 END) AS members,
                   SUM(CASE WHEN mt.registration_style  = 'staff' AND ms.behaviour = 'active' THEN 1 ELSE 0 END) AS staff
            FROM member_sessions msj
            JOIN session_types st ON st.id = msj.session_type_id
            JOIN members m        ON m.id = msj.member_id
            JOIN member_types mt  ON mt.slug = m.member_type
            LEFT JOIN member_statuses ms ON ms.name = m.status
            WHERE st.name IN ({ph})
            GROUP BY st.name
        ''', scoped).fetchall()
        pending = db.execute(
            f'SELECT COUNT(*) AS n FROM pending_registrations WHERE status = "pending"'
            f' AND (assigned_session IN ({ph}) OR assigned_session IS NULL OR assigned_session = "")',
            scoped
        ).fetchone()['n']
        alert_rows = db.execute(f'''
            SELECT ar.id, ar.flag_label, ar.flag_colour,
                   COUNT(CASE WHEN EXISTS (SELECT 1 FROM member_sessions ms_x
                                           JOIN session_types st_x ON st_x.id = ms_x.session_type_id
                                           WHERE ms_x.member_id = m.id AND st_x.name IN ({ph}))
                              THEN mf.id END) AS flag_count
            FROM alert_rules ar
            LEFT JOIN member_flags mf ON mf.rule_id = ar.id AND mf.resolved_at IS NULL
            LEFT JOIN members m ON m.id = mf.member_id
            WHERE ar.is_active = 1
            GROUP BY ar.id
            ORDER BY flag_count DESC, ar.name
        ''', scoped).fetchall()

    session_counts = {r['session']: {'members': r['members'], 'staff': r['staff']}
                      for r in session_rows if r['session'] is not None}

    # NB: completing a register writes absence rows (signed_in_at IS NULL) for
    # every member who didn't attend — count only actual sign-ins/outs.
    if scoped is None:
        today_att = db.execute('''
            SELECT SUM(CASE WHEN a.signed_in_at IS NOT NULL THEN 1 ELSE 0 END) AS total_signed_in,
                   SUM(CASE WHEN a.signed_in_at IS NOT NULL
                             AND a.signed_out_at IS NOT NULL THEN 1 ELSE 0 END) AS signed_out,
                   a.session_type
            FROM attendance a
            JOIN members m ON m.id = a.member_id
            JOIN member_types mt ON mt.slug = m.member_type
            WHERE a.session_date = ?
              AND mt.registration_style != 'staff'
            GROUP BY a.session_type
        ''', (today,)).fetchall()
    else:
        today_att = db.execute(f'''
            SELECT SUM(CASE WHEN a.signed_in_at IS NOT NULL THEN 1 ELSE 0 END) AS total_signed_in,
                   SUM(CASE WHEN a.signed_in_at IS NOT NULL
                             AND a.signed_out_at IS NOT NULL THEN 1 ELSE 0 END) AS signed_out,
                   a.session_type
            FROM attendance a
            JOIN members m ON m.id = a.member_id
            JOIN member_types mt ON mt.slug = m.member_type
            WHERE a.session_date = ? AND a.session_type IN ({ph})
              AND mt.registration_style != 'staff'
            GROUP BY a.session_type
        ''', [today] + list(scoped)).fetchall()

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
        'scoped_sessions':   scoped,  # list or None (admin)
        'alert_flags':       [dict(r) for r in alert_rows],
        'alerts_last_run':   alerts_last_run['value'] if alerts_last_run else '',
    })


@bp.route('/api/dashboard/attendance-trend')
@login_required
def api_attendance_trend():
    """Headcount per session date for the dashboard trend chart.
    Returns the last 12 session dates that have any attendance,
    scoped to the user's assigned sessions (all sessions for admins).

    Query params:
      view=members (default) — active non-staff members only
      view=staff             — staff/volunteer members only
    """
    db     = get_db()
    scoped = _assigned_session()
    view   = request.args.get('view', 'members')

    # Staff filter clause (joined to members + member_types)
    if view == 'staff':
        style_clause = "mt.registration_style = 'staff'"
    else:
        style_clause = "mt.registration_style != 'staff'"

    # NB: completing a register writes absence rows (signed_in_at IS NULL)
    # for every member who didn't attend — count only actual sign-ins.
    if scoped is None:
        rows = db.execute(f'''
            SELECT a.session_date,
                   SUM(CASE WHEN a.signed_in_at IS NOT NULL THEN 1 ELSE 0 END) AS headcount
            FROM attendance a
            JOIN members m ON m.id = a.member_id
            JOIN member_types mt ON mt.slug = m.member_type
            WHERE {style_clause}
            GROUP BY a.session_date
            ORDER BY a.session_date DESC
            LIMIT 12
        ''').fetchall()
    else:
        if not scoped:
            return jsonify([])
        ph = ','.join('?' * len(scoped))
        rows = db.execute(f'''
            SELECT a.session_date,
                   SUM(CASE WHEN a.signed_in_at IS NOT NULL THEN 1 ELSE 0 END) AS headcount
            FROM attendance a
            JOIN members m ON m.id = a.member_id
            JOIN member_types mt ON mt.slug = m.member_type
            WHERE {style_clause}
              AND a.session_type IN ({ph})
            GROUP BY a.session_date
            ORDER BY a.session_date DESC
            LIMIT 12
        ''', list(scoped)).fetchall()

    # Oldest → newest for charting
    return jsonify([dict(r) for r in reversed(rows)])


@bp.route('/api/dashboard/stat-trends')
@login_required
def api_stat_trends():
    """Real historical series for the dashboard stat-card sparklines.

    members / staff : cumulative headcount of current members by created_at,
                      sampled at 12 weekly cut-offs (membership growth)
    approvals       : registration submissions per week (last 12 weeks)
    attendance      : % attendance per completed session (last 12), derived
                      from sign-in vs absence rows written at completion
    """
    from datetime import date, timedelta

    db     = get_db()
    scoped = _assigned_session()
    today  = date.today()
    cutoffs = [(today - timedelta(days=7 * i)).isoformat() for i in range(11, -1, -1)]

    def cumulative(rows):
        dates = sorted((r['created_at'] or '')[:10] for r in rows)
        series, i = [], 0
        for c in cutoffs:
            while i < len(dates) and dates[i] <= c:
                i += 1
            series.append(i)
        return series

    # ── Members (active, non-staff) ──────────────────────────────────────────
    sess_filter, sess_args = '', []
    if scoped is not None:
        if not scoped:
            return jsonify({})
        ph = ','.join('?' * len(scoped))
        # v12.51: scope via the member_sessions junction (any-session match)
        sess_filter = (f' AND EXISTS (SELECT 1 FROM member_sessions ms_x'
                       f' JOIN session_types st_x ON st_x.id = ms_x.session_type_id'
                       f' WHERE ms_x.member_id = m.id AND st_x.name IN ({ph}))')
        sess_args = list(scoped)

    member_rows = db.execute(f'''
        SELECT m.created_at FROM members m
        JOIN member_types mt ON mt.slug = m.member_type
        LEFT JOIN member_statuses ms ON ms.name = m.status
        WHERE mt.registration_style != 'staff' AND ms.behaviour = 'active'{sess_filter}
    ''', sess_args).fetchall()
    member_series = cumulative(member_rows)
    month_ago = (today - timedelta(days=30)).isoformat()
    members_new = sum(1 for r in member_rows if (r['created_at'] or '')[:10] >= month_ago)

    # ── Staff & volunteers (not leavers) ─────────────────────────────────────
    staff_rows = db.execute(f'''
        SELECT m.created_at FROM members m
        JOIN member_types mt ON mt.slug = m.member_type
        LEFT JOIN member_statuses ms ON ms.name = m.status
        WHERE mt.registration_style = 'staff' AND ms.behaviour != 'leaver'{sess_filter}
    ''', sess_args).fetchall()
    staff_series = cumulative(staff_rows)
    staff_new = sum(1 for r in staff_rows if (r['created_at'] or '')[:10] >= month_ago)

    # ── Per-session membership growth (session stat tiles) ──────────────────
    # v12.51: one row per member-session pair so multi-session members feed
    # every one of their sessions' growth tiles.
    per_sess_rows = db.execute(f'''
        SELECT m.created_at, st.name AS session
        FROM member_sessions msj
        JOIN session_types st ON st.id = msj.session_type_id
        JOIN members m        ON m.id = msj.member_id
        JOIN member_types mt  ON mt.slug = m.member_type
        LEFT JOIN member_statuses ms ON ms.name = m.status
        WHERE mt.registration_style != 'staff' AND ms.behaviour = 'active'{sess_filter}
    ''', sess_args).fetchall()
    by_session = {}
    for r in per_sess_rows:
        if r['session']:
            by_session.setdefault(r['session'], []).append(r)
    session_series = {name: {'series': cumulative(rows)} for name, rows in by_session.items()}

    # ── Inactive / Leaver cohorts (their stat tiles) ─────────────────────────
    def cohort_series(behaviour):
        rows = db.execute(f'''
            SELECT m.created_at FROM members m
            JOIN member_types mt ON mt.slug = m.member_type
            LEFT JOIN member_statuses ms ON ms.name = m.status
            WHERE mt.registration_style != 'staff' AND ms.behaviour = ?{sess_filter}
        ''', [behaviour] + sess_args).fetchall()
        return cumulative(rows)
    inactive_series = cohort_series('inactive')
    leaver_series   = cohort_series('leaver')

    # ── Per-session attendance headcounts (Today's Sessions cards) ──────────
    if scoped is None:
        att_by_type = db.execute('''
            SELECT a.session_type, a.session_date,
                   SUM(CASE WHEN a.signed_in_at IS NOT NULL THEN 1 ELSE 0 END) AS n
            FROM attendance a
            JOIN members m ON m.id = a.member_id
            JOIN member_types mt ON mt.slug = m.member_type
            WHERE mt.registration_style != 'staff'
            GROUP BY a.session_type, a.session_date
            ORDER BY a.session_date
        ''').fetchall()
    else:
        ph2 = ','.join('?' * len(scoped))
        att_by_type = db.execute(f'''
            SELECT a.session_type, a.session_date,
                   SUM(CASE WHEN a.signed_in_at IS NOT NULL THEN 1 ELSE 0 END) AS n
            FROM attendance a
            JOIN members m ON m.id = a.member_id
            JOIN member_types mt ON mt.slug = m.member_type
            WHERE mt.registration_style != 'staff'
              AND a.session_type IN ({ph2})
            GROUP BY a.session_type, a.session_date
            ORDER BY a.session_date
        ''', list(scoped)).fetchall()
    session_attendance = {}
    for r in att_by_type:
        session_attendance.setdefault(r['session_type'], []).append(r['n'])
    session_attendance = {k: v[-12:] for k, v in session_attendance.items()}

    # ── Registration submissions per week ────────────────────────────────────
    if scoped is None:
        sub_rows = db.execute(
            "SELECT submitted_at FROM pending_registrations WHERE submitted_at >= ?",
            ((today - timedelta(days=84)).isoformat(),)).fetchall()
    else:
        ph = ','.join('?' * len(scoped))
        sub_rows = db.execute(
            f"SELECT submitted_at FROM pending_registrations WHERE submitted_at >= ?"
            f" AND (assigned_session IN ({ph}) OR assigned_session IS NULL OR assigned_session = '')",
            [(today - timedelta(days=84)).isoformat()] + list(scoped)).fetchall()
    approvals_series = [0] * 12
    approvals_week = 0
    for r in sub_rows:
        d = (r['submitted_at'] or '')[:10]
        if not d:
            continue
        days_ago = (today - date.fromisoformat(d)).days
        bucket = 11 - (days_ago // 7)
        if 0 <= bucket <= 11:
            approvals_series[bucket] += 1
        if days_ago < 7:
            approvals_week += 1

    # ── Attendance % per completed session date ──────────────────────────────
    if scoped is None:
        att_rows = db.execute('''
            SELECT a.session_date,
                   SUM(CASE WHEN a.signed_in_at IS NOT NULL THEN 1 ELSE 0 END) AS signed,
                   COUNT(*) AS total
            FROM attendance a
            JOIN members m ON m.id = a.member_id
            JOIN member_types mt ON mt.slug = m.member_type
            JOIN session_completions sc
              ON sc.session_date = a.session_date AND sc.session_type = a.session_type
            WHERE mt.registration_style != 'staff'
            GROUP BY a.session_date
            ORDER BY a.session_date DESC
            LIMIT 12
        ''').fetchall()
    else:
        ph = ','.join('?' * len(scoped))
        att_rows = db.execute(f'''
            SELECT a.session_date,
                   SUM(CASE WHEN a.signed_in_at IS NOT NULL THEN 1 ELSE 0 END) AS signed,
                   COUNT(*) AS total
            FROM attendance a
            JOIN members m ON m.id = a.member_id
            JOIN member_types mt ON mt.slug = m.member_type
            JOIN session_completions sc
              ON sc.session_date = a.session_date AND sc.session_type = a.session_type
            WHERE mt.registration_style != 'staff'
              AND a.session_type IN ({ph})
            GROUP BY a.session_date
            ORDER BY a.session_date DESC
            LIMIT 12
        ''', list(scoped)).fetchall()
    att = [{'date': r['session_date'],
            'pct': round(100 * r['signed'] / r['total'])}
           for r in reversed(att_rows) if r['total']]

    return jsonify({
        'members':   {'series': member_series, 'new_30d': members_new},
        'staff':     {'series': staff_series,  'new_30d': staff_new},
        'approvals': {'series': approvals_series, 'new_7d': approvals_week},
        'sessions':  session_series,            # {session_name: {series}}
        'inactive':  {'series': inactive_series},
        'leavers':   {'series': leaver_series},
        'session_attendance': session_attendance,  # {session_type: [headcounts]}
        'attendance': {
            'series':   [a['pct'] for a in att],
            'last_pct': att[-1]['pct'] if att else None,
            'avg_pct':  round(sum(a['pct'] for a in att) / len(att)) if att else None,
        },
    })


# ── Audit log ─────────────────────────────────────────────────────────────────

@bp.route('/api/admin/audit')
@permission_required('audit.view')
def api_audit_log():
    # v12.41: validate numeric params — bad input previously raised ValueError → 500
    try:
        limit  = min(int(request.args.get('limit', 500)), 2000)
        offset = max(int(request.args.get('offset', 0)), 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'limit and offset must be numeric'}), 400
    action    = request.args.get('action', '').strip()
    user_id   = request.args.get('user_id', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to   = request.args.get('date_to', '').strip()

    if user_id and not user_id.isdigit():
        return jsonify({'error': 'user_id must be numeric'}), 400

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

    if user_id and not user_id.isdigit():
        return jsonify({'error': 'user_id must be numeric'}), 400

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
    filename  = f'{club_slug()}_audit_log_{timestamp}.csv'

    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )
