"""
AYC Portal — Alerts blueprint.
Routes: /api/alert-rules/*, /api/alerts/*, /api/members/<id>/flags/*, /admin/alerts
Helpers: _run_alert_rule, run_all_alert_rules  (also called by scheduler in app.py)
"""

import re
import sqlcipher3 as sqlite3
from collections import defaultdict
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request, session

from helpers import (
    get_db, log_action, permission_required, _assigned_session,
    get_session_types, get_setting, send_notification, tpl_ctx,
    _connect_db,
)

bp = Blueprint('alerts', __name__)

# Colour validation: any valid 6-digit CSS hex colour is accepted.
# The old fixed whitelist of 5 colours was unnecessarily restrictive.
_HEX_COLOUR_RE = re.compile(r'^#[0-9a-fA-F]{6}$')

# Whitelist of column names that may be interpolated into SQL for system fields.
# This prevents SQL injection if a field_definition row's column_name is ever
# tampered with — only names on this list can be used directly in queries.
_SAFE_MEMBER_COLUMNS = frozenset({
    'first_name', 'surname', 'date_of_birth', 'address', 'postcode',
    'ethnicity_religion', 'medical_sen', 'gp_contact', 'mobile', 'email',
    'member_type', 'staff_role', 'status', 'status_note', 'session',
    'member_id',
})


# ── Alert rule engine ─────────────────────────────────────────────────────────

def _run_alert_rule(db, rule, today_str):
    """Evaluate one active alert rule against all eligible members.

    For each member that meets the condition:
      - Insert into member_flags if no active flag already exists.
    For each member that no longer meets the condition (auto_resolve=1):
      - Set resolved_at on their active flag.

    Returns (raised_count, resolved_count).
    """
    rule_id     = rule['id']
    rule_type   = rule['rule_type']
    auto_res    = rule['auto_resolve']
    scoped_sess = rule['applies_to_session']   # None → all sessions

    # ── Fetch eligible members ────────────────────────────────────────────────
    member_cond = (
        "EXISTS (SELECT 1 FROM member_statuses ms WHERE ms.name = m.status AND ms.behaviour = 'active') "
        "AND m.member_type IN (SELECT slug FROM member_types WHERE registration_style != 'staff')"
    )
    params_base = []
    if scoped_sess:
        member_cond += ' AND m.session = ?'
        params_base.append(scoped_sess)

    members = db.execute(
        f'SELECT m.id, m.member_id, m.first_name, m.surname, m.session '
        f'FROM members m WHERE {member_cond}',
        params_base
    ).fetchall()

    # ── Existing active flags for this rule ────────────────────────────────────
    existing_flags = {
        row['member_id']: row['id']
        for row in db.execute(
            'SELECT member_id, id FROM member_flags '
            'WHERE rule_id = ? AND resolved_at IS NULL',
            (rule_id,)
        ).fetchall()
    }

    should_flag = set()   # member db ids that currently meet the condition

    # ── Attendance rule ────────────────────────────────────────────────────────
    if rule_type == 'attendance':
        threshold = rule['threshold_value'] or 5
        past_sessions_rows = db.execute(
            "SELECT session_date, session_type FROM term_sessions "
            "WHERE session_date <= ? ORDER BY session_date DESC",
            (today_str,)
        ).fetchall()
        sessions_by_type = defaultdict(list)
        for s in past_sessions_rows:
            sessions_by_type[s['session_type']].append(s['session_date'])

        for m in members:
            relevant = sessions_by_type[m['session']][:threshold]
            if len(relevant) < threshold:
                continue
            attended = db.execute(
                'SELECT COUNT(*) AS n FROM attendance WHERE member_id = ? '
                'AND session_date IN ({})'.format(','.join('?' * len(relevant))),
                [m['id']] + relevant
            ).fetchone()['n']
            if attended == 0:
                should_flag.add(m['id'])

    # ── Date field rule ────────────────────────────────────────────────────────
    elif rule_type == 'date_field':
        target      = rule['target_field']
        condition   = rule['condition']     # older_than | before_today
        threshold_d = rule['threshold_value'] or 0

        fd = db.execute(
            'SELECT id, column_name, system_field FROM field_definitions WHERE key = ?',
            (target,)
        ).fetchone()

        for m in members:
            if fd and fd['system_field'] and fd['column_name']:
                col = fd['column_name']
                if col not in _SAFE_MEMBER_COLUMNS:
                    continue  # refuse to interpolate unsafe column names
                row = db.execute(
                    f'SELECT {col} AS val FROM members WHERE id = ?',
                    (m['id'],)
                ).fetchone()
                val = row['val'] if row else None
            else:
                fid = fd['id'] if fd else None
                if not fid:
                    continue
                row = db.execute(
                    'SELECT value FROM member_field_values WHERE member_id = ? AND field_id = ?',
                    (m['id'], fid)
                ).fetchone()
                val = row['value'] if row else None

            if not val:
                continue
            try:
                field_date = datetime.strptime(val[:10], '%Y-%m-%d').date()
            except (ValueError, TypeError):
                continue

            today_date = datetime.strptime(today_str, '%Y-%m-%d').date()
            if condition == 'older_than':
                if (today_date - field_date).days >= threshold_d:
                    should_flag.add(m['id'])
            elif condition == 'before_today':
                if field_date < today_date:
                    should_flag.add(m['id'])

    # ── Empty field rule ───────────────────────────────────────────────────────
    elif rule_type == 'empty_field':
        target    = rule['target_field']
        condition = rule['condition'] or 'is_empty'   # is_empty | is_filled
        fd = db.execute(
            'SELECT id, column_name, system_field FROM field_definitions WHERE key = ?',
            (target,)
        ).fetchone()

        for m in members:
            if fd and fd['system_field'] and fd['column_name']:
                col = fd['column_name']
                if col not in _SAFE_MEMBER_COLUMNS:
                    continue  # refuse to interpolate unsafe column names
                row = db.execute(
                    f'SELECT {col} AS val FROM members WHERE id = ?',
                    (m['id'],)
                ).fetchone()
                val = (row['val'] or '').strip() if row else ''
            else:
                fid = fd['id'] if fd else None
                if not fid:
                    continue
                row = db.execute(
                    'SELECT value FROM member_field_values WHERE member_id = ? AND field_id = ?',
                    (m['id'], fid)
                ).fetchone()
                val = (row['value'] or '').strip() if row else ''

            if condition == 'is_filled':
                if val:
                    should_flag.add(m['id'])
            else:  # is_empty (default)
                if not val:
                    should_flag.add(m['id'])

    # ── Numeric rule ───────────────────────────────────────────────────────────
    elif rule_type == 'numeric':
        target    = rule['target_field']
        condition = rule['condition']    # above | below
        threshold = rule['threshold_value'] or 0
        fd = db.execute(
            'SELECT id, column_name, system_field FROM field_definitions WHERE key = ?',
            (target,)
        ).fetchone()

        for m in members:
            if fd and fd['system_field'] and fd['column_name']:
                col = fd['column_name']
                if col not in _SAFE_MEMBER_COLUMNS:
                    continue  # refuse to interpolate unsafe column names
                row = db.execute(
                    f'SELECT {col} AS val FROM members WHERE id = ?',
                    (m['id'],)
                ).fetchone()
                raw = row['val'] if row else None
            else:
                fid = fd['id'] if fd else None
                if not fid:
                    continue
                row = db.execute(
                    'SELECT value FROM member_field_values WHERE member_id = ? AND field_id = ?',
                    (m['id'], fid)
                ).fetchone()
                raw = row['value'] if row else None

            try:
                num = float(raw)
            except (TypeError, ValueError):
                continue

            if condition == 'above' and num > threshold:
                should_flag.add(m['id'])
            elif condition == 'below' and num < threshold:
                should_flag.add(m['id'])

    # ── Raise new flags ────────────────────────────────────────────────────────
    raised = 0
    for mid in should_flag:
        if mid not in existing_flags:
            db.execute(
                'INSERT INTO member_flags (member_id, rule_id, flagged_at, flagged_by) '
                'VALUES (?, ?, datetime("now"), "auto")',
                (mid, rule_id)
            )
            raised += 1

    # ── Auto-resolve flags where condition no longer met ──────────────────────
    resolved = 0
    if auto_res:
        for mid, flag_id in existing_flags.items():
            if mid not in should_flag:
                db.execute(
                    "UPDATE member_flags SET resolved_at = datetime('now'), "
                    "resolved_by = 'auto' WHERE id = ?",
                    (flag_id,)
                )
                resolved += 1

    return raised, resolved


def run_all_alert_rules():
    """Evaluate every active alert rule. Called by the nightly scheduler and the manual API."""
    db = _connect_db()
    db.row_factory = sqlite3.Row
    today = datetime.now().strftime('%Y-%m-%d')
    try:
        rules = db.execute(
            'SELECT * FROM alert_rules WHERE is_active = 1'
        ).fetchall()

        total_raised   = 0
        total_resolved = 0
        for rule in rules:
            try:
                raised, resolved = _run_alert_rule(db, rule, today)
                total_raised   += raised
                total_resolved += resolved
            except Exception as e:
                print(f'[alerts] Rule {rule["id"]} ({rule["name"]}) error: {e}')

        db.execute(
            "UPDATE settings SET value = ?, updated_at = datetime('now') "
            "WHERE key = 'alerts_last_run'",
            (datetime.now().strftime('%Y-%m-%d %H:%M'),)
        )

        # System notification to admins when new flags are raised
        if total_raised > 0:
            flag_word = 'flag' if total_raised == 1 else 'flags'
            try:
                send_notification(
                    sender_id=None,
                    title='⚑ Alert Flags Raised',
                    body=(f'{total_raised} new member {flag_word} raised by the automated '
                          f'alert check. Open the Members section to review.'),
                    notification_type='Urgent',
                    target_type='role',
                    target_value='admin',
                    is_system=1,
                    related_table='member_flags',
                    _db=db,
                )
            except Exception as _notif_exc:
                print(f'[alerts] Failed to send system notification: {_notif_exc}')

        db.commit()
        print(f'[alerts] Run complete — {total_raised} raised, {total_resolved} resolved')
        return total_raised, total_resolved
    except Exception as _run_exc:
        print(f'[alerts] Run failed: {_run_exc}')
        raise
    finally:
        db.close()


# ── Alert Rules API ───────────────────────────────────────────────────────────

@bp.route('/api/alert-rules')
@permission_required('alerts.view')
def api_alert_rules_list():
    """List all alert rules with active flag counts."""
    db   = get_db()
    rows = db.execute('''
        SELECT ar.*,
               COUNT(CASE WHEN mf.resolved_at IS NULL THEN 1 END) AS active_flag_count
        FROM alert_rules ar
        LEFT JOIN member_flags mf ON mf.rule_id = ar.id
        GROUP BY ar.id
        ORDER BY ar.is_active DESC, ar.name
    ''').fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/alert-rules', methods=['POST'])
@permission_required('alerts.manage')
def api_alert_rules_create():
    """Create a new alert rule."""
    data = request.get_json() or {}
    name        = (data.get('name') or '').strip()
    rule_type   = (data.get('rule_type') or '').strip()
    flag_label  = (data.get('flag_label') or '').strip()
    flag_colour = (data.get('flag_colour') or '#f59e0b').strip()

    if not name:
        return jsonify({'error': 'Rule name is required'}), 400
    if rule_type not in ('attendance', 'date_field', 'empty_field', 'numeric'):
        return jsonify({'error': 'Invalid rule_type'}), 400
    if not flag_label:
        return jsonify({'error': 'Flag label is required'}), 400
    if not _HEX_COLOUR_RE.match(flag_colour):
        return jsonify({'error': 'Colour must be a valid 6-digit hex code (e.g. #ef4444)'}), 400

    target_field   = (data.get('target_field') or '').strip() or None
    condition      = (data.get('condition') or '').strip() or None
    threshold_val  = data.get('threshold_value')
    threshold_unit = (data.get('threshold_unit') or '').strip() or None
    applies_sess   = (data.get('applies_to_session') or '').strip() or None
    auto_resolve   = 1 if data.get('auto_resolve', True) else 0
    resolve_field  = (data.get('resolve_field') or '').strip() or None

    db  = get_db()
    cur = db.execute(
        'INSERT INTO alert_rules (name, rule_type, target_field, condition, '
        'threshold_value, threshold_unit, applies_to_session, flag_label, '
        'flag_colour, auto_resolve, resolve_field, is_active, created_by) '
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?)',
        (name, rule_type, target_field, condition, threshold_val, threshold_unit,
         applies_sess, flag_label, flag_colour, auto_resolve, resolve_field,
         session['user_id'])
    )
    db.commit()
    log_action('create_alert_rule', 'alert_rules', cur.lastrowid,
               {'name': name, 'rule_type': rule_type, 'flag_label': flag_label})
    return jsonify({'success': True, 'id': cur.lastrowid})


@bp.route('/api/alert-rules/<int:rule_id>', methods=['PUT'])
@permission_required('alerts.manage')
def api_alert_rules_update(rule_id):
    """Update an existing alert rule."""
    rule = get_db().execute('SELECT * FROM alert_rules WHERE id = ?', (rule_id,)).fetchone()
    if not rule:
        return jsonify({'error': 'Not found'}), 404

    data        = request.get_json() or {}
    flag_colour = (data.get('flag_colour') or rule['flag_colour']).strip()
    if not _HEX_COLOUR_RE.match(flag_colour):
        return jsonify({'error': 'Colour must be a valid 6-digit hex code (e.g. #ef4444)'}), 400

    db = get_db()
    db.execute(
        'UPDATE alert_rules SET name=?, rule_type=?, target_field=?, condition=?, '
        'threshold_value=?, threshold_unit=?, applies_to_session=?, flag_label=?, '
        'flag_colour=?, auto_resolve=?, resolve_field=?, is_active=? WHERE id=?',
        (
            (data.get('name') or rule['name']).strip(),
            (data.get('rule_type') or rule['rule_type']).strip(),
            (data.get('target_field') or rule['target_field'] or None),
            (data.get('condition') or rule['condition'] or None),
            data.get('threshold_value', rule['threshold_value']),
            (data.get('threshold_unit') or rule['threshold_unit'] or None),
            (data.get('applies_to_session') or rule['applies_to_session'] or None),
            (data.get('flag_label') or rule['flag_label']).strip(),
            flag_colour,
            1 if data.get('auto_resolve', bool(rule['auto_resolve'])) else 0,
            (data.get('resolve_field') or rule['resolve_field'] or None),
            1 if data.get('is_active', bool(rule['is_active'])) else 0,
            rule_id,
        )
    )
    db.commit()
    log_action('update_alert_rule', 'alert_rules', rule_id,
               {'name': data.get('name', rule['name'])})
    return jsonify({'success': True})


@bp.route('/api/alert-rules/<int:rule_id>', methods=['DELETE'])
@permission_required('alerts.manage')
def api_alert_rules_delete(rule_id):
    """Deactivate (soft-delete) a rule and resolve all its open flags."""
    db   = get_db()
    rule = db.execute('SELECT * FROM alert_rules WHERE id = ?', (rule_id,)).fetchone()
    if not rule:
        return jsonify({'error': 'Not found'}), 404
    db.execute("UPDATE alert_rules SET is_active = 0 WHERE id = ?", (rule_id,))
    db.execute(
        "UPDATE member_flags SET resolved_at = datetime('now'), resolved_by = 'rule_deleted' "
        "WHERE rule_id = ? AND resolved_at IS NULL",
        (rule_id,)
    )
    db.commit()
    log_action('deactivate_alert_rule', 'alert_rules', rule_id, {'name': rule['name']})
    return jsonify({'success': True})


@bp.route('/api/alert-rules/<int:rule_id>/permanent-delete', methods=['POST'])
@permission_required('alerts.manage')
def api_alert_rules_permanent_delete(rule_id):
    """Permanently delete a rule and all its flag history. Irreversible."""
    db   = get_db()
    rule = db.execute('SELECT * FROM alert_rules WHERE id = ?', (rule_id,)).fetchone()
    if not rule:
        return jsonify({'error': 'Not found'}), 404
    flag_count = db.execute(
        'SELECT COUNT(*) AS n FROM member_flags WHERE rule_id = ?', (rule_id,)
    ).fetchone()['n']
    db.execute('DELETE FROM member_flags WHERE rule_id = ?', (rule_id,))
    db.execute('DELETE FROM alert_rules WHERE id = ?', (rule_id,))
    db.commit()
    log_action('delete_alert_rule', 'alert_rules', rule_id, {
        'name': rule['name'], 'flags_deleted': flag_count
    })
    return jsonify({'success': True})


@bp.route('/api/alert-rules/run', methods=['POST'])
@permission_required('alerts.run')
def api_alert_rules_run():
    """Manually trigger a full evaluation of all active alert rules."""
    raised, resolved = run_all_alert_rules()
    log_action('run_alert_rules', 'alert_rules', None,
               {'raised': raised, 'resolved': resolved, 'triggered_by': 'manual'})
    return jsonify({'success': True, 'raised': raised, 'resolved': resolved})


# ── Alerts summary ────────────────────────────────────────────────────────────

@bp.route('/api/alerts/summary')
@permission_required('alerts.view')
def api_alerts_summary():
    """Per-rule active flag counts — used by the dashboard widget."""
    db     = get_db()
    scoped = _assigned_session()  # None or list

    if scoped is None:
        rows = db.execute('''
            SELECT ar.id, ar.name, ar.flag_label, ar.flag_colour,
                   COUNT(CASE WHEN mf.resolved_at IS NULL THEN 1 END) AS flag_count
            FROM alert_rules ar
            LEFT JOIN member_flags mf ON mf.rule_id = ar.id
            WHERE ar.is_active = 1
            GROUP BY ar.id
            ORDER BY flag_count DESC, ar.name
        ''').fetchall()
    elif not scoped:
        rows = []
    else:
        placeholders = ','.join('?' * len(scoped))
        rows = db.execute(f'''
            SELECT ar.id, ar.name, ar.flag_label, ar.flag_colour,
                   COUNT(CASE WHEN mf.resolved_at IS NULL AND m.session IN ({placeholders})
                              THEN 1 END) AS flag_count
            FROM alert_rules ar
            LEFT JOIN member_flags mf ON mf.rule_id = ar.id
            LEFT JOIN members m ON m.id = mf.member_id
            WHERE ar.is_active = 1
            GROUP BY ar.id
            ORDER BY flag_count DESC, ar.name
        ''', scoped).fetchall()

    last_run = db.execute(
        "SELECT value FROM settings WHERE key = 'alerts_last_run'"
    ).fetchone()

    return jsonify({
        'rules':    [dict(r) for r in rows],
        'last_run': last_run['value'] if last_run else '',
    })


# ── Member flags ──────────────────────────────────────────────────────────────

@bp.route('/api/members/<int:member_id>/flags')
@permission_required('alerts.view')
def api_member_flags(member_id):
    """Return all flags (active and resolved) for a member."""
    db     = get_db()
    scoped = _assigned_session()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Not found'}), 404
    if scoped is not None and (member['session'] or '') not in (scoped or []):
        return jsonify({'error': 'Forbidden'}), 403

    flags = db.execute('''
        SELECT mf.id, mf.flagged_at, mf.flagged_by, mf.resolved_at, mf.resolved_by, mf.note,
               ar.id AS rule_id, ar.name AS rule_name, ar.flag_label, ar.flag_colour, ar.rule_type
        FROM member_flags mf
        JOIN alert_rules ar ON ar.id = mf.rule_id
        WHERE mf.member_id = ?
        ORDER BY mf.flagged_at DESC
    ''', (member_id,)).fetchall()

    return jsonify([dict(f) for f in flags])


@bp.route('/api/members/<int:member_id>/flags/<int:flag_id>/dismiss', methods=['POST'])
@permission_required('alerts.dismiss')
def api_member_flag_dismiss(member_id, flag_id):
    """Manually dismiss a flag from a member, with an optional note."""
    db   = get_db()
    flag = db.execute(
        'SELECT * FROM member_flags WHERE id = ? AND member_id = ?',
        (flag_id, member_id)
    ).fetchone()
    if not flag:
        return jsonify({'error': 'Flag not found'}), 404
    if flag['resolved_at']:
        return jsonify({'error': 'Flag already resolved'}), 400

    data = request.get_json() or {}
    note = (data.get('note') or '').strip() or None

    db.execute(
        "UPDATE member_flags SET resolved_at = datetime('now'), resolved_by = ?, note = ? "
        "WHERE id = ?",
        (str(session['user_id']), note, flag_id)
    )
    db.commit()

    member = db.execute('SELECT first_name, surname FROM members WHERE id = ?',
                        (member_id,)).fetchone()
    rule   = db.execute('SELECT name FROM alert_rules WHERE id = ?',
                        (flag['rule_id'],)).fetchone()
    log_action('dismiss_flag', 'member_flags', flag_id, {
        'member': f"{member['first_name'] or ''} {member['surname'] or ''}".strip(),
        'rule':   rule['name'] if rule else str(flag['rule_id']),
        'note':   note,
    })
    return jsonify({'success': True})


# ── Admin page ────────────────────────────────────────────────────────────────

@bp.route('/admin/alerts')
@permission_required('alerts.view')
def admin_alerts_page():
    """Alert Rules admin page — rule builder and manual run trigger."""
    db     = get_db()
    fields = db.execute(
        'SELECT key, label, field_type, system_field FROM field_definitions '
        'WHERE active = 1 ORDER BY label'
    ).fetchall()
    last_run = get_setting('alerts_last_run', '')
    return render_template(
        'admin/alerts.html',
        field_definitions=[dict(f) for f in fields],
        alerts_last_run=last_run,
        **tpl_ctx(),
    )
