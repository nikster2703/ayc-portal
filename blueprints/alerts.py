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
    get_setting, send_notification, tpl_ctx,
    _connect_db,
)
import rule_engine
from rule_engine import SAFE_MEMBER_COLUMNS

bp = Blueprint('alerts', __name__)

# Colour validation: any valid 6-digit CSS hex colour is accepted.
# The old fixed whitelist of 5 colours was unnecessarily restrictive.
_HEX_COLOUR_RE = re.compile(r'^#[0-9a-fA-F]{6}$')

# Whitelist of column names that may be interpolated into SQL for system fields.
# This prevents SQL injection if a field_definition row's column_name is ever
# tampered with — only names on this list can be used directly in queries.
# v12.77: the list now lives in rule_engine so there is exactly ONE copy. Two
# copies that drift apart is the echo-column bug class. The module-level alias
# is kept so the legacy evaluators below read unchanged.
_SAFE_MEMBER_COLUMNS = SAFE_MEMBER_COLUMNS

# Rule types accepted by the API. 'conditions' is the v12.77 multi-condition
# rule; the three legacy single-condition types are still accepted so existing
# rules can be edited without being forcibly rewritten.
_LEGACY_RULE_TYPES = ('date_field', 'empty_field', 'numeric')
_RULE_TYPES = ('attendance', 'conditions') + _LEGACY_RULE_TYPES


def _row_get(row, key, default=None):
    """Read a column that may not exist yet on an older schema."""
    try:
        val = row[key]
    except (KeyError, IndexError):
        return default
    return default if val is None else val


def _sessions_remaining_map(db, member_ids):
    """{member_id: sessions remaining} for the derived sessions_remaining field.

    Granted = sum of payment_types.sessions_granted across the member's
    non-voided payments in the CURRENT membership period.
    Used    = attendance sign-ins falling inside that period.

    Members with no session-granting payment are omitted entirely rather than
    reported as 0 — they have no value for this field, so a numeric condition
    should not match them. Reporting 0 would flag every member who never
    bought a block of sessions the moment someone wrote 'remaining is under 2'.
    """
    member_ids = list(member_ids)
    if not member_ids:
        return {}
    period  = (get_setting('current_membership_period', '') or '').strip()
    if not period:
        return {}
    p_start = (get_setting('current_period_start', '') or '').strip()
    p_end   = (get_setting('current_period_end', '') or '').strip()
    # v12.80: without BOTH bounds this cannot be computed. Before this guard the
    # date filter was simply omitted, so every session the member had ever
    # attended counted against the block they just bought — silently producing a
    # far-too-low "remaining" and flagging people who are nowhere near running
    # out. Returning nothing means those members have no value for the field and
    # therefore match no numeric condition, which is the safe direction.
    if not p_start or not p_end:
        # print(), not current_app.logger — this runs under the nightly scheduler
        # as well as in a request, and there is no app context there.
        print('[alerts] sessions_remaining not computed: the current membership '
              'period has no start and end date. Set them in Payment Settings.')
        return {}

    ph = ','.join('?' * len(member_ids))
    granted = {}
    for r in db.execute(
        f'SELECT mp.member_id AS mid, SUM(pt.sessions_granted) AS n '
        f'FROM member_payments mp '
        f'JOIN payment_types pt ON pt.id = mp.payment_type_id '
        f'WHERE mp.voided_at IS NULL AND mp.period = ? '
        f'  AND pt.sessions_granted IS NOT NULL '
        f'  AND mp.member_id IN ({ph}) '
        f'GROUP BY mp.member_id',
        [period] + member_ids
    ).fetchall():
        if r['n']:
            granted[r['mid']] = int(r['n'])
    if not granted:
        return {}

    ids    = list(granted)
    params = list(ids)
    date_cond = ''
    if p_start:
        date_cond += ' AND session_date >= ?'
        params.append(p_start)
    if p_end:
        date_cond += ' AND session_date <= ?'
        params.append(p_end)
    ph2 = ','.join('?' * len(ids))
    used = {}
    for r in db.execute(
        f'SELECT member_id AS mid, COUNT(*) AS n FROM attendance '
        f'WHERE signed_in_at IS NOT NULL AND member_id IN ({ph2}){date_cond} '
        f'GROUP BY member_id',
        params
    ).fetchall():
        used[r['mid']] = r['n']

    return {mid: granted[mid] - used.get(mid, 0) for mid in granted}


def _rule_conditions(db, rule_id):
    """Condition rows for a rule; [] if the table predates this install."""
    try:
        return db.execute(
            'SELECT field_key, operator, value_1, value_2 FROM rule_conditions '
            'WHERE rule_id = ? ORDER BY sort_order, id', (rule_id,)
        ).fetchall()
    except sqlite3.OperationalError:
        return []


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
        # v12.55: rule applies if the member has that session assigned (junction)
        member_cond += (' AND EXISTS (SELECT 1 FROM member_sessions ms_x '
                        'JOIN session_types st_x ON st_x.id = ms_x.session_type_id '
                        'WHERE ms_x.member_id = m.id AND st_x.name = ?)')
        params_base.append(scoped_sess)

    members = db.execute(
        f'SELECT m.id, m.member_id, m.first_name, m.surname, m.session, '
        f'm.date_registered, m.created_at '
        f'FROM members m WHERE {member_cond}',
        params_base
    ).fetchall()

    # v12.55: sessions per member (junction), echo column as defensive fallback
    member_sessions_map = {}
    for _r in db.execute(
        'SELECT ms.member_id, st.name FROM member_sessions ms '
        'JOIN session_types st ON st.id = ms.session_type_id'
    ).fetchall():
        member_sessions_map.setdefault(_r['member_id'], []).append(_r['name'])

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

    # ── Condition-set rules (v12.77) ──────────────────────────────────────────
    # The new path. Attendance keeps its own timeline evaluator below because it
    # tests a sequence of sessions, not a field value. A legacy flat rule whose
    # condition could not be migrated has no rule_conditions rows and falls
    # through to its original evaluator, so nothing stops working.
    _conds = _rule_conditions(db, rule_id) if rule_type != 'attendance' else []

    if _conds:
        _member_ids = [m['id'] for m in members]
        _virtual = {}
        if any((c['field_key'] or '') == 'sessions_remaining' for c in _conds):
            _virtual['sessions_remaining'] = _sessions_remaining_map(db, _member_ids)
        should_flag = rule_engine.evaluate_conditions(
            db, _conds, _member_ids,
            today=datetime.strptime(today_str, '%Y-%m-%d').date(),
            match_mode=_row_get(rule, 'match_mode', 'all'),
            virtual_values=_virtual,
        )

    # ── Attendance rule ────────────────────────────────────────────────────────
    elif rule_type == 'attendance':
        threshold = rule['threshold_value'] or 5
        # Use session_completions (registers that were actually completed) rather
        # than term_sessions (the planning calendar).  term_sessions may be
        # sparsely populated which would cause the threshold guard below to skip
        # every member and produce 0 flags.
        past_sessions_rows = db.execute(
            "SELECT session_date, session_type FROM session_completions "
            "WHERE session_date <= ? ORDER BY session_date DESC",
            (today_str,)
        ).fetchall()
        sessions_by_type = defaultdict(list)
        for s in past_sessions_rows:
            sessions_by_type[s['session_type']].append(s['session_date'])

        for m in members:
            # Determine the effective join date for this member.
            # date_registered takes priority (staff-set, may be a historical date).
            # created_at is the automatic fallback — always present, never editable.
            raw_join = (m['date_registered'] or '').strip() or (m['created_at'] or '')[:10]
            join_date = raw_join[:10]  # normalise to YYYY-MM-DD

            # Only consider sessions that took place on or after the member joined.
            # This prevents new members being flagged for sessions they could not
            # have attended before they were registered.
            #
            # v12.55 (multi-session): evaluate against the member's COMBINED
            # timeline — the last N completed registers across every session
            # they are assigned to, newest first. The member is flagged only if
            # they attended none of those N club sessions, i.e. the rule means
            # "disengaged from the club", not "dropped one of their sessions".
            m_sessions = member_sessions_map.get(m['id']) or \
                         ([m['session']] if m['session'] else [])
            events = sorted(
                ((d, st) for st in m_sessions
                         for d in sessions_by_type.get(st, [])
                         if d >= join_date),
                key=lambda e: e[0], reverse=True
            )
            relevant = events[:threshold]
            if len(relevant) < threshold:
                continue
            # Count positive sign-ins only (signed_in_at IS NOT NULL) so that
            # absence rows written at register-completion time are not counted
            # as attended sessions. Match on (date, session_type) pairs to avoid
            # cross-session contamination on shared dates.
            pair_cond = ' OR '.join(
                ['(session_date = ? AND session_type = ?)'] * len(relevant))
            pair_params = [v for pair in relevant for v in pair]
            attended = db.execute(
                f'SELECT COUNT(*) AS n FROM attendance '
                f'WHERE member_id = ? AND signed_in_at IS NOT NULL AND ({pair_cond})',
                [m['id']] + pair_params
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


def _validate_conditions(db, raw):
    """Normalise and validate an incoming conditions list.

    Returns (conditions, error). A rule must not be saveable in a state the
    evaluator would silently ignore, so an operator that is not offered for the
    target field's type is rejected here rather than quietly matching nobody.
    Returns (None, None) when the caller sent no conditions key at all, which
    means 'leave the existing conditions alone'.
    """
    if raw is None:
        return None, None
    if not isinstance(raw, list):
        return None, 'conditions must be a list'

    out = []
    for i, c in enumerate(raw, 1):
        if not isinstance(c, dict):
            return None, 'Condition %d is malformed' % i
        fkey = (c.get('field_key') or '').strip()
        op   = (c.get('operator') or '').strip()
        if not fkey:
            return None, 'Condition %d: choose a field' % i
        if op not in rule_engine.OPERATORS:
            return None, 'Condition %d: unknown operator "%s"' % (i, op)

        if fkey in rule_engine.VIRTUAL_FIELDS:
            ftype = rule_engine.VIRTUAL_FIELDS[fkey]['field_type']
        else:
            fd = db.execute(
                'SELECT field_type FROM field_definitions WHERE key = ?', (fkey,)
            ).fetchone()
            if not fd:
                return None, 'Condition %d: unknown field "%s"' % (i, fkey)
            ftype = fd['field_type'] or 'text'

        if op not in rule_engine.operators_for(ftype):
            return None, ('Condition %d: "%s" cannot be used on a %s field'
                          % (i, rule_engine.OPERATORS[op]['label'], ftype))

        need = rule_engine.OPERATORS[op]['value_args']
        v1 = c.get('value_1')
        v2 = c.get('value_2')
        v1 = None if v1 is None or str(v1).strip() == '' else str(v1).strip()
        v2 = None if v2 is None or str(v2).strip() == '' else str(v2).strip()
        if need >= 1 and v1 is None:
            return None, 'Condition %d: a value is required' % i
        if need >= 2 and v2 is None:
            return None, 'Condition %d: two values are required' % i
        if need == 0:
            v1 = v2 = None
        elif need == 1:
            v2 = None
        out.append({'field_key': fkey, 'operator': op,
                    'value_1': v1, 'value_2': v2})
    return out, None


def _write_conditions(db, rule_id, conds):
    """Replace a rule's condition set wholesale."""
    db.execute('DELETE FROM rule_conditions WHERE rule_id = ?', (rule_id,))
    for i, c in enumerate(conds):
        db.execute(
            'INSERT INTO rule_conditions (rule_id, field_key, operator, '
            'value_1, value_2, sort_order) VALUES (?,?,?,?,?,?)',
            (rule_id, c['field_key'], c['operator'],
             c['value_1'], c['value_2'], i)
        )


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

    # v12.77: attach each rule's condition set. One query for the lot rather
    # than one per rule.
    conds_by_rule = {}
    try:
        for c in db.execute(
            'SELECT rule_id, field_key, operator, value_1, value_2 '
            'FROM rule_conditions ORDER BY rule_id, sort_order, id'
        ).fetchall():
            conds_by_rule.setdefault(c['rule_id'], []).append({
                'field_key': c['field_key'], 'operator': c['operator'],
                'value_1': c['value_1'], 'value_2': c['value_2'],
            })
    except sqlite3.OperationalError:
        pass   # table not created yet on a pre-migration boot

    out = []
    for r in rows:
        d = dict(r)
        d['conditions'] = conds_by_rule.get(r['id'], [])
        d.setdefault('match_mode', 'all')
        out.append(d)
    return jsonify(out)


@bp.route('/api/alert-rules/fields')
@permission_required('alerts.view')
def api_alert_rule_fields():
    """Field + operator catalogue for the rule condition builder.

    Returns every active field definition the engine can evaluate, each with the
    operators valid for its type, plus the derived virtual fields. The UI drives
    its operator dropdown from this so the two can never disagree.
    """
    db = get_db()
    fields = []
    for r in db.execute(
        'SELECT key, label, field_type, system_field FROM field_definitions '
        'WHERE active = 1 ORDER BY system_field DESC, sort_order, label'
    ).fetchall():
        ftype = r['field_type'] or 'text'
        if ftype in ('declaration',):
            continue          # recorded at registration, not staff-editable
        fields.append({
            'key': r['key'], 'label': r['label'], 'field_type': ftype,
            'system': bool(r['system_field']),
            'operators': rule_engine.operators_for(ftype),
        })
    for key, meta in rule_engine.VIRTUAL_FIELDS.items():
        fields.append({
            'key': key, 'label': meta['label'], 'field_type': meta['field_type'],
            'system': True, 'virtual': True, 'help': meta.get('help'),
            'operators': rule_engine.operators_for(meta['field_type']),
        })
    return jsonify({
        'fields': fields,
        'operators': {k: v for k, v in rule_engine.OPERATORS.items()},
    })


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
    if rule_type not in _RULE_TYPES:
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

    match_mode = 'any' if (data.get('match_mode') or 'all').strip().lower() == 'any' else 'all'

    db = get_db()
    conds, cond_err = _validate_conditions(db, data.get('conditions'))
    if cond_err:
        return jsonify({'error': cond_err}), 400
    # A condition rule with no conditions would match nobody, which is a silently
    # broken rule rather than an error the user can see. Reject it at save time.
    if rule_type == 'conditions' and not conds:
        return jsonify({'error': 'Add at least one condition'}), 400

    cur = db.execute(
        'INSERT INTO alert_rules (name, rule_type, target_field, condition, '
        'threshold_value, threshold_unit, applies_to_session, flag_label, '
        'flag_colour, auto_resolve, resolve_field, match_mode, is_active, created_by) '
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?)',
        (name, rule_type, target_field, condition, threshold_val, threshold_unit,
         applies_sess, flag_label, flag_colour, auto_resolve, resolve_field,
         match_mode, session['user_id'])
    )
    rule_id = cur.lastrowid
    if conds:
        _write_conditions(db, rule_id, conds)
    db.commit()
    log_action('create_alert_rule', 'alert_rules', rule_id,
               {'name': name, 'rule_type': rule_type, 'flag_label': flag_label,
                'conditions': len(conds or [])})
    return jsonify({'success': True, 'id': rule_id})


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
    conds, cond_err = _validate_conditions(db, data.get('conditions'))
    if cond_err:
        return jsonify({'error': cond_err}), 400
    new_type = (data.get('rule_type') or rule['rule_type']).strip()
    if new_type not in _RULE_TYPES:
        return jsonify({'error': 'Invalid rule_type'}), 400
    if new_type == 'conditions':
        # Either the payload carries conditions, or the rule already has some.
        existing = _rule_conditions(db, rule_id)
        if conds is not None and not conds:
            return jsonify({'error': 'Add at least one condition'}), 400
        if conds is None and not existing:
            return jsonify({'error': 'Add at least one condition'}), 400
    match_mode = 'any' if (data.get('match_mode')
                           or _row_get(rule, 'match_mode', 'all')
                           ).strip().lower() == 'any' else 'all'
    db.execute(
        'UPDATE alert_rules SET name=?, rule_type=?, target_field=?, condition=?, '
        'threshold_value=?, threshold_unit=?, applies_to_session=?, flag_label=?, '
        'flag_colour=?, auto_resolve=?, resolve_field=?, match_mode=?, is_active=? '
        'WHERE id=?',
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
            match_mode,
            1 if data.get('is_active', bool(rule['is_active'])) else 0,
            rule_id,
        )
    )
    if conds is not None:
        _write_conditions(db, rule_id, conds)
    db.commit()
    log_action('update_alert_rule', 'alert_rules', rule_id,
               {'name': data.get('name', rule['name']),
                'conditions': len(conds) if conds is not None else 'unchanged'})
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
                   COUNT(CASE WHEN mf.resolved_at IS NULL
                              AND EXISTS (SELECT 1 FROM member_sessions ms_x
                                          JOIN session_types st_x ON st_x.id = ms_x.session_type_id
                                          WHERE ms_x.member_id = m.id AND st_x.name IN ({placeholders}))
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
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Not found'}), 404
    from helpers import member_in_scope
    if not member_in_scope(member_id):   # v12.51: any-session intersection
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
