"""
AYC Portal — Member groups blueprint.

Routes: /api/groups/*, /api/group-types/*, /api/membership-periods/*, /admin/groups

Introduced in v12.78 (Phase 1a). Every endpoint is inert on an install that has
not enabled groups: the resolution helpers in groups.py return nothing, and the
admin page is reachable but shows the feature as off.

The invariants this blueprint exists to enforce are documented in groups.py.
The two that matter most:
  * A member belongs to at most ONE billing group. A second is refused, never
    silently swapped — which group owes the money is not a question the system
    should answer on someone's behalf.
  * A billing group always has a primary contact. Removing or retiring the
    primary is BLOCKED until another is nominated, which is what stops a payment
    reminder being addressed to somebody who has died.
"""

import re
import sqlcipher3 as sqlite3

from flask import Blueprint, jsonify, render_template, request, session

from helpers import (
    get_db, log_action, permission_required, get_setting, tpl_ctx,
)
import groups as G

bp = Blueprint('groups', __name__)

_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,38}$')
_HEX_RE  = re.compile(r'^#[0-9a-fA-F]{6}$')


def _slugify(name):
    s = re.sub(r'[^a-z0-9]+', '-', (name or '').strip().lower()).strip('-')
    return s[:39] or 'group'


def _group_row(db, r):
    """Serialise a group with its members and a payment-history flag."""
    members = db.execute('''
        SELECT m.id, m.member_id, m.first_name, m.surname, m.status,
               m.email, m.mobile, mgm.added_at
        FROM member_group_members mgm
        JOIN members m ON m.id = mgm.member_id
        WHERE mgm.group_id = ?
        ORDER BY mgm.added_at, mgm.id
    ''', (r['id'],)).fetchall()
    return {
        'id':                r['id'],
        'name':              r['name'],
        'group_type_id':     r['group_type_id'],
        'group_type':        r['type_name'] if 'type_name' in r.keys() else None,
        'is_billing_unit':   bool(r['is_billing_unit']) if 'is_billing_unit' in r.keys() else False,
        'primary_member_id': r['primary_member_id'],
        'notes':             r['notes'],
        'is_active':         bool(r['is_active']),
        'archived_at':       r['archived_at'],
        'member_count':      len(members),
        'members':           [dict(m) for m in members],
        'has_payments':      G.group_has_payments(db, r['id']),
    }


_GROUP_SELECT = '''
    SELECT mg.*, gt.name AS type_name, gt.is_billing_unit, gt.icon, gt.colour
    FROM member_groups mg
    JOIN group_types gt ON gt.id = mg.group_type_id
'''


# ── Groups ────────────────────────────────────────────────────────────────────

@bp.route('/api/groups')
@permission_required('groups.view')
def api_groups_list():
    """List groups. Archived groups are excluded unless explicitly asked for."""
    db = get_db()
    include_archived = request.args.get('archived') == '1'
    type_id = request.args.get('type_id')

    where, params = [], []
    if not include_archived:
        where.append('mg.is_active = 1')
    if type_id:
        where.append('mg.group_type_id = ?')
        params.append(type_id)
    sql = _GROUP_SELECT + (' WHERE ' + ' AND '.join(where) if where else '')
    sql += ' ORDER BY mg.is_active DESC, mg.name'
    rows = db.execute(sql, params).fetchall()
    return jsonify({
        'enabled': G.groups_enabled(),
        'label':   G.group_label(db),
        'groups':  [_group_row(db, r) for r in rows],
    })


@bp.route('/api/groups/<int:group_id>')
@permission_required('groups.view')
def api_group_get(group_id):
    db = get_db()
    r = db.execute(_GROUP_SELECT + ' WHERE mg.id = ?', (group_id,)).fetchone()
    if not r:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(_group_row(db, r))


@bp.route('/api/groups', methods=['POST'])
@permission_required('groups.manage')
def api_group_create():
    db   = get_db()
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'A name is required'}), 400

    type_id = data.get('group_type_id')
    if not type_id:
        gt = G.billing_group_type(db)
        if not gt:
            return jsonify({'error': 'No group type is configured'}), 400
        type_id = gt['id']
    if not db.execute('SELECT 1 FROM group_types WHERE id = ? AND active = 1',
                      (type_id,)).fetchone():
        return jsonify({'error': 'Unknown group type'}), 400

    cur = db.execute(
        'INSERT INTO member_groups (name, group_type_id, notes, created_by) '
        'VALUES (?,?,?,?)',
        (name, type_id, (data.get('notes') or '').strip() or None,
         session.get('user_id'))
    )
    gid = cur.lastrowid

    # Optional member list on create, so the merge wizard can build a group in
    # one call. Each addition still goes through the billing-group check.
    rejected = []
    for mid in (data.get('member_ids') or []):
        ok, err = G.can_join_billing_group(db, mid, gid)
        if not ok:
            rejected.append({'member_id': mid, 'reason': err})
            continue
        db.execute('INSERT OR IGNORE INTO member_group_members (group_id, member_id) '
                   'VALUES (?,?)', (gid, mid))

    _autoset_primary(db, gid)
    db.commit()
    log_action('group_create', 'member_groups', gid,
               {'name': name, 'members': len(data.get('member_ids') or [])})
    return jsonify({'success': True, 'id': gid, 'rejected': rejected})


@bp.route('/api/groups/<int:group_id>', methods=['PUT'])
@permission_required('groups.manage')
def api_group_update(group_id):
    db = get_db()
    g  = db.execute('SELECT * FROM member_groups WHERE id = ?', (group_id,)).fetchone()
    if not g:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json() or {}

    name = (data.get('name') or g['name']).strip()
    if not name:
        return jsonify({'error': 'A name is required'}), 400

    primary = data.get('primary_member_id', g['primary_member_id'])
    if primary is not None:
        if primary not in G.group_member_ids(db, group_id):
            return jsonify({'error': 'The primary contact must be a member of the group'}), 400

    db.execute(
        'UPDATE member_groups SET name = ?, notes = ?, primary_member_id = ? WHERE id = ?',
        (name, (data.get('notes') if 'notes' in data else g['notes']), primary, group_id)
    )
    db.commit()
    log_action('group_update', 'member_groups', group_id, {'name': name})
    return jsonify({'success': True})


@bp.route('/api/groups/<int:group_id>', methods=['DELETE'])
@permission_required('groups.manage')
def api_group_delete(group_id):
    """Retire a group. Archived if it has payment history, deleted if not."""
    db = get_db()
    if not db.execute('SELECT 1 FROM member_groups WHERE id = ?', (group_id,)).fetchone():
        return jsonify({'error': 'Not found'}), 404
    outcome = G.archive_or_delete_group(db, group_id, session.get('user_id'))
    db.commit()
    log_action(f'group_{outcome}', 'member_groups', group_id, {})
    return jsonify({'success': True, 'outcome': outcome})


# ── Membership ────────────────────────────────────────────────────────────────

def _autoset_primary(db, group_id):
    """Give a group a primary contact when it has none and a candidate exists.

    Only ever FILLS an empty primary. It never reassigns one that is already
    set: a different person paying is not evidence that the contact changed,
    and silently moving it is how reminders end up addressed to the wrong
    person. A genuine change is a deliberate edit.
    """
    g = db.execute('SELECT primary_member_id FROM member_groups WHERE id = ?',
                   (group_id,)).fetchone()
    if not g or g['primary_member_id']:
        return
    ids = G.group_member_ids(db, group_id)
    if ids:
        db.execute('UPDATE member_groups SET primary_member_id = ? WHERE id = ?',
                   (ids[0], group_id))


@bp.route('/api/groups/<int:group_id>/members', methods=['POST'])
@permission_required('groups.manage')
def api_group_add_member(group_id):
    db   = get_db()
    data = request.get_json() or {}
    mid  = data.get('member_id')
    if not mid:
        return jsonify({'error': 'member_id is required'}), 400
    if not db.execute('SELECT 1 FROM member_groups WHERE id = ? AND is_active = 1',
                      (group_id,)).fetchone():
        return jsonify({'error': 'Group not found or archived'}), 404
    if not db.execute('SELECT 1 FROM members WHERE id = ?', (mid,)).fetchone():
        return jsonify({'error': 'Member not found'}), 404

    ok, err = G.can_join_billing_group(db, mid, group_id)
    if not ok:
        return jsonify({'error': err}), 409

    db.execute('INSERT OR IGNORE INTO member_group_members (group_id, member_id) '
               'VALUES (?,?)', (group_id, mid))
    _autoset_primary(db, group_id)
    db.commit()
    log_action('group_add_member', 'member_groups', group_id, {'member_id': mid})
    return jsonify({'success': True})


@bp.route('/api/groups/<int:group_id>/members/<int:member_id>', methods=['DELETE'])
@permission_required('groups.manage')
def api_group_remove_member(group_id, member_id):
    """Remove a member from a group.

    Blocked while they are the primary contact and others remain. If they are
    the LAST member, the group is archived or deleted per its payment history.
    """
    db = get_db()
    if not db.execute(
        'SELECT 1 FROM member_group_members WHERE group_id = ? AND member_id = ?',
        (group_id, member_id)
    ).fetchone():
        return jsonify({'error': 'Not a member of this group'}), 404

    blocked, msg = G.blocks_on_primary_contact(db, member_id, leaving_group_id=group_id)
    if blocked:
        return jsonify({'error': msg}), 409

    db.execute('DELETE FROM member_group_members WHERE group_id = ? AND member_id = ?',
               (group_id, member_id))

    outcome = 'removed'
    if not G.group_member_ids(db, group_id):
        outcome = G.archive_or_delete_group(db, group_id, session.get('user_id'))
    else:
        db.execute('UPDATE member_groups SET primary_member_id = NULL '
                   'WHERE id = ? AND primary_member_id = ?', (group_id, member_id))
        _autoset_primary(db, group_id)
    db.commit()
    log_action('group_remove_member', 'member_groups', group_id,
               {'member_id': member_id, 'outcome': outcome})
    return jsonify({'success': True, 'outcome': outcome})


@bp.route('/api/members/<int:member_id>/group')
@permission_required('members.view')
def api_member_group(member_id):
    """The member's billing group, for the member card panel."""
    db = get_db()
    g  = G.member_billing_group(db, member_id)
    if not g:
        return jsonify({
            'enabled': G.groups_enabled(),
            'label':   G.group_label(db),
            'exempt':  G.billing_exempt_member(db, member_id),
            'group':   None,
        })
    r = db.execute(_GROUP_SELECT + ' WHERE mg.id = ?', (g['id'],)).fetchone()
    return jsonify({
        'enabled': G.groups_enabled(),
        'label':   G.group_label(db),
        'exempt':  G.billing_exempt_member(db, member_id),
        'group':   _group_row(db, r),
    })


# ── Group types ───────────────────────────────────────────────────────────────

@bp.route('/api/group-types')
@permission_required('groups.view')
def api_group_types_list():
    db = get_db()
    rows = db.execute(
        'SELECT gt.*, (SELECT COUNT(*) FROM member_groups mg '
        '              WHERE mg.group_type_id = gt.id AND mg.is_active = 1) AS group_count '
        'FROM group_types gt ORDER BY gt.sort_order, gt.name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/group-types', methods=['POST'])
@permission_required('groups.manage')
def api_group_types_create():
    db   = get_db()
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'A name is required'}), 400
    slug = (data.get('slug') or _slugify(name)).strip().lower()
    if not _SLUG_RE.match(slug):
        return jsonify({'error': 'Invalid slug'}), 400
    colour = (data.get('colour') or '#3b6fde').strip()
    if not _HEX_RE.match(colour):
        return jsonify({'error': 'Colour must be a 6-digit hex code'}), 400

    billing = 1 if data.get('is_billing_unit') else 0
    if billing:
        # Exactly one billing type. The database has a partial unique index that
        # would reject this anyway; clearing the old one first turns a hard
        # constraint error into the obvious behaviour the admin intended.
        db.execute('UPDATE group_types SET is_billing_unit = 0 WHERE is_billing_unit = 1')
    try:
        cur = db.execute(
            'INSERT INTO group_types (name, slug, is_billing_unit, icon, colour, sort_order) '
            'VALUES (?,?,?,?,?,COALESCE((SELECT MAX(sort_order)+1 FROM group_types),0))',
            (name, slug, billing, (data.get('icon') or '🏠').strip()[:8], colour)
        )
    except sqlite3.IntegrityError:
        return jsonify({'error': 'A group type with that name or slug already exists'}), 409
    db.commit()
    log_action('group_type_create', 'group_types', cur.lastrowid, {'name': name})
    return jsonify({'success': True, 'id': cur.lastrowid})


@bp.route('/api/group-types/<int:type_id>', methods=['PUT'])
@permission_required('groups.manage')
def api_group_types_update(type_id):
    db = get_db()
    t  = db.execute('SELECT * FROM group_types WHERE id = ?', (type_id,)).fetchone()
    if not t:
        return jsonify({'error': 'Not found'}), 404
    data   = request.get_json() or {}
    name   = (data.get('name') or t['name']).strip()
    colour = (data.get('colour') or t['colour']).strip()
    if not name:
        return jsonify({'error': 'A name is required'}), 400
    if not _HEX_RE.match(colour):
        return jsonify({'error': 'Colour must be a 6-digit hex code'}), 400

    billing = 1 if data.get('is_billing_unit', bool(t['is_billing_unit'])) else 0
    if billing and not t['is_billing_unit']:
        db.execute('UPDATE group_types SET is_billing_unit = 0 WHERE is_billing_unit = 1')
    if not billing and t['is_billing_unit']:
        # Refuse to leave the organisation with no billing unit while billing
        # groups still exist — every payment would lose its home.
        n = db.execute('SELECT COUNT(*) AS n FROM member_groups '
                       'WHERE group_type_id = ? AND is_active = 1', (type_id,)).fetchone()['n']
        if n:
            return jsonify({'error': f'{n} active group(s) still use this as the billing '
                                     f'type. Move them first.'}), 409
    db.execute(
        'UPDATE group_types SET name=?, colour=?, icon=?, is_billing_unit=?, active=? WHERE id=?',
        (name, colour, (data.get('icon') or t['icon']).strip()[:8], billing,
         1 if data.get('active', bool(t['active'])) else 0, type_id)
    )
    db.commit()
    log_action('group_type_update', 'group_types', type_id, {'name': name})
    return jsonify({'success': True})


# ── Membership periods ────────────────────────────────────────────────────────

@bp.route('/api/membership-periods')
@permission_required('payments.view')
def api_periods_list():
    db = get_db()
    rows = db.execute(
        'SELECT mp.*, (SELECT COUNT(*) FROM member_payments p '
        '              WHERE p.period = mp.name) AS payment_count '
        'FROM membership_periods mp ORDER BY mp.sort_order, mp.start_date'
    ).fetchall()
    return jsonify({
        'periods':        [dict(r) for r in rows],
        'renewal_anchor': G.renewal_anchor(),
    })


@bp.route('/api/membership-periods', methods=['POST'])
@permission_required('payments.manage')
def api_periods_create():
    db   = get_db()
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    start = (data.get('start_date') or '').strip()
    end   = (data.get('end_date') or '').strip()
    if not name or not start or not end:
        return jsonify({'error': 'Name, start date and end date are all required'}), 400
    if start >= end:
        return jsonify({'error': 'The start date must be before the end date'}), 400
    try:
        cur = db.execute(
            'INSERT INTO membership_periods (name, start_date, end_date, sort_order) '
            'VALUES (?,?,?,COALESCE((SELECT MAX(sort_order)+1 FROM membership_periods),0))',
            (name, start, end)
        )
    except sqlite3.IntegrityError:
        return jsonify({'error': 'A period with that name already exists'}), 409
    if data.get('is_current'):
        _set_current_period(db, cur.lastrowid, name)
    db.commit()
    log_action('period_create', 'membership_periods', cur.lastrowid, {'name': name})
    return jsonify({'success': True, 'id': cur.lastrowid})


def _set_current_period(db, period_id, name):
    """Mark one period current, and keep the legacy settings in step.

    The old current_membership_period settings are still read by payments.py and
    members.py, so they are updated together rather than left to drift. They go
    away once every reader has moved to membership_periods.
    """
    db.execute('UPDATE membership_periods SET is_current = 0')
    db.execute('UPDATE membership_periods SET is_current = 1 WHERE id = ?', (period_id,))
    row = db.execute('SELECT start_date, end_date FROM membership_periods WHERE id = ?',
                     (period_id,)).fetchone()
    for k, v in (('current_membership_period', name),
                 ('current_period_start', row['start_date']),
                 ('current_period_end',   row['end_date'])):
        db.execute("INSERT OR REPLACE INTO settings (key, value, updated_at, updated_by) "
                   "VALUES (?,?,datetime('now'),?)", (k, v, session.get('user_id')))


@bp.route('/api/membership-periods/<int:period_id>/current', methods=['POST'])
@permission_required('payments.manage')
def api_periods_set_current(period_id):
    db = get_db()
    p  = db.execute('SELECT * FROM membership_periods WHERE id = ?', (period_id,)).fetchone()
    if not p:
        return jsonify({'error': 'Not found'}), 404
    _set_current_period(db, period_id, p['name'])
    db.commit()
    log_action('period_set_current', 'membership_periods', period_id, {'name': p['name']})
    return jsonify({'success': True})


@bp.route('/api/groups/enabled', methods=['POST'])
@permission_required('groups.manage')
def api_groups_set_enabled():
    """Turn the whole member-groups feature on or off.

    v12.81: this existed only as a setting with no way to change it. The admin
    page told people to "turn it on in Settings" and there was no control there
    or anywhere else, so the feature could not be enabled at all without editing
    the database — which blocked every group test.

    Switching OFF is deliberately non-destructive: groups, memberships and any
    payments recorded against a group are all left alone, and simply stop being
    consulted. Turning it back on restores exactly the previous state.
    """
    data = request.get_json() or {}
    enabled = '1' if data.get('enabled') else '0'
    db = get_db()
    db.execute(
        "INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('groups_enabled',?,datetime('now'),?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, "
        "updated_by=excluded.updated_by",
        (enabled, session.get('user_id'))
    )
    db.commit()
    log_action('setting_change', 'settings', None,
               {'key': 'groups_enabled', 'value': enabled})
    return jsonify({'success': True, 'enabled': enabled == '1'})


# ── Admin page ────────────────────────────────────────────────────────────────

@bp.route('/admin/groups')
@permission_required('groups.view')
def admin_groups_page():
    db = get_db()
    return render_template(
        'admin/groups.html',
        group_label=G.group_label(db),
        group_label_plural=G.group_label(db, plural=True),
        groups_enabled=G.groups_enabled(),
        **tpl_ctx()
    )
