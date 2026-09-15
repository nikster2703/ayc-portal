"""
AYC Portal — member group resolution.

Shared helpers for member groups: which group bills a member, which payments
cover them, and the invariants the UI must enforce.

Introduced in v12.78 (Phase 1a of the Automations & Member Groups plan).

Design notes:
  * A group is an EXPLICIT record. Membership is an explicit row. Nothing here
    ever infers a grouping from an address — postcodes cover many addresses,
    flats and annexes share a street address, and two people at one address may
    legitimately hold two memberships.
  * Exactly one group type per organisation is the BILLING unit. A member may
    belong to several groups but to at most ONE billing group. That invariant
    spans two tables so it cannot be a table constraint; it is enforced here and
    repaired by the startup reconcile in db.ensure_tables().
  * Resolution always goes through the junction. There is deliberately no group
    id echoed onto the members row — a value living in two places and quietly
    diverging is the bug class the July 2026 audits kept finding.
  * Everything degrades to today's behaviour when groups are disabled or a
    member has no group, so an install that never turns groups on is unaffected.
"""

from helpers import get_setting


# ── Configuration ─────────────────────────────────────────────────────────────

def groups_enabled():
    """Is the member groups feature switched on for this organisation?"""
    return (get_setting('groups_enabled', '0') or '0').strip() in ('1', 'true', 'True')


def billing_group_type(db):
    """The group type flagged as the billing unit, or None."""
    return db.execute(
        'SELECT * FROM group_types WHERE is_billing_unit = 1 AND active = 1'
    ).fetchone()


def group_label(db, plural=False):
    """What this organisation calls a billing group — Household, Family, ..."""
    gt = billing_group_type(db)
    name = gt['name'] if gt else 'Group'
    return (name + 's') if plural else name


def renewal_anchor():
    """anniversary | period_end | fixed_date"""
    val = (get_setting('renewal_anchor', 'anniversary') or 'anniversary').strip()
    return val if val in ('anniversary', 'period_end', 'fixed_date') else 'anniversary'


# ── Membership resolution ─────────────────────────────────────────────────────

def member_billing_group(db, member_id):
    """The member's active billing group row, or None.

    Returns None when groups are disabled, when no billing type is configured,
    or when the member simply is not in one — all of which are normal.
    """
    if not groups_enabled():
        return None
    return db.execute('''
        SELECT mg.* FROM member_group_members mgm
        JOIN member_groups mg ON mg.id = mgm.group_id
        JOIN group_types   gt ON gt.id = mg.group_type_id
        WHERE mgm.member_id = ? AND gt.is_billing_unit = 1 AND mg.is_active = 1
        LIMIT 1
    ''', (member_id,)).fetchone()


def billing_group_map(db, member_ids):
    """{member_id: group_id} for many members in one query.

    Used by the members list so paid status can resolve through groups without
    reintroducing an N+1.
    """
    member_ids = list(member_ids)
    if not member_ids or not groups_enabled():
        return {}
    ph = ','.join('?' * len(member_ids))
    return {
        r['member_id']: r['group_id']
        for r in db.execute(f'''
            SELECT mgm.member_id, mgm.group_id FROM member_group_members mgm
            JOIN member_groups mg ON mg.id = mgm.group_id
            JOIN group_types   gt ON gt.id = mg.group_type_id
            WHERE gt.is_billing_unit = 1 AND mg.is_active = 1
              AND mgm.member_id IN ({ph})
        ''', member_ids).fetchall()
    }


def group_member_ids(db, group_id):
    """Member ids in a group, in the order they were added."""
    return [r['member_id'] for r in db.execute(
        'SELECT member_id FROM member_group_members WHERE group_id = ? '
        'ORDER BY added_at, id', (group_id,)
    ).fetchall()]


def group_has_payments(db, group_id):
    """Has this group ever had a payment recorded against it?

    Voided payments still count: a void is part of the financial record, and
    destroying it would lose the audit trail the void exists to provide.
    """
    return db.execute(
        'SELECT 1 FROM member_payments WHERE group_id = ? LIMIT 1', (group_id,)
    ).fetchone() is not None


# ── Invariants the UI must enforce ────────────────────────────────────────────

def billing_exempt_member(db, member_id):
    """True if the member's TYPE does not participate in billing.

    Honorary members and staff are not billed, so they need no billing group and
    the unpaid rule must never chase them. Flagged on the type rather than
    matched on a name, so an organisation can rename it.
    """
    row = db.execute('''
        SELECT COALESCE(mt.billing_exempt, 0) AS ex
        FROM members m
        LEFT JOIN member_types mt ON mt.slug = m.member_type
        WHERE m.id = ?
    ''', (member_id,)).fetchone()
    return bool(row['ex']) if row else False


def can_join_billing_group(db, member_id, group_id):
    """(ok, error) — may this member be added to this group?

    Refuses a second billing group rather than silently replacing the first:
    which one owes the money is not a question the system should answer on a
    person's behalf.
    """
    gt = db.execute('''
        SELECT gt.is_billing_unit FROM member_groups mg
        JOIN group_types gt ON gt.id = mg.group_type_id WHERE mg.id = ?
    ''', (group_id,)).fetchone()
    if not gt or not gt['is_billing_unit']:
        return True, None          # non-billing groups are unconstrained
    existing = member_billing_group(db, member_id)
    if existing and existing['id'] != group_id:
        return False, (f'This member already belongs to {existing["name"]}. '
                       f'Remove them from it first.')
    return True, None


def status_is_deceased(db, status_name):
    """Is this status the one flagged as recording a death?"""
    if not status_name:
        return False
    row = db.execute(
        'SELECT COALESCE(is_deceased, 0) AS d FROM member_statuses WHERE name = ?',
        (status_name,)
    ).fetchone()
    return bool(row['d']) if row else False


def deceased_status_names(db):
    """Set of status names flagged as recording a death.

    A set rather than a single name: an organisation may rename the status or
    add its own. Callers compare against this instead of hard-coding 'Deceased'.
    """
    return {
        r['name'] for r in db.execute(
            'SELECT name FROM member_statuses WHERE COALESCE(is_deceased, 0) = 1'
        ).fetchall()
    }


def blocks_on_primary_contact(db, member_id, new_status=None, leaving_group_id=None):
    """(blocked, message) — would this change strand a group without a primary?

    A billing group must always have a primary contact: without one it silently
    stops being chased for money, which nobody notices until the year end. So
    removing the primary — or marking them deceased — is blocked until someone
    else is nominated.

    This is the guard that stops a payment reminder being addressed to someone
    who has died. It is deliberately a block and not a warning.
    """
    grp = member_billing_group(db, member_id)
    if not grp or grp['primary_member_id'] != member_id:
        return False, None
    if leaving_group_id is not None and leaving_group_id != grp['id']:
        return False, None
    if new_status is not None and not status_is_deceased(db, new_status):
        return False, None

    others = [m for m in group_member_ids(db, grp['id']) if m != member_id]
    if not others:
        return False, None         # last member leaving — handled by archival
    return True, (f'{grp["name"]} has no other primary contact. '
                  f'Choose a new primary contact for the group first.')


def archive_or_delete_group(db, group_id, user_id=None):
    """Retire a group whose last member has left. Returns 'archived'|'deleted'.

    A group that has ever taken a payment is ARCHIVED, never deleted — it owns
    that history, and the treasurer must still be able to answer what an address
    paid three years ago. A group with no financial history is a mistake someone
    made, and is removed outright.
    """
    if group_has_payments(db, group_id):
        db.execute(
            'UPDATE member_groups SET is_active = 0, primary_member_id = NULL, '
            "archived_at = datetime('now'), archived_by = ? WHERE id = ?",
            (user_id, group_id)
        )
        return 'archived'
    db.execute('DELETE FROM member_group_members WHERE group_id = ?', (group_id,))
    db.execute('DELETE FROM member_groups WHERE id = ?', (group_id,))
    return 'deleted'


# ── Payment coverage ──────────────────────────────────────────────────────────

def group_payment_coverage(db, member_ids, period):
    """Payments made against a GROUP, attributed to each of its members.

    Returns (whole_club_member_ids, {member_id: {session names}}) in exactly the
    shape the existing per-member coverage code produces, so the two merge.

    Empty for every install that has not enabled groups, which is why wiring
    this in cannot change existing behaviour.
    """
    member_ids = list(member_ids)
    if not member_ids or not period or not groups_enabled():
        return set(), {}
    ph = ','.join('?' * len(member_ids))
    whole = set()
    per_session = {}
    for r in db.execute(f'''
        SELECT mgm.member_id, mp.session_type_id, st.name AS session_name
        FROM   member_payments mp
        JOIN   payment_types pt        ON pt.id  = mp.payment_type_id
        JOIN   member_groups mg        ON mg.id  = mp.group_id AND mg.is_active = 1
        JOIN   member_group_members mgm ON mgm.group_id = mp.group_id
        LEFT JOIN session_types st     ON st.id  = mp.session_type_id
        WHERE  pt.is_membership = 1 AND mp.period = ? AND mp.voided_at IS NULL
          AND  mp.group_id IS NOT NULL AND mgm.member_id IN ({ph})
    ''', [period] + member_ids).fetchall():
        if r['session_type_id'] is None:
            whole.add(r['member_id'])
        elif r['session_name']:
            per_session.setdefault(r['member_id'], set()).add(r['session_name'])
    return whole, per_session
