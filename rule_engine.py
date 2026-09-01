"""
AYC Portal — rule condition engine.

Shared evaluation layer for alert / automation rules. Resolves a rule's set of
conditions against a population of members and returns the member ids that match.

Introduced in v12.77 (Phase 0 of the Automations & Member Groups plan). It
replaces the single flat condition (rule_type + condition + threshold_value)
that was evaluated inline in blueprints/alerts.py. Legacy flat rules are
migrated to single-condition rows by db.ensure_tables(); the flat columns are
still written so a rollback stays possible until the migration is proven.

Design notes:
  * Field values are bulk-loaded ONCE per field per run. The previous engine
    issued one query per member per rule (N+1); on a few hundred members with
    several rules that was thousands of round trips.
  * Date conditions support RELATIVE anchors. Literal "between two dates" is
    useless for a recurring rule such as "renewals due next month" — it would
    need re-editing every month.
  * Operators are offered per field type. Presenting "greater than" on a text
    field or a two-date range on a checkbox is how a config UI loses trust.
"""

import calendar
from datetime import datetime, date, timedelta

# ── Column whitelist ──────────────────────────────────────────────────────────
# Names that may be interpolated into SQL for system fields. Defined here and
# imported by blueprints/alerts.py so there is exactly ONE copy — two lists that
# drift apart is the echo-column bug class the July 2026 audits kept finding.
SAFE_MEMBER_COLUMNS = frozenset({
    'first_name', 'surname', 'date_of_birth', 'address', 'postcode',
    'ethnicity_religion', 'medical_sen', 'gp_contact', 'mobile', 'email',
    'member_type', 'staff_role', 'status', 'status_note', 'session',
    'member_id', 'date_registered', 'comments',
})

# ── Operator registry ─────────────────────────────────────────────────────────
# value_args = how many of value_1 / value_2 the operator consumes.
OPERATORS = {
    'eq':                 {'label': 'Is equal to',             'value_args': 1},
    'ne':                 {'label': 'Is not equal to',          'value_args': 1},
    'contains':           {'label': 'Contains',                 'value_args': 1},
    'gt':                 {'label': 'Is greater than',          'value_args': 1},
    'lt':                 {'label': 'Is less than',             'value_args': 1},
    'between':            {'label': 'Between',                  'value_args': 2},
    'before':             {'label': 'Is before',                'value_args': 1},
    'after':              {'label': 'Is after',                 'value_args': 1},
    'in_next_days':       {'label': 'Is in the next N days',    'value_args': 1},
    'in_last_days':       {'label': 'Was in the last N days',   'value_args': 1},
    'more_than_days_ago': {'label': 'Was more than N days ago', 'value_args': 1},
    'this_month':         {'label': 'Is this calendar month',   'value_args': 0},
    'next_month':         {'label': 'Is next calendar month',   'value_args': 0},
    'prev_month':         {'label': 'Was last calendar month',  'value_args': 0},
    'is_filled':          {'label': 'Is filled',                'value_args': 0},
    'is_empty':           {'label': 'Is empty',                 'value_args': 0},
    'is_true':            {'label': 'Is yes / ticked',          'value_args': 0},
    'is_false':           {'label': 'Is no / unticked',         'value_args': 0},
}

_TEXTISH = ('eq', 'ne', 'contains', 'is_filled', 'is_empty')
_NUMERIC = ('eq', 'ne', 'gt', 'lt', 'between', 'is_filled', 'is_empty')
_DATE    = ('eq', 'ne', 'before', 'after', 'between', 'in_next_days',
            'in_last_days', 'more_than_days_ago', 'this_month', 'next_month',
            'prev_month', 'is_filled', 'is_empty')
_BOOL    = ('is_true', 'is_false', 'is_filled', 'is_empty')

# field_definitions.field_type -> permitted operators
OPERATORS_BY_FIELD_TYPE = {
    'text':      _TEXTISH,
    'textarea':  _TEXTISH,
    'select':    _TEXTISH,
    'email':     _TEXTISH,
    'phone':     _TEXTISH,
    'postcode':  _TEXTISH,
    'signature': _TEXTISH,
    'number':    _NUMERIC,
    'date':      _DATE,
    'boolean':   _BOOL,
}

# Virtual (derived) fields the engine exposes alongside real field definitions.
# Populated by the caller via `virtual_values`; declared here so the UI can
# offer them in the field picker with the right operator set.
VIRTUAL_FIELDS = {
    'sessions_remaining': {
        'label': 'Paid sessions remaining',
        'field_type': 'number',
        'help': 'Sessions granted by payments in the current period, minus sessions attended since.',
    },
}


def operators_for(field_type):
    """Operators offered for a field type. Unknown types fall back to text."""
    return list(OPERATORS_BY_FIELD_TYPE.get(field_type or 'text', _TEXTISH))


# ── Parsing helpers ───────────────────────────────────────────────────────────

def parse_date(raw):
    """Lenient YYYY-MM-DD parse. Returns a date, or None."""
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    try:
        return datetime.strptime(s[:10], '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return None


def parse_number(raw):
    """Lenient float parse. Returns a float, or None."""
    if raw is None:
        return None
    s = str(raw).strip().replace(',', '')
    if not s:
        return None
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def _as_int(raw, default=0):
    n = parse_number(raw)
    return int(n) if n is not None else default


def month_bounds(anchor, offset=0):
    """(first_day, last_day) of the calendar month `offset` months from anchor."""
    y, m = anchor.year, anchor.month + offset
    while m > 12:
        m -= 12
        y += 1
    while m < 1:
        m += 12
        y -= 1
    return date(y, m, 1), date(y, m, calendar.monthrange(y, m)[1])


_TRUTHY = {'1', 'true', 'yes', 'y', 'on', 'ticked', 'checked'}
_FALSEY = {'0', 'false', 'no', 'n', 'off', 'unticked', 'unchecked'}


def _is_blank(raw):
    return raw is None or str(raw).strip() == ''


# ── Single condition evaluation ───────────────────────────────────────────────

def evaluate_condition(raw_value, operator, value_1, value_2, field_type, today):
    """Does one member's raw field value satisfy this condition?

    Returns a bool. Never raises on bad data — an unparseable value simply
    fails the comparison, which is the safe direction for a rule that may
    change a status or send an email.
    """
    op = (operator or '').strip()

    # Presence operators apply to every field type and must run before any
    # type coercion, otherwise "is empty" on a date field would need a
    # parseable date in order to report that there isn't one.
    if op == 'is_empty':
        return _is_blank(raw_value)
    if op == 'is_filled':
        return not _is_blank(raw_value)

    if op in ('is_true', 'is_false'):
        s = str(raw_value).strip().lower() if raw_value is not None else ''
        if op == 'is_true':
            return s in _TRUTHY
        return s in _FALSEY or s == ''

    # Everything below needs a value present.
    if _is_blank(raw_value):
        return False

    ftype = (field_type or 'text').lower()

    # ── Dates ────────────────────────────────────────────────────────────────
    if ftype == 'date':
        v = parse_date(raw_value)
        if v is None:
            return False
        if op == 'eq':
            d1 = parse_date(value_1)
            return d1 is not None and v == d1
        if op == 'ne':
            d1 = parse_date(value_1)
            return d1 is not None and v != d1
        if op == 'before':
            d1 = parse_date(value_1)
            return d1 is not None and v < d1
        if op == 'after':
            d1 = parse_date(value_1)
            return d1 is not None and v > d1
        if op == 'between':
            d1, d2 = parse_date(value_1), parse_date(value_2)
            if d1 is None or d2 is None:
                return False
            if d1 > d2:
                d1, d2 = d2, d1          # tolerate a reversed range
            return d1 <= v <= d2
        if op == 'in_next_days':
            return today <= v <= today + timedelta(days=_as_int(value_1))
        if op == 'in_last_days':
            return today - timedelta(days=_as_int(value_1)) <= v <= today
        if op == 'more_than_days_ago':
            return v < today - timedelta(days=_as_int(value_1))
        if op in ('this_month', 'next_month', 'prev_month'):
            offset = {'this_month': 0, 'next_month': 1, 'prev_month': -1}[op]
            lo, hi = month_bounds(today, offset)
            return lo <= v <= hi
        return False

    # ── Numbers ──────────────────────────────────────────────────────────────
    if ftype == 'number':
        v = parse_number(raw_value)
        if v is None:
            return False
        if op == 'eq':
            n = parse_number(value_1)
            return n is not None and v == n
        if op == 'ne':
            n = parse_number(value_1)
            return n is not None and v != n
        if op == 'gt':
            n = parse_number(value_1)
            return n is not None and v > n
        if op == 'lt':
            n = parse_number(value_1)
            return n is not None and v < n
        if op == 'between':
            lo, hi = parse_number(value_1), parse_number(value_2)
            if lo is None or hi is None:
                return False
            if lo > hi:
                lo, hi = hi, lo
            return lo <= v <= hi
        return False

    # ── Text and everything else ─────────────────────────────────────────────
    v = str(raw_value).strip().lower()
    t = str(value_1).strip().lower() if value_1 is not None else ''
    if op == 'eq':
        return v == t
    if op == 'ne':
        return v != t
    if op == 'contains':
        return bool(t) and t in v
    return False


# ── Bulk value loading ────────────────────────────────────────────────────────

def load_field_values(db, field_key, member_ids):
    """Return ({member_id: raw_value}, field_type) for one field across many members.

    One query, not one per member. Resolves system fields (a real members
    column) and custom fields (member_field_values) alike.

    field_type is None if the field does not exist, which callers should treat
    as "no member can match".
    """
    if not member_ids:
        return {}, None

    fd = db.execute(
        'SELECT id, column_name, system_field, field_type '
        'FROM field_definitions WHERE key = ?',
        (field_key,)
    ).fetchone()
    if not fd:
        return {}, None

    field_type = fd['field_type'] or 'text'

    if fd['system_field'] and fd['column_name']:
        col = fd['column_name']
        if col not in SAFE_MEMBER_COLUMNS:
            # Refuse to interpolate an unrecognised column name.
            return {}, field_type
        placeholders = ','.join('?' * len(member_ids))
        rows = db.execute(
            f'SELECT id, {col} AS val FROM members WHERE id IN ({placeholders})',
            list(member_ids)
        ).fetchall()
        return {r['id']: r['val'] for r in rows}, field_type

    placeholders = ','.join('?' * len(member_ids))
    rows = db.execute(
        f'SELECT member_id, value FROM member_field_values '
        f'WHERE field_id = ? AND member_id IN ({placeholders})',
        [fd['id']] + list(member_ids)
    ).fetchall()
    return {r['member_id']: r['value'] for r in rows}, field_type


# ── Condition set evaluation ──────────────────────────────────────────────────

def _cget(cond, key):
    """Read a key from a sqlite3.Row or a plain dict."""
    try:
        return cond[key]
    except (KeyError, IndexError):
        return None


def evaluate_conditions(db, conditions, member_ids, today=None,
                        match_mode='all', virtual_values=None):
    """Evaluate a rule's condition set against a set of members.

    conditions     — rows (or dicts) with field_key, operator, value_1, value_2
    member_ids     — the population to test
    match_mode     — 'all' (every condition) or 'any' (at least one)
    virtual_values — {field_key: {member_id: value}} for derived fields such as
                     sessions_remaining, which have no field_definitions row.

    Returns a set of member ids that match.

    A rule with NO conditions matches nobody. That is deliberate: an empty
    condition set most likely means a half-configured rule, and matching
    everybody would be the worst possible default once actions are attached
    in Phase 2.
    """
    member_ids = list(member_ids)
    if not conditions or not member_ids:
        return set()

    today = today or date.today()
    virtual_values = virtual_values or {}
    mode = 'any' if str(match_mode).lower() == 'any' else 'all'

    per_condition = []
    for cond in conditions:
        field_key = (_cget(cond, 'field_key') or '').strip()
        operator  = (_cget(cond, 'operator') or '').strip()
        value_1   = _cget(cond, 'value_1')
        value_2   = _cget(cond, 'value_2')

        if field_key in virtual_values:
            values = virtual_values[field_key]
            ftype  = VIRTUAL_FIELDS.get(field_key, {}).get('field_type', 'number')
        else:
            values, ftype = load_field_values(db, field_key, member_ids)
            if ftype is None:
                # Unknown field — no member can satisfy this condition.
                per_condition.append(set())
                continue

        matched = {
            mid for mid in member_ids
            if evaluate_condition(values.get(mid), operator,
                                  value_1, value_2, ftype, today)
        }
        per_condition.append(matched)

    if not per_condition:
        return set()
    if mode == 'any':
        return set().union(*per_condition)
    result = set(member_ids)
    for s in per_condition:
        result &= s
    return result
