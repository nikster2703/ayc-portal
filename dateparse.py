"""
AYC Portal — date reading for hand-kept spreadsheets.

Introduced in v12.85 (Phase 1b). Not a general date library: it exists because
of one specific, entirely ordinary property of real membership spreadsheets.

THE PROBLEM
-----------
In the Residents Association's September 2026 register, the 26/27 payment
column holds 52 TEXT strings against 14 real dates, in at least three shapes —
`21/3/26`, `20/4/2027`, `29/08/26` — plus `00/00/00` used as a sentinel meaning
"no payment required". Excel typed some cells as dates and left the rest as
text, because a human typed them on different days.

A value-only import calls str() on all of that and stores whatever comes out.
The damage is silent: `3/4/26` is 3 April to a British treasurer and 4 March to
a parser written in the wrong hemisphere, and nothing about the stored value
tells you which happened.

THE APPROACH
------------
  * Never guess a convention per value. Infer it ONCE from the whole column,
    using only the values that prove it — a first component above 12 can only
    be a day, so the column is day-first.
  * If the evidence is absent or contradictory, every ambiguous value in that
    column is flagged. Not defaulted, flagged. A column of forty dates that are
    all 1-12 in both positions genuinely cannot be resolved from inside the
    file, and pretending otherwise is how you silently move somebody's renewal
    by nine months.
  * Sentinels are recognised as conventions, not corruption (plan §8.2). A
    repeated impossible value in a hand-kept sheet means something.
  * Every result carries its issues. The importer's job is to put anything with
    an unresolved issue in front of a person; this module's job is to be honest
    about which those are.
"""

import datetime
import re

__all__ = ['ParsedDate', 'infer_convention', 'parse_value', 'parse_column',
           'SENTINELS']

# Values that are impossible as dates and appear repeatedly in hand-kept sheets.
# Recognised so they surface as "this column uses a sentinel" rather than as
# forty separate parse failures.
SENTINELS = {'00/00/00', '00/00/0000', '0/0/0', '00-00-00', '-', '--', 'n/a', 'na'}

_SEP = r'[/\-.]'
_NUMERIC = re.compile(rf'^\s*(\d{{1,4}}){_SEP}(\d{{1,2}}){_SEP}(\d{{2,4}})\s*$')

# Two-digit years: a membership payment date is never far in the future and
# rarely far in the past, so anything up to (this year + 5) is this century.
_Y2_FUTURE_ALLOWANCE = 5


class ParsedDate:
    """One cell's outcome. `date` is None whenever the value is not usable.

    ISSUES are things a person must decide. NOTES are things worth recording
    but which resolve themselves. The distinction matters more than it looks:
    on the RA's 26/27 column, treating "year was written as two digits" as an
    issue put 16 rows in front of a human who had nothing to decide about any
    of them — and a review queue that cries wolf sixteen times is a review
    queue nobody reads the seventeenth time.
    """

    __slots__ = ('raw', 'date', 'issues', 'notes', 'convention')

    def __init__(self, raw, date=None, issues=None, notes=None, convention=None):
        self.raw = raw
        self.date = date
        self.issues = issues or []
        self.notes = notes or []
        self.convention = convention

    @property
    def ok(self):
        """Usable without a human looking at it. Notes do not block."""
        return self.date is not None and not self.issues

    @property
    def iso(self):
        return self.date.isoformat() if self.date else None

    def __repr__(self):
        tail = f' {self.issues}' if self.issues else ''
        tail += f' notes={self.notes}' if self.notes else ''
        return f'<ParsedDate {self.raw!r} -> {self.iso}{tail}>'


def _components(value):
    """(a, b, year_text) for a numeric date-like string, else None."""
    m = _NUMERIC.match(value)
    if not m:
        return None
    a, b, y = m.group(1), m.group(2), m.group(3)
    if len(a) == 4:          # ISO-ish 2026/04/21 — unambiguous, year first
        return ('iso', int(a), int(b), y)
    return ('short', int(a), int(b), y)


def _resolve_year(text, today):
    if len(text) == 4:
        return int(text), False
    n = int(text)
    century = today.year - (today.year % 100)
    year = century + n
    if year > today.year + _Y2_FUTURE_ALLOWANCE:
        year -= 100
    return year, True


def infer_convention(values):
    """('dmy'|'mdy'|None, evidence) for a whole column.

    Only values that PROVE the order count: a component above 12 cannot be a
    month. Returns None when nothing proves it, or when both orders are proven,
    which means the column is internally inconsistent and no single convention
    can be trusted.
    """
    dmy = mdy = 0
    for v in values:
        if v is None:
            continue
        if isinstance(v, (datetime.datetime, datetime.date)):
            continue
        parts = _components(str(v).strip())
        if not parts or parts[0] == 'iso':
            continue
        _, a, b, _y = parts
        if a > 12 and b <= 12:
            dmy += 1
        elif b > 12 and a <= 12:
            mdy += 1
    evidence = {'day_first': dmy, 'month_first': mdy}
    if dmy and not mdy:
        return 'dmy', evidence
    if mdy and not dmy:
        return 'mdy', evidence
    return None, evidence


def parse_value(value, convention=None, today=None, future_ok=False):
    """Parse one cell. Always returns a ParsedDate; never raises."""
    today = today or datetime.date.today()

    if value is None or (isinstance(value, str) and not value.strip()):
        return ParsedDate(value)

    # Excel already typed it. Nothing to infer, nothing to get wrong.
    if isinstance(value, datetime.datetime):
        d = value.date()
    elif isinstance(value, datetime.date):
        d = value
    else:
        text = str(value).strip()
        if text.lower() in SENTINELS:
            return ParsedDate(value, issues=['sentinel'])
        parts = _components(text)
        if not parts:
            return ParsedDate(value, issues=['unparseable'])

        kind, a, b, ytext = parts
        issues, notes = [], []
        if kind == 'iso':
            # 2026/04/21 — four-digit year first, so nothing is ambiguous.
            year, month, day = a, b, int(ytext)
        else:
            year, two_digit = _resolve_year(ytext, today)
            if two_digit:
                notes.append('two_digit_year')
            if a > 12 and b <= 12:
                day, month = a, b               # proven day-first
            elif b > 12 and a <= 12:
                month, day = a, b               # proven month-first
            elif a <= 12 and b <= 12:
                if convention == 'dmy':
                    day, month = a, b
                elif convention == 'mdy':
                    month, day = a, b
                else:
                    # Unresolvable from inside the file. Say so.
                    return ParsedDate(value, issues=['ambiguous'])
            else:
                return ParsedDate(value, issues=['invalid'])
        try:
            d = datetime.date(year, month, day)
        except ValueError:
            return ParsedDate(value, issues=['invalid'])
        return _finish(ParsedDate(value, d, issues, notes, convention), today, future_ok)

    return _finish(ParsedDate(value, d, [], [], convention), today, future_ok)


def _finish(p, today, future_ok):
    if p.date and not future_ok and p.date > today:
        p.issues.append('future')
    if p.date and p.date.year < today.year - 60:
        p.issues.append('far_past')
    return p


def parse_column(values, today=None, future_ok=False):
    """Parse a whole column together, so the convention is inferred once.

    SET future_ok FOR ANY COLUMN WHERE A FUTURE DATE IS THE POINT — a renewal
    or expiry date. Run against the RA sheet's renewal column with the default,
    this flagged 167 of 189 rows as suspicious, which is not a finding, it is a
    column doing its job. A payment date is the opposite: a future one there is
    how "20/4/2027" sat unnoticed in a paid column.

    Returns (results, summary). The summary is what the import wizard shows a
    person before anything is written.
    """
    today = today or datetime.date.today()
    convention, evidence = infer_convention(values)
    results = [parse_value(v, convention, today, future_ok) for v in values]

    counts, note_counts = {}, {}
    for r in results:
        for issue in r.issues:
            counts[issue] = counts.get(issue, 0) + 1
        for note in r.notes:
            note_counts[note] = note_counts.get(note, 0) + 1
    filled = [r for r in results if r.raw not in (None, '')]
    summary = {
        'convention':      convention,
        'convention_evidence': evidence,
        'values':          len(filled),
        'parsed':          len([r for r in filled if r.date]),
        'needs_review':    len([r for r in filled if r.issues]),
        'issues':          counts,
        'notes':           note_counts,
        'already_typed':   len([r for r in filled
                                if isinstance(r.raw, (datetime.date, datetime.datetime))]),
    }
    return results, summary
