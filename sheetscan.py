"""
AYC Portal — read what a hand-kept spreadsheet encodes in FORMATTING.

Introduced in v12.85 (Phase 1b). Implements plan §8.2, which is the second
highest risk in the project and the one specific to this migration:

    "The source spreadsheet encodes deceased members, duplicates, withdrawals,
     exemptions and non-payers entirely in cell formatting and sentinel values.
     A conventional value-only import loses all of them silently — no error, no
     warning, and the damage surfaces only when a reminder reaches the wrong
     person."

In the Residents Association's register, 105 rows are shaded grey, 6 cells in
the 26/27 column are filled red, 4 rows are struck through, and `00/00/00`
means "no payment required". None of that survives str(cell.value). One struck
row reads "Deceased" and carries a recorded payment: imported on values alone
it becomes an active, paid member, and next year it gets a renewal reminder.

WHAT THIS MODULE DOES NOT DO
----------------------------
It does not decide what grey MEANS. It cannot: the same colour means "removed
from the mailing list" in one organisation and "left" in another, and I got the
RA's own convention backwards on the first pass by inferring from correlation.
It reports the clusters and what correlates with them, and a person declares
the meaning in the wizard. That declaration is configuration, so the next
organisation's yellow costs nobody any code.
"""

import datetime
from collections import Counter, defaultdict

import dateparse

__all__ = ['scan_sheet', 'fill_key', 'ColumnScan']

# A value repeated at least this often that does not fit its column's dominant
# type is treated as a possible CONVENTION rather than as bad data. The plan:
# "In a hand-kept spreadsheet an odd repeated value is usually a convention,
# not corruption."
_CONVENTION_MIN = 2
_MAX_DISTINCT   = 40


def fill_key(cell):
    """A stable, comparable name for a cell's background, or None.

    openpyxl reports a colour as an explicit RGB, or as a theme index plus a
    tint, and the two are not interchangeable. Reading only .rgb returns the
    useless string 'Values must be of type <class str>' for theme colours —
    which is exactly how a fill-colour check can appear to run and silently
    find nothing.
    """
    f = getattr(cell, 'fill', None)
    if not f or f.fill_type != 'solid':
        return None
    c = f.start_color
    theme, tint, rgb = getattr(c, 'theme', None), getattr(c, 'tint', None), getattr(c, 'rgb', None)
    if isinstance(theme, int):
        t = round(tint, 3) if isinstance(tint, float) else 0.0
        if theme == 0 and t == 0.0:
            return None           # plain white is not a marking
        return f'theme{theme}/tint{t}'
    if isinstance(rgb, str) and len(rgb) == 8:
        if rgb.upper() in ('00000000', 'FFFFFFFF'):
            return None
        return f'#{rgb[2:].upper()}'
    return None


class ColumnScan:
    """What one column contains, and what it appears to mean."""

    def __init__(self, letter, header):
        self.letter = letter
        self.header = header
        self.filled = 0
        self.types = Counter()
        self.distinct = Counter()
        # Real cardinality, counted separately from the capped sample. Showing
        # the cap as the answer told a person that 14 different columns each
        # had exactly 40 distinct values, which is obviously nonsense and
        # quietly hid how varied a column really is.
        self.distinct_all = set()
        # Text values only. The convention check must run against what was
        # TYPED, not against str() of a cell Excel had already made a date:
        # str(datetime(2025,9,27)) is '2025-09-27 00:00:00', which no date
        # parser accepts, so every repeated real date got reported as a
        # mysterious convention. 74 false questions on the RA sheet.
        self.text_values = Counter()
        self.fills = defaultdict(list)       # fill_key -> [row, ...]
        self.date_summary = None
        self.conventions = []                # [{'value','count','why'}]
        # v12.87: formula columns. openpyxl gives you VALUES or
        # FORMULAS-and-formatting, never both from one workbook, and formatting
        # is what this module is for — so without a second, values-only
        # worksheet every derived column reports its formula as its content.
        # On the RA register that made "Full Name" look like 4 distinct values
        # (one CONCATENATE repeated 297 times) and "Members No" look like 302
        # distinct values (=P2, =P3, =P4 …). The plan calls this out in §7.4:
        # import the sources, derive the rest.
        self.formula_cells = 0
        self.formula_sample = None
        self.overtyped = []                  # rows where someone replaced the formula

    def as_dict(self):
        return {
            'column': self.letter,
            'header': self.header,
            'filled': self.filled,
            'types': dict(self.types),
            'distinct_count': len(self.distinct_all),
            'sampled':        len(self.distinct),
            'top_values': self.distinct.most_common(10),
            'cell_fills': {k: {'count': len(v), 'rows': v[:25]} for k, v in self.fills.items()},
            'dates': self.date_summary,
            'possible_conventions': self.conventions,
            'is_formula':     self.formula_cells > 0,
            'formula_cells':  self.formula_cells,
            'formula_sample': self.formula_sample,
            'overtyped_rows': self.overtyped[:25],
            'formula_note': (
                f'This column is calculated ({self.formula_sample}). Import the columns '
                f'it is built from, not this one.' if self.formula_cells else None),
        }


def _looks_dateish(values):
    dated = sum(1 for v in values if isinstance(v, (datetime.date, datetime.datetime)))
    textual = [v for v in values if isinstance(v, str)]
    hits = sum(1 for v in textual if dateparse._components(v.strip()))
    return (dated + hits) >= max(3, 0.4 * len(values))


def scan_sheet(ws, ws_values=None, header_row=1, max_rows=None, today=None):
    """Inventory a worksheet: values, types, sentinels, fills, strikethrough.

    `ws`        — loaded WITHOUT data_only, so formatting and formulas are present.
    `ws_values` — the SAME sheet loaded WITH data_only, so calculated columns
                  report what they display rather than how they are built. Pass
                  it whenever you have it; without it a formula column is
                  inventoried as its formula text.
    """
    today = today or datetime.date.today()
    last = min(ws.max_row, max_rows + header_row) if max_rows else ws.max_row

    headers = {}
    for cell in ws[header_row]:
        if cell.value not in (None, ''):
            headers[cell.column_letter] = str(cell.value).replace('\n', ' ').strip()

    # A row counts as real if any of its headed columns holds something.
    _src = ws_values if ws_values is not None else ws
    rows = []
    for r in range(header_row + 1, last + 1):
        if any(_src[f'{col}{r}'].value not in (None, '') for col in headers):
            rows.append(r)

    scans = {col: ColumnScan(col, h) for col, h in headers.items()}
    row_fills = defaultdict(list)
    struck = []
    coloured_text = defaultdict(list)

    def value_of(col, r):
        if ws_values is not None:
            return ws_values[f'{col}{r}'].value
        return ws[f'{col}{r}'].value

    for r in rows:
        # Row-level formatting: the mode across the headed cells, so one
        # manually recoloured cell does not masquerade as a row marking.
        keys = [fill_key(ws[f'{col}{r}']) for col in headers]
        present = [k for k in keys if k]
        if present and len(present) >= max(2, len(keys) // 2):
            row_fills[Counter(present).most_common(1)[0][0]].append(r)

        for col in headers:
            cell = ws[f'{col}{r}']
            sc = scans[col]
            raw = cell.value
            if isinstance(raw, str) and raw.startswith('='):
                sc.formula_cells += 1
                if sc.formula_sample is None:
                    sc.formula_sample = raw[:80]
            elif sc.formula_cells and raw not in (None, ''):
                # Somebody typed over the formula. Three rows of the RA's
                # "Full Name" column are hand-typed, which is exactly the kind
                # of thing that silently disagrees with its own formula.
                sc.overtyped.append(r)
            v = value_of(col, r)
            k = fill_key(cell)
            if k:
                sc.fills[k].append(r)
            font = getattr(cell, 'font', None)
            if font is not None:
                if font.strike:
                    struck.append(r)
                fc = getattr(getattr(font, 'color', None), 'rgb', None)
                if isinstance(fc, str) and len(fc) == 8 and fc.upper() not in ('FF000000', '00000000'):
                    coloured_text[f'#{fc[2:].upper()}'].append(r)
            if v in (None, ''):
                continue
            sc.filled += 1
            sc.types[type(v).__name__] += 1
            sc.distinct_all.add(str(v))
            if len(sc.distinct) < _MAX_DISTINCT or str(v) in sc.distinct:
                sc.distinct[str(v)] += 1
            if isinstance(v, str) and v.strip():
                sc.text_values[v.strip()] += 1

    for col, sc in scans.items():
        values = [value_of(col, r) for r in rows]
        if _looks_dateish([v for v in values if v not in (None, '')]):
            _res, summary = dateparse.parse_column(values, today=today)
            # A column where most dates are in the future is a renewal or expiry
            # date, and "future" is not a finding there — it is the column doing
            # its job. Say so, so the wizard can propose that role and stop the
            # review queue filling with 167 perfectly good renewal dates.
            parsed = [r for r in _res if r.date]
            future = [r for r in parsed if r.date > today]
            summary['mostly_future'] = bool(parsed) and len(future) / len(parsed) > 0.5
            if summary['mostly_future']:
                summary['role_hint'] = ('most values are in the future — this looks like a '
                                        'renewal or expiry date, not a payment date')
            sc.date_summary = summary
            # A repeated value that will not parse as a date, in a date column,
            # is a convention somebody adopted — surface it as a question.
            for raw, n in sc.text_values.items():
                if n < _CONVENTION_MIN:
                    continue
                p = dateparse.parse_value(raw, summary.get('convention'), today)
                if p.date is None:
                    sc.conventions.append({
                        'value': raw, 'count': n,
                        'why': 'repeats in a date column but is not a date — '
                               'likely a convention, confirm what it means'})
        else:
            for raw, n in sc.text_values.items():
                if n >= _CONVENTION_MIN and raw.strip().lower() in dateparse.SENTINELS:
                    sc.conventions.append({
                        'value': raw, 'count': n,
                        'why': 'a placeholder value used more than once'})

    # A fill or font colour applied to almost every row is the sheet's house
    # style, not a marking. The RA register sets every row's text to #0000FF;
    # reporting that as a 302-row signal would bury the 4 rows that matter.
    total = max(1, len(rows))
    _DEFAULT_AT = 0.9
    house_style = {
        'row_fills':    [k for k, v in row_fills.items() if len(v) / total >= _DEFAULT_AT],
        'font_colours': [k for k, v in coloured_text.items()
                         if len(set(v)) / total >= _DEFAULT_AT],
    }
    for k in house_style['row_fills']:
        row_fills.pop(k, None)
    for k in house_style['font_colours']:
        coloured_text.pop(k, None)

    return {
        'sheet':        ws.title,
        'house_style':  house_style,
        'header_row':   header_row,
        'data_rows':    len(rows),
        'first_row':    rows[0] if rows else None,
        'last_row':     rows[-1] if rows else None,
        'columns':      [scans[c].as_dict() for c in sorted(scans, key=lambda x: (len(x), x))],
        'row_fills':    {k: {'count': len(v), 'rows': v} for k, v in row_fills.items()},
        'strikethrough': sorted(set(struck)),
        'font_colours': {k: {'count': len(set(v)), 'rows': sorted(set(v))}
                         for k, v in coloured_text.items()},
    }
