"""
AYC Portal — propose household groupings from a spreadsheet, for a human to confirm.

Introduced in v12.86 (Phase 1b). Implements plan §7.3: use ALL FOUR signals,
because no single one is sufficient and each finds groupings the others miss.

    Surname + road clustering .... 47 members
    Household / "paid by" notes .. 29
    £0 fee ....................... 11
    Shared email address ......... 6  (all already covered by the above)
    Union ........................ 60 of 285

THIS MODULE NEVER MERGES ANYTHING
---------------------------------
It returns PROPOSALS. Every one is confirmed by a person before a group exists.
That is not timidity: deciding that two people at one address share a membership
is deciding who owes money and who gets the renewal letter, and an address is
not evidence of a household. Postcodes cover many addresses, flats and annexes
share a street, and two people at one address may legitimately hold two
memberships. The plan's standing rule — where money or a relationship changes,
the system flags and a human decides — is exactly this case.

BLIND SPOTS ARE OUTPUT, NOT SILENCE
-----------------------------------
Members the signals cannot reach are reported as blind spots rather than
quietly left alone: a "paid by" note naming somebody the sheet does not
contain, and members with no road name at all, who are invisible to clustering.
The plan puts the treasurer's review at about half an hour, which only holds if
she is told where the gaps are instead of discovering them next renewal.
"""

import re
import unicodedata
from collections import defaultdict

__all__ = ['propose_households', 'normalise_name', 'normalise_road', 'Proposal']

# "Family membership paid by Sue", "Same household as Jan Sivelle",
# "Household membership with LAURA CHILDS - paid by Laura"
_PAID_BY   = re.compile(r'\bpaid\s+by\s+([A-Za-zÀ-ɏ\'’.\- ]+)', re.I)
_WITH_WHOM = re.compile(r'\b(?:same household as|household membership with|'
                        r'family membership with|household with)\s+'
                        r'([A-Za-zÀ-ɏ\'’.\- ]+)', re.I)
_HOUSEHOLD_HINT = re.compile(r'family membership|household|same household|paid by', re.I)
# Words that follow "paid by" in the RA register and are NOT people: the column
# doubles as a payment-method note. Without this, "Paid by Bank Transfer" is
# read as a member called Bank Transfer who cannot be found, and Steve Wherlock
# — correctly grouped by two other signals — is reported as a blind spot.
_NOT_A_PERSON = re.compile(
    r'^(bank\s*transfer|bt|cash|cheque|check|paypal|card|tap|izettle|i-zettle|'
    r'bacs|standing\s*order|direct\s*debit|so|dd|online|phone|post)\b', re.I)
# A note only implies a household if it says so in words. "Paid by cash" does not.
_REAL_HOUSEHOLD = re.compile(r'family membership|household', re.I)
# Where a captured name ENDS. The character class has to allow spaces (people
# have two names) and hyphens (Smith-Jones), which makes it swallow the rest of
# the note: "with LAURA CHILDS - paid by Laura" captured all nine words and
# matched nobody, so a member who WAS in the sheet came back as a blind spot.
_NAME_END = re.compile(r'\s*(?:[,/;()]|\s-\s|\bpaid\b|\band\b|\bwho\b|\bvia\b|\bon\b)', re.I)

_ROAD_SUFFIX = {
    'road': 'rd', 'rd': 'rd', 'street': 'st', 'st': 'st', 'avenue': 'ave',
    'ave': 'ave', 'av': 'ave', 'lane': 'ln', 'ln': 'ln', 'close': 'cl',
    'cl': 'cl', 'drive': 'dr', 'dr': 'dr', 'way': 'way', 'park': 'park',
    'gardens': 'gdns', 'gdns': 'gdns', 'crescent': 'cres', 'cres': 'cres',
    'court': 'ct', 'ct': 'ct', 'place': 'pl', 'pl': 'pl', 'grove': 'gr',
    'terrace': 'terr', 'walk': 'walk', 'rise': 'rise', 'hill': 'hill',
}


def _fold(s):
    """Casefold and flatten the punctuation that splits identical names.

    The RA register contains both "O'Brien" (U+0027) and "O’Brien" (U+2019).
    To a human those are one family; to a dictionary key they are two, which is
    how a household silently fails to cluster.
    """
    if s is None:
        return ''
    s = unicodedata.normalize('NFKD', str(s))
    s = ''.join(c for c in s if not unicodedata.combining(c))
    s = s.replace('’', "'").replace('‘', "'").replace('`', "'")
    return re.sub(r'[^a-z0-9 ]+', '', s.lower()).strip()


def normalise_name(s):
    return re.sub(r'\s+', ' ', _fold(s))


def normalise_road(s):
    """Fold a road name so "Doris Road" and "doris rd" are one key."""
    t = normalise_name(s)
    if not t:
        return ''
    parts = t.split()
    if parts and parts[-1] in _ROAD_SUFFIX:
        parts[-1] = _ROAD_SUFFIX[parts[-1]]
    return ' '.join(parts)


class Proposal:
    """A suggested household. Nothing exists until a person confirms it."""

    __slots__ = ('member_rows', 'signals', 'evidence', 'suggested_name',
                 'suggested_primary', 'flagged')

    def __init__(self, member_rows, signals, evidence, suggested_name=None,
                 suggested_primary=None):
        self.member_rows = sorted(member_rows)
        self.signals = sorted(signals)
        self.evidence = evidence
        self.suggested_name = suggested_name
        self.suggested_primary = suggested_primary
        self.flagged = []

    @property
    def confidence(self):
        """How many independent signals agree. Not a probability — a count.

        Presenting a made-up percentage would invite people to accept anything
        over 80%. A count of agreeing signals is something a treasurer can
        actually reason about.
        """
        return len(self.signals)

    def as_dict(self):
        return {
            'member_rows':       self.member_rows,
            'signals':           self.signals,
            'signal_count':      self.confidence,
            'evidence':          self.evidence,
            'suggested_name':    self.suggested_name,
            'suggested_primary': self.suggested_primary,
            'flagged_rows':      self.flagged,
        }

    def __repr__(self):
        return f'<Proposal rows={self.member_rows} signals={self.signals}>'


class _Union:
    """Union-find, so signals combine instead of competing."""

    def __init__(self):
        self.parent = {}

    def find(self, a):
        self.parent.setdefault(a, a)
        while self.parent[a] != a:
            self.parent[a] = self.parent[self.parent[a]]
            a = self.parent[a]
        return a

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def propose_households(rows, flagged_rows=None):
    """(proposals, blind_spots, stats) from a list of member dicts.

    Each row needs at least: row, first_name, surname. Optional and used when
    present: road, postcode, email, fee, paid, notes.

    flagged_rows: spreadsheet rows that sheetscan found struck through, or whose
    notes mark them deceased or duplicate. They still JOIN their household — the
    payment history is theirs and the group owns it — but they are never
    suggested as the primary contact.

    That guard is not theoretical. Run without it on the RA register, this
    proposed Margaret Robinson as primary contact of the Robinson household: a
    row that is struck through and annotated "signed up twice". The household
    also contains Keith, struck through and annotated "Deceased". Suggesting
    either as the person who receives the renewal letter is the exact failure
    v12.83 and v12.84 were spent preventing, arriving through the import instead
    of through the UI.
    """
    flagged_rows = set(flagged_rows or ())
    by_row = {r['row']: r for r in rows}
    uf = _Union()
    signals = defaultdict(set)      # row -> {signal names}
    evidence = defaultdict(list)

    def link(a, b, signal, why):
        if a == b or a not in by_row or b not in by_row:
            return
        uf.union(a, b)
        signals[a].add(signal)
        signals[b].add(signal)
        evidence[uf.find(a)].append(why)

    # ── Signal 1: surname + road ─────────────────────────────────────────────
    clusters = defaultdict(list)
    for r in rows:
        road = normalise_road(r.get('road'))
        sur = normalise_name(r.get('surname'))
        if sur and road:
            clusters[(sur, road)].append(r['row'])
    for (sur, road), members in clusters.items():
        if len(members) > 1:
            for m in members[1:]:
                link(members[0], m, 'surname+road',
                     f'same surname and road: {sur.title()}, {road.title()}')

    # ── Signal 2: shared email ───────────────────────────────────────────────
    emails = defaultdict(list)
    for r in rows:
        e = (r.get('email') or '').strip().lower()
        if e and '@' in e:
            emails[e].append(r['row'])
    for e, members in emails.items():
        if len(members) > 1:
            for m in members[1:]:
                link(members[0], m, 'shared-email', f'shared email address: {e}')

    # ── Signal 3: a note naming the other person ─────────────────────────────
    # Built from FIRST names as well as full names, because the notes say
    # "paid by Sue", not "paid by Sue Kielty".
    by_full, by_first = defaultdict(list), defaultdict(list)
    for r in rows:
        full = normalise_name(f"{r.get('first_name','')} {r.get('surname','')}")
        if full:
            by_full[full].append(r['row'])
        f = normalise_name(r.get('first_name'))
        if f:
            by_first[f].append(r['row'])

    unresolved_notes = []
    for r in rows:
        note = r.get('notes') or ''
        if not _HOUSEHOLD_HINT.search(note):
            continue
        named = None
        for pat in (_WITH_WHOM, _PAID_BY):
            m = pat.search(note)
            if m:
                candidate = m.group(1).strip()
                cut = _NAME_END.search(candidate)
                if cut:
                    candidate = candidate[:cut.start()].strip()
                if not candidate or _NOT_A_PERSON.match(candidate):
                    continue          # a payment method, not a housemate
                named = normalise_name(candidate)
                break
        # "Paid by cheque" is not a household signal, and must not be reported
        # as one that failed to resolve.
        if not named and not _REAL_HOUSEHOLD.search(note):
            continue
        signals[r['row']].add('note')
        if not named:
            continue
        target = None
        if named in by_full:
            target = by_full[named][0]
        else:
            # A first name alone is only safe when it is unique in the sheet,
            # or unique among people sharing this member's road.
            cands = by_first.get(named, [])
            same_road = [c for c in cands
                         if normalise_road(by_row[c].get('road')) ==
                            normalise_road(r.get('road')) and normalise_road(r.get('road'))]
            if len(same_road) == 1:
                target = same_road[0]
            elif len(cands) == 1:
                target = cands[0]
        if target is not None and target == r['row']:
            # "Family Membership - paid by Sue" written on Sue's own row. She
            # paid; there is nothing unresolved and nothing to report.
            continue
        if target is not None:
            link(r['row'], target, 'note', f'note names {named.title()}: "{note.strip()}"')
        else:
            unresolved_notes.append({
                'row': r['row'],
                'name': f"{r.get('first_name','')} {r.get('surname','')}".strip(),
                'note': note.strip(),
                'why': ('names somebody not found in the sheet' if named
                        else 'says household but names nobody'),
            })

    # ── Signal 4: £0 / blank fee against a recorded payment ──────────────────
    # On its own this only says "somebody else paid" — it never says who, so it
    # can bind nothing. It marks the member, and is reported separately when no
    # other signal reached them.
    zero_fee = []
    for r in rows:
        fee, paid = r.get('fee'), r.get('paid')
        if paid not in (None, '') and (fee in (None, '', 0) or fee == 0.0):
            signals[r['row']].add('zero-fee')
            zero_fee.append(r['row'])

    # ── Assemble ─────────────────────────────────────────────────────────────
    groups = defaultdict(list)
    for row in by_row:
        groups[uf.find(row)].append(row)

    proposals = []
    for root, members in groups.items():
        if len(members) < 2:
            continue
        sigs = set()
        for m in members:
            sigs |= {s for s in signals[m] if s != 'zero-fee'}
        if 'zero-fee' in {s for m in members for s in signals[m]}:
            sigs.add('zero-fee')
        recs = [by_row[m] for m in members]
        sur = normalise_name(recs[0].get('surname')).title()
        road = recs[0].get('road') or ''
        name = f'{sur} — {road}'.strip(' —') or sur or f'Household (row {min(members)})'
        # Suggest the payer as primary: the one whose fee was actually recorded,
        # never a flagged row, and never somebody with no way of being contacted.
        eligible = [m for m in sorted(members) if m not in flagged_rows]
        payer = next((m for m in eligible if by_row[m].get('fee') not in (None, '', 0)), None)
        if payer is None:
            payer = next((m for m in eligible if (by_row[m].get('email') or '').strip()), None)
        if payer is None:
            payer = eligible[0] if eligible else None
        prop = Proposal(members, sigs, evidence.get(root, []), name, payer)
        prop.flagged = sorted(set(members) & flagged_rows)
        if prop.flagged and payer is None:
            prop.evidence.append('every member of this household is flagged — '
                                 'no primary contact can be suggested')
        elif prop.flagged:
            prop.evidence.append(
                f'row(s) {prop.flagged} are struck through or marked deceased/duplicate '
                f'and were excluded from the primary-contact suggestion')
        proposals.append(prop)

    proposals.sort(key=lambda p: (-p.confidence, p.member_rows))

    grouped = {m for p in proposals for m in p.member_rows}
    blind_spots = {
        'notes_naming_someone_absent': unresolved_notes,
        'zero_fee_not_grouped': [
            {'row': r, 'name': f"{by_row[r].get('first_name','')} "
                               f"{by_row[r].get('surname','')}".strip(),
             'why': 'no fee recorded against a payment, but no other signal reached them'}
            for r in zero_fee if r not in grouped],
        'no_road_name': [
            {'row': r['row'], 'name': f"{r.get('first_name','')} {r.get('surname','')}".strip(),
             'why': 'no road name — invisible to surname+road clustering'}
            for r in rows if not normalise_road(r.get('road'))],
    }
    stats = {
        'members':            len(rows),
        'proposals':          len(proposals),
        'members_in_proposals': len(grouped),
        'single_member_households': len(rows) - len(grouped),
        'by_signal': {
            s: len([p for p in proposals if s in p.signals])
            for s in ('surname+road', 'shared-email', 'note', 'zero-fee')},
        'blind_spots': {k: len(v) for k, v in blind_spots.items()},
    }
    return proposals, blind_spots, stats
