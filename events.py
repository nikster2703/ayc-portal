"""
AYC Portal — automation events and the import suppression boundary.

Introduced in v12.85 (Phase 1b of the Automations & Member Groups plan), ahead
of the Phase 2 automation engine that will consume these events.

WHY THIS EXISTS BEFORE THE THING IT GUARDS
------------------------------------------
Migrating the Residents Association off their spreadsheet means importing ~300
members together with their historic payment dates — payments made one and two
years ago. The moment Phase 2 adds `payment.recorded`, an import that emits one
event per row would advance every renewal date and queue hundreds of emails to
real people about money they paid in 2025.

The plan calls that the highest-severity risk in the whole project (§8.1), and
the fix is not to remember to suppress events later. It is for the event system
to be BORN suppressed inside an import, with a test that proves it, so no future
emitter can be added without passing through this boundary.

DESIGN
------
  * Suppression is thread-local. A long import running in one request must not
    silence events in another request being served concurrently — gunicorn runs
    threads, and a global flag would do exactly that.
  * Suppression is a CONTEXT MANAGER, not a flag anyone sets and forgets. It
    cannot be left on by an exception part-way through an import.
  * Suppressed events are COUNTED, not silently dropped. An import that says
    "312 automation events suppressed" is auditable; one that says nothing is
    indistinguishable from an import that never tried.
  * fire_event dispatches to registered handlers. The registry is empty until
    Phase 2, so today this changes no behaviour at all — which is the point:
    the boundary is in place and tested before there is anything to leak.
"""

import threading
from contextlib import contextmanager
from functools import wraps

__all__ = [
    'fire_event', 'events_suppressed', 'suppress_events', 'suppressed_import',
    'current_suppression', 'register_handler', 'clear_handlers',
    'SuppressionRecord',
]

_state = threading.local()

# event name -> [handler(db, event, member_id, payload), ...]
_HANDLERS = {}


class SuppressionRecord:
    """What an import suppressed, for its report and for the audit trail."""

    def __init__(self, reason):
        self.reason = reason
        self.count = 0
        self.by_event = {}

    def _record(self, event):
        self.count += 1
        self.by_event[event] = self.by_event.get(event, 0) + 1

    def summary(self):
        if not self.count:
            return 'No automation events were raised.'
        parts = ', '.join(f'{n}× {e}' for e, n in sorted(self.by_event.items()))
        return f'{self.count} automation event(s) suppressed ({parts}).'

    def __repr__(self):
        return f'<SuppressionRecord {self.reason}: {self.count}>'


def _stack():
    if not hasattr(_state, 'stack'):
        _state.stack = []
    return _state.stack


def events_suppressed():
    """Is the CURRENT THREAD inside a suppression context?"""
    return bool(_stack())


@contextmanager
def suppress_events(reason):
    """Suppress automation events for the duration of the block.

    Nests: an inner context does not re-enable events when it exits, and every
    suppressed event is recorded against every active record, so an outer import
    report still sees what an inner helper tried to raise.

    Always use this rather than setting a flag. An import that raises half way
    through must not leave events switched off for the rest of the process.
    """
    record = SuppressionRecord(reason)
    _stack().append(record)
    try:
        yield record
    finally:
        _stack().pop()


def register_handler(event, fn):
    """Phase 2 wires the automation engine in here."""
    _HANDLERS.setdefault(event, []).append(fn)


def clear_handlers():
    """Test helper — drop every registered handler."""
    _HANDLERS.clear()


def fire_event(db, event, member_id=None, payload=None):
    """Raise an automation event. Returns True if it was dispatched.

    Returns False — and dispatches to nobody — when the calling thread is inside
    a suppression context. Callers must not work around a False return: it means
    a human deliberately asked for this work to be silent.
    """
    stack = _stack()
    if stack:
        for record in stack:
            record._record(event)
        return False

    for fn in _HANDLERS.get(event, ()):
        fn(db, event, member_id, payload)
    return True


def current_suppression():
    """The innermost active SuppressionRecord, or None.

    An import handler uses this to put the suppressed count into its report.
    """
    stack = _stack()
    return stack[-1] if stack else None


def suppressed_import(reason):
    """Decorator — run a whole import endpoint with events suppressed.

    Applied to the route function rather than wrapped around the row loop on
    purpose. These handlers are several hundred lines with many early returns,
    and a boundary that covers everything including the error paths is the only
    kind that cannot be got subtly wrong later by someone adding a branch.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            with suppress_events(reason):
                return fn(*args, **kwargs)
        return wrapper
    return decorator
