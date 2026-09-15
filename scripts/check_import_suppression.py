#!/usr/bin/env python3
"""Assert that every import endpoint that WRITES runs with events suppressed.

Plan §8.1 says the suppression "must be explicit and tested rather than
assumed". A unit test proves the boundary works; it cannot prove somebody has
not since added a fourth import route without it. This can.

WHAT COUNTS AS AN IMPORT ROUTE
------------------------------
Not "the path contains /import/". That was the first rule here and it was
lazy: it flagged /import/scan, /import/households and /import/profiles, none
of which touches member data. Three false alarms on a check that exists to be
believed is worse than no check — the v12.85 lesson about a review queue that
cries wolf applies to linters too.

The rule is what the code DOES: a route that writes to a member-data table
must run inside a suppression context, because that write is what a Phase 2
event handler would react to. A route that only reads a spreadsheet, or writes
configuration, has nothing to suppress and is left alone.

    python3 scripts/check_import_suppression.py .

Exit status 1 if any writing import route is unguarded.
"""
import ast
import os
import re
import sys

# Tables whose rows represent MEMBERS and their history. A write to any of
# these is what an automation rule reacts to, so an import touching them must
# be suppressed. Writes to configuration tables (import_profiles, settings,
# field_definitions) are not member events and need no boundary.
MEMBER_DATA_TABLES = {
    'members', 'member_contacts', 'member_payments', 'member_field_values',
    'member_groups', 'member_group_members', 'member_sessions', 'member_flags',
    'attendance', 'attendance_history', 'member_tags', 'member_notes',
}

_WRITE_RE = re.compile(
    r'\b(?:INSERT\s+(?:OR\s+\w+\s+)?INTO|UPDATE|DELETE\s+FROM)\s+["\'`\[]?(\w+)',
    re.I)


def _route_paths(node):
    """(path, methods) for every @bp.route on this function."""
    out = []
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        fn = dec.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, 'id', '')
        if name != 'route' or not dec.args:
            continue
        path = dec.args[0].value if isinstance(dec.args[0], ast.Constant) else ''
        methods = []
        for kw in dec.keywords:
            if kw.arg == 'methods' and isinstance(kw.value, (ast.List, ast.Tuple)):
                methods = [e.value for e in kw.value.elts if isinstance(e, ast.Constant)]
        out.append((path, methods or ['GET']))
    return out


def _has_suppression(node):
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, 'id', '')
        if name == 'suppressed_import':
            return True
    return False


def _direct_writes(node):
    """Member-data tables written by SQL literals in this function itself."""
    hit = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            for table in _WRITE_RE.findall(sub.value):
                if table.lower() in MEMBER_DATA_TABLES:
                    hit.add(table.lower())
    return hit


def _calls(node):
    """Names of functions this one calls (bare names and attribute calls)."""
    out = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


def _effective_writes(name, direct, calls, seen=None):
    """What a route writes INCLUDING through the helpers it calls.

    api_import_run_ayc does not contain a single INSERT: it delegates to
    _ayc_import_members, _ayc_import_attendance and _ayc_import_payments. That
    is the normal way to structure a handler, so a checker that only looks
    inside the route function misses most real cases — and silently, which is
    the worst way to miss one. Follow the call graph within the module.
    """
    seen = seen if seen is not None else set()
    if name in seen:
        return set()
    seen.add(name)
    out = set(direct.get(name, ()))
    for callee in calls.get(name, ()):
        out |= _effective_writes(callee, direct, calls, seen)
    return out


def check_file(path):
    try:
        src = open(path, encoding='utf-8').read()
        tree = ast.parse(src, path)
    except (SyntaxError, UnicodeDecodeError):
        return [], []
    direct, calls, funcs = {}, {}, {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[node.name] = node
            direct[node.name] = _direct_writes(node)
            calls[node.name] = _calls(node)

    guarded, unguarded = [], []
    for name, node in funcs.items():
        routes = _route_paths(node)
        if not routes:
            continue
        if not any('POST' in [m.upper() for m in methods] for _r, methods in routes):
            continue
        if '/import/' not in routes[0][0]:
            continue
        tables = _effective_writes(name, direct, calls)
        if not tables:
            continue          # reads a file, or writes configuration — nothing to suppress
        entry = (os.path.basename(path), routes[0][0], name, sorted(tables))
        (guarded if _has_suppression(node) else unguarded).append(entry)
    return guarded, unguarded


def main(root):
    skip = {'venv', 'venv 2', 'venv3', '__pycache__', '.git', 'node_modules'}
    g_all, u_all = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for f in sorted(filenames):
            if f.endswith('.py'):
                g, u = check_file(os.path.join(dirpath, f))
                g_all += g
                u_all += u
    for f, route, name, tables in g_all:
        print(f'  ok        {route}  ({name}) writes {", ".join(tables)}')
    for f, route, name, tables in u_all:
        print(f'  UNGUARDED {route}  ({name}) in {f} writes {", ".join(tables)} '
              f'— needs @suppressed_import')
    print(f'\n{len(g_all)} guarded, {len(u_all)} unguarded.')
    if not g_all and not u_all:
        print('No import routes found at all — has the route path changed?')
        return 1
    return 1 if u_all else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else '.'))
