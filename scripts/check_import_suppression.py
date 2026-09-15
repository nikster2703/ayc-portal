#!/usr/bin/env python3
"""Assert that every import endpoint that WRITES runs with events suppressed.

Plan §8.1 says the suppression "must be explicit and tested rather than
assumed". A unit test proves the boundary works; it cannot prove somebody has
not since added a fourth import route without it. This can.

An import route is any POST route whose path contains "/import/" and which is
not an analyse/preview step. Each one must carry @suppressed_import(...).

    python3 scripts/check_import_suppression.py .

Exit status 1 if any writing import route is unguarded.
"""
import ast
import os
import sys

READ_ONLY_HINTS = ('/analyse', '/fields', '/report', '/preview', '/template')


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


def check_file(path):
    try:
        tree = ast.parse(open(path, encoding='utf-8').read(), path)
    except (SyntaxError, UnicodeDecodeError):
        return [], []
    guarded, unguarded = [], []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for route, methods in _route_paths(node):
            if '/import/' not in route:
                continue
            if 'POST' not in [m.upper() for m in methods]:
                continue
            if any(h in route for h in READ_ONLY_HINTS):
                continue
            (guarded if _has_suppression(node) else unguarded).append(
                (os.path.basename(path), route, node.name))
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
    for f, route, name in g_all:
        print(f'  ok        {route}  ({name})')
    for f, route, name in u_all:
        print(f'  UNGUARDED {route}  ({name}) in {f} — needs @suppressed_import')
    print(f'\n{len(g_all)} guarded, {len(u_all)} unguarded.')
    if not g_all and not u_all:
        print('No import routes found at all — has the route path changed?')
        return 1
    return 1 if u_all else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else '.'))
