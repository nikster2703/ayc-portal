#!/usr/bin/env python3
"""Find names a function reads but never binds — the NameError linter.

Why this exists
---------------
v12.78 added the primary-contact guard to blueprints/members.py and pasted the
call into api_member_detail(), a GET route with no `new_status` in scope. The
line was both a guard that guarded nothing AND a certain NameError, and it
survived five releases and 122 automated tests because the members UI never
calls that endpoint, so the crash never happened where anyone could see it.

pyflakes would have caught it in a second, but this box has no network and no
linter, so this is the smallest thing that does the same job with the stdlib
alone. Run it in CI, or before a release:

    python3 scripts/check_undefined_names.py .

Exit status is 1 if anything is reported. It is deliberately conservative: it
only reports a name that is read in a function and bound NOWHERE reachable —
not in the function, not in any enclosing function, not at module level, not
imported, not a builtin. False positives should be rare; a real one means the
line either crashes or is dead.
"""
import ast
import builtins
import os
import sys

BUILTINS = set(dir(builtins)) | {'__file__', '__name__', '__doc__', '__all__'}


def _walk_shallow(node):
    """Walk a subtree WITHOUT descending into nested def/class bodies.

    This is the whole trick. A naive ast.walk() over a module-level function
    collects that function's local variables as if they were module globals,
    which makes every misplaced local look defined — and misses precisely the
    bug this script exists to find.
    """
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        for child in ast.iter_child_nodes(n):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                yield child          # the NAME is bound here; the body is not
                continue
            stack.append(child)


def _bound_by(nodes):
    """Every name these statements bind into the scope that contains them."""
    out = set()
    for node in nodes:
        # A def/class statement binds only its own NAME here. Its body belongs
        # to its own scope, and walking into it is exactly the mistake that
        # made the first version of this script report nothing.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
            continue
        for n in _walk_shallow(node):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out.add(n.name)
            elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                out.add(n.id)
            elif isinstance(n, ast.arg):
                out.add(n.arg)
            elif isinstance(n, ast.alias):
                out.add((n.asname or n.name).split('.')[0])
            elif isinstance(n, ast.ExceptHandler) and n.name:
                out.add(n.name)
            elif isinstance(n, (ast.Global, ast.Nonlocal)):
                out.update(n.names)
    return out


def _params(fn):
    a = fn.args
    names = {p.arg for p in a.posonlyargs + a.args + a.kwonlyargs}
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    return names


def check_file(path):
    try:
        src = open(path, encoding='utf-8').read()
        tree = ast.parse(src, path)
    except (SyntaxError, UnicodeDecodeError) as e:
        return [(path, 0, '<parse error>', str(e))]

    problems = []

    def visit(fn, enclosing):
        scope = enclosing | _params(fn) | _bound_by(fn.body)
        for n in _walk_shallow(ast.Module(body=fn.body, type_ignores=[])):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                if n.id not in scope and n.id not in BUILTINS:
                    problems.append((path, n.lineno, fn.name, n.id))
        # Recurse into IMMEDIATE nested functions only, each with its own
        # parent's scope. A deep ast.walk here hands a grandchild the
        # grandparent's scope and reports the middle function's parameters as
        # undefined — the closure in permission_required() is the live example.
        for child in _walk_shallow(ast.Module(body=fn.body, type_ignores=[])):
            if child is not fn and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, scope)

    module = _bound_by(tree.body)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            visit(node, module)
        elif isinstance(node, ast.ClassDef):
            cscope = module | _bound_by(node.body)
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    visit(m, cscope)

    seen, unique = set(), []
    for p, line, fn, name in problems:
        if (fn, name) in seen:
            continue
        seen.add((fn, name))
        unique.append((p, line, fn, name))
    return unique


def main(root):
    skip = {'venv', 'venv 2', 'venv3', '__pycache__', '.git', 'node_modules'}
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for f in sorted(filenames):
            if f.endswith('.py'):
                found += check_file(os.path.join(dirpath, f))
    for path, line, fn, name in found:
        rel = os.path.relpath(path, root)
        print(f'{rel}:{line}: {fn}() reads undefined name {name!r}')
    print(f'\n{len(found)} problem(s).')
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else '.'))
