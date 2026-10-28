"""Conservative direct-import binding checks for source-slice consumers.

Checks source syntax only. This is not a theorem about import hooks, arbitrary
module initialization, monkey-patching or runtime dependency overrides.
"""
import ast

from native_casbin import AdmissionError, MAX_TEXT_BYTES


def require_import_bindings(source, expected):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("binding source exceeds byte envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("binding source does not parse", "invalid") from error
    direct, writes, unsafe = {}, {}, []

    def walk(statement, unconditional=True):
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            writes[statement.name] = writes.get(statement.name, 0) + 1
            return
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            for alias in statement.names:
                if alias.name == "*":
                    unsafe.append("wildcard import")
                    continue
                local = alias.asname or (alias.name.split(".")[0] if isinstance(statement, ast.Import) else alias.name)
                writes[local] = writes.get(local, 0) + 1
                if local in expected:
                    actual = ((statement.module, statement.level, alias.name) if isinstance(statement, ast.ImportFrom)
                              else (alias.name, 0, None))
                    if not unconditional:
                        unsafe.append("conditional import for " + local)
                    direct[local] = actual
            return
        if isinstance(statement, ast.Name) and isinstance(statement.ctx, (ast.Store, ast.Del)):
            writes[statement.id] = writes.get(statement.id, 0) + 1
        if isinstance(statement, ast.Attribute) and isinstance(statement.ctx, (ast.Store, ast.Del)):
            base = statement.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id in expected:
                unsafe.append("mutation of imported primitive " + base.id)
        for child in ast.iter_child_nodes(statement):
            walk(child, False)
    for node in tree.body:
        walk(node)
    if unsafe:
        raise AdmissionError("source binding is not static: " + "; ".join(unsafe[:4]))
    for name, binding in expected.items():
        if direct.get(name) != tuple(binding) or writes.get(name) != 1:
            raise AdmissionError("missing, ambiguous or rebound source import: " + name)
    return {"verified_direct_imports": {name: list(value) for name, value in expected.items()},
            "runtime_import_hooks_or_monkey_patches_verified": False}


def require_static_class_members(cls, members):
    """Reject static class-body rebindings hidden behind conditional syntax.

    Instance initialization, arbitrary top-level effects and monkey patches are
    not executed or proved by this syntactic check.
    """
    counts = {name: 0 for name in members}
    pending = list(cls.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in {"__getattribute__", "__getattr__", "__setattr__"}:
                raise AdmissionError("dynamic source class attributes need a separate binding contract")
            if node.name in counts:
                counts[node.name] += 1
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in counts:
            raise AdmissionError("source class rebinds a selected member: " + node.id)
        pending.extend(ast.iter_child_nodes(node))
    if any(count != 1 for count in counts.values()):
        raise AdmissionError("selected source class members must have one unmodified declaration")


def require_static_definitions(tree, names, reserved=()):
    """Require unique direct definitions, excluding nested function scopes.

    This rejects syntactic module rebindings; arbitrary initialization effects
    or runtime monkey patches remain outside this check.
    """
    direct = {node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    counts = {name: 0 for name in [*names, *reserved]}
    def visit(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in counts:
                counts[node.name] += 1
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in counts:
            counts[node.id] += 1
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                if local in counts:
                    counts[local] += 1
        for child in ast.iter_child_nodes(node):
            visit(child)
    for statement in tree.body:
        visit(statement)
    if not set(names) <= direct or any(counts[name] != 1 for name in names) or any(counts[name] != 0 for name in reserved):
        raise AdmissionError("selected module definitions must be direct and unmodified")
