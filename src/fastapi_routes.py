"""Extract literal FastAPI route-boundary contracts without importing apps.

Router, decorator and argument-default dependencies are all considered. Unknown
dependencies remain unresolved, not evidence that an endpoint is unrestricted.
Endpoint bodies and application startup are never executed or certified.
"""
from __future__ import annotations

import ast

from native_casbin import AdmissionError, MAX_TEXT_BYTES


VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}
GUARDS = {"require_permission", "require_scope", "require_role"}


def _parse(source):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("router source exceeds its envelope", "inconclusive")
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("router source does not parse", "invalid") from error


def _string(node):
    if not isinstance(node, ast.Constant) or type(node.value) is not str or len(node.value) > 256:
        raise AdmissionError("routing value requires a bounded source string literal")
    return node.value


def _keywords(call):
    values = {item.arg: item.value for item in call.keywords}
    if None in values or len(values) != len(call.keywords):
        raise AdmissionError("expanded or duplicate routing keywords need a separate conversion")
    return values


def extract_router(source: bytes, module: str) -> dict:
    tree = _parse(source)
    router_types, depends_names, security_names, field_names, guards = set(), set(), set(), set(), {}
    writes = {}
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                name = alias.asname or alias.name
                writes[name] = writes.get(name, 0) + 1
                if statement.module == "fastapi" and statement.level == 0:
                    if alias.name == "APIRouter":
                        router_types.add(name)
                    if alias.name == "Depends":
                        depends_names.add(name)
                    if alias.name == "Security":
                        security_names.add(name)
                    if alias.name in ("Query", "Path", "Body", "Header", "Cookie", "Form", "File"):
                        field_names.add(name)
                elif alias.name in GUARDS:
                    guards[name] = {"factory": alias.name, "module": statement.module,
                                    "level": statement.level, "line": statement.lineno}
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            writes[statement.name] = writes.get(statement.name, 0) + 1
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    writes[target.id] = writes.get(target.id, 0) + 1
    if any(writes.get(name) != 1 for name in router_types | depends_names | security_names | field_names | set(guards)):
        raise AdmissionError("routing primitive has an ambiguous module binding")

    def dependency(node):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in depends_names and len(node.args) == 1 and not node.keywords):
            return None, {"line": node.lineno, "reason": "dependency is not a literal Depends call"}
        expression = node.args[0]
        if (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name)
                and expression.func.id in guards and len(expression.args) == 1 and not expression.keywords):
            try:
                argument = _string(expression.args[0])
            except AdmissionError as error:
                return None, {"line": node.lineno, "reason": str(error)}
            return {**guards[expression.func.id], "argument": argument, "line": node.lineno}, None
        if isinstance(expression, ast.Name) and expression.id in ("get_current_auth", "get_current_key"):
            return {"factory": "validated_auth_boundary", "argument": expression.id, "line": node.lineno}, None
        return None, {"line": node.lineno, "reason": "dependency binding or factory is unresolved"}

    def dependencies(node):
        if node is None:
            return [], []
        if not isinstance(node, (ast.List, ast.Tuple)):
            return [], [{"line": node.lineno, "reason": "dependency list is not literal"}]
        supported, unresolved = [], []
        for value in node.elts:
            item, error = dependency(value)
            if item:
                supported.append(item)
            if error:
                unresolved.append(error)
        return supported, unresolved

    routers = {}
    for statement in tree.body:
        if not (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name) and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Name) and statement.value.func.id in router_types):
            continue
        name, call = statement.targets[0].id, statement.value
        if writes.get(name) != 1 or call.args:
            raise AdmissionError("router construction needs an unambiguous keyword-only binding")
        keywords = _keywords(call)
        prefix = _string(keywords["prefix"]) if "prefix" in keywords else ""
        if prefix and (not prefix.startswith("/") or prefix.endswith("/")):
            raise AdmissionError("router prefix lacks the declared path form")
        supported, unresolved = dependencies(keywords.get("dependencies"))
        routers[name] = {"prefix": prefix, "guards": supported, "unresolved": unresolved}

    routes = []
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in function.decorator_list:
            if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                    and isinstance(decorator.func.value, ast.Name) and decorator.func.value.id in routers
                    and decorator.func.attr in VERBS):
                continue
            router = routers[decorator.func.value.id]
            if len(decorator.args) != 1:
                raise AdmissionError("route path is not one explicit positional literal")
            suffix = _string(decorator.args[0])
            keywords = _keywords(decorator)
            found, unresolved = dependencies(keywords.get("dependencies"))
            found = list(router["guards"]) + found
            unresolved = list(router["unresolved"]) + unresolved
            for default in list(function.args.defaults) + [n for n in function.args.kw_defaults if n is not None]:
                if isinstance(default, ast.Call) and isinstance(default.func, ast.Name) and default.func.id in depends_names:
                    item, error = dependency(default)
                    if item:
                        found.append(item)
                    if error:
                        unresolved.append(error)
                elif isinstance(default, ast.Call) and isinstance(default.func, ast.Name) and default.func.id in security_names:
                    unresolved.append({"line": default.lineno, "reason": "Security dependency requires a separate binding"})
                elif isinstance(default, ast.Call) and not (isinstance(default.func, ast.Name) and default.func.id in field_names):
                    unresolved.append({"line": default.lineno, "reason": "dynamic parameter default may create an unmodeled dependency"})
            # FastAPI also accepts dependencies in typing.Annotated metadata.
            # Ignoring annotations would silently omit these authorization gates.
            for argument in function.args.posonlyargs + function.args.args + function.args.kwonlyargs:
                if argument.annotation is None:
                    continue
                for call in (n for n in ast.walk(argument.annotation) if isinstance(n, ast.Call)):
                    if isinstance(call.func, ast.Name) and call.func.id in depends_names:
                        item, error = dependency(call)
                        if item:
                            found.append(item)
                        if error:
                            unresolved.append(error)
                    elif isinstance(call.func, ast.Name) and call.func.id in security_names:
                        unresolved.append({"line": call.lineno, "reason": "annotated Security dependency requires a separate binding"})
            if len(function.decorator_list) != 1:
                unresolved.append({"line": function.lineno, "reason": "additional decorators have not been modeled"})
            prefix = router["prefix"]
            # One-component router names give an independent resource label,
            # separate from the dependency decoder's split/index expression.
            resource = prefix.strip("/") if prefix and "/" not in prefix.strip("/") else None
            routes.append({"module": module, "function": function.name, "line": function.lineno,
                           "router": decorator.func.value.id, "router_prefix": prefix,
                           "resource_contract": resource, "suffix": suffix,
                           "relative_path": prefix + suffix, "method": decorator.func.attr.upper(),
                           "guards": found, "unresolved": unresolved,
                           "endpoint_body_verified": False})
    if len(routes) > 256:
        raise AdmissionError("route count exceeds source-interface envelope", "inconclusive")
    return {"module": module, "routes": routes, "router_count": len(routers),
            "scope": "declared route dependency boundaries, not endpoint bodies or startup",
            "source_module_executed": False}


def extract_mounts(source: bytes) -> list[dict]:
    tree = _parse(source)
    result = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "include_router" and len(node.args) == 1
                and isinstance(node.args[0], ast.Attribute) and node.args[0].attr == "router"
                and isinstance(node.args[0].value, ast.Name)):
            continue
        keywords = _keywords(node)
        prefix = _string(keywords["prefix"]) if "prefix" in keywords else ""
        inherited, unresolved = [], []
        if "dependencies" in keywords:
            unresolved.append("include_router dependencies require an additional binding")
        result.append({"module_alias": node.args[0].value.id, "prefix": prefix,
                       "line": node.lineno, "unresolved": unresolved,
                       "registration_executed": False})
    return result
