"""Discover a source-rooted file constructor and pure three-argument sink.

The caller supplies an archive and an ordered method interface contract, not
module paths, class names, model paths or parameter-name maps. Source bytes are
parsed only. Import roots, __file__, builtins, startup and mutation-free use are
explicit source-slice premises, not certificates of a running application.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath
import re

from native_casbin import AdmissionError, MAX_NATIVE_WORK
from native_literal_policy import admit_native_literals
from native_runtime import engine_identity
from public_inputs import translate
from python_wrapper import compare_wrapper, dotted, extract_wrapper
from rest_source_chain import SourceArchive
from source_bindings import require_import_bindings, require_static_class_members, require_static_definitions


_UNKNOWN = object()


def _body(node):
    rows = list(node.body)
    if rows and isinstance(rows[0], ast.Expr) and isinstance(rows[0].value, ast.Constant) and type(rows[0].value.value) is str:
        rows.pop(0)
    return rows


def _tree(raw):
    try:
        return ast.parse(raw)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("potential source constructor does not parse", "invalid") from error


@dataclass(frozen=True)
class _SourcePath:
    path: PurePosixPath


def _path_value(node, environment, member, depth=0):
    if depth > 32:
        raise AdmissionError("source-rooted path exceeds the bounded grammar", "inconclusive")
    resolve = lambda n: _path_value(n, environment, member, depth + 1)
    if isinstance(node, ast.Name):
        if node.id == "__file__":
            return _SourcePath(PurePosixPath("/archive") / member)
        if node.id not in environment or environment[node.id] is _UNKNOWN:
            raise AdmissionError("path construction reads an unresolved value")
        return environment[node.id]
    if isinstance(node, ast.Constant) and type(node.value) is str:
        SourceArchive._safe(node.value)
        return node.value
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        parent = resolve(node.value)
        if isinstance(parent, _SourcePath) and parent.path.parent.is_relative_to(PurePosixPath("/archive")):
            return _SourcePath(parent.path.parent)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left, right = resolve(node.left), resolve(node.right)
        if isinstance(left, _SourcePath) and type(right) is str:
            SourceArchive._safe(right)
            return _SourcePath(left.path / right)
    if isinstance(node, ast.Call) and not node.keywords:
        if dotted(node.func) == "Path" and len(node.args) == 1:
            value = resolve(node.args[0])
            if isinstance(value, _SourcePath):
                return value
        if dotted(node.func) == "str" and len(node.args) == 1:
            value = resolve(node.args[0])
            if isinstance(value, _SourcePath):
                return value
        if isinstance(node.func, ast.Attribute) and node.func.attr == "resolve" and not node.args:
            value = resolve(node.func.value)
            if isinstance(value, _SourcePath):
                return value
    raise AdmissionError("only literal, source-rooted Path construction is admitted")


def _constructor(raw, cls):
    if cls.bases or cls.keywords or cls.decorator_list:
        raise AdmissionError("inherited or decorated constructors require another source contract")
    tree = _tree(raw)
    require_static_definitions(tree, [cls.name])
    require_import_bindings(raw, {"casbin": ("casbin", 0, None)})
    initializers = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__"]
    if len(initializers) != 1:
        raise AdmissionError("native class lacks a unique initializer")
    init = initializers[0]
    a = init.args
    names = [arg.arg for arg in a.args]
    if (len(names) != 3 or names[0] != "self" or len(set(names)) != 3 or a.posonlyargs or a.kwonlyargs
            or a.vararg or a.kwarg or init.decorator_list
            or any(not isinstance(n, ast.Constant) or n.value is not None for n in a.defaults)):
        raise AdmissionError("constructor needs two directly supplied distinct file arguments")
    statements = _body(init)
    if len(statements) != 1 or not isinstance(statements[0], ast.Assign) or len(statements[0].targets) != 1:
        raise AdmissionError("constructor has more than the direct native assignment")
    assignment = statements[0]
    target, call = assignment.targets[0], assignment.value
    if (not isinstance(target, ast.Attribute) or not isinstance(target.value, ast.Name) or target.value.id != "self"
            or not isinstance(call, ast.Call) or dotted(call.func) != "casbin.Enforcer" or call.keywords
            or len(call.args) != 2 or any(not isinstance(arg, ast.Name) for arg in call.args)
            or [arg.id for arg in call.args] != names[1:]):
        raise AdmissionError("constructor argument-to-native-file flow is not direct and ordered")
    for node in cls.body:
        if ((isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == target.attr)
                or any(isinstance(value, ast.Name) and value.id == target.attr and isinstance(value.ctx, (ast.Store, ast.Del))
                    for value in ast.walk(node) if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))):
            raise AdmissionError("native receiver conflicts with a class-level descriptor or value")
    methods = []
    for method in cls.body:
        if not isinstance(method, ast.FunctionDef) or method.name == "__init__":
            continue
        if not any(isinstance(n, ast.Call) and dotted(n.func) == "self." + target.attr + ".enforce" for n in ast.walk(method)):
            continue
        parameters = [arg.arg for arg in method.args.args]
        if len(parameters) != 4 or parameters[0] != "self":
            raise AdmissionError("native decision method is outside the ordered three-argument interface")
        selector = cls.name + "." + method.name
        descriptor = extract_wrapper(raw, selector, parameters[1:], "self." + target.attr)
        methods.append({"selector": selector, "parameters": parameters[1:], "extraction": descriptor})
    if not methods:
        raise AdmissionError("class has no admitted pure three-argument decision method", "unsupported")
    if len(methods) > 64:
        raise AdmissionError("pure native method inventory exceeds its envelope", "inconclusive")
    require_static_class_members(cls, ["__init__", *[row["selector"].split(".")[-1] for row in methods]])
    return {"class": cls.name, "initializer_lines": [init.lineno, init.end_lineno], "engine_attribute": target.attr, "methods": methods}


def _exported_class(bundle, module, symbol, target_member, class_name):
    stem = module.replace(".", "/")
    possible = [name for name in bundle.members if name in (stem + ".py", stem + "/__init__.py")
        or name.endswith("/" + stem + ".py") or name.endswith("/" + stem + "/__init__.py")]
    if not possible:
        raise AdmissionError("import module has no source-root candidate", "missing_input")
    bound = set()
    # Multiple search-root interpretations are allowed only if EVERY candidate
    # resolves to the exact same source class (e.g. file and package re-export).
    # Selecting whichever root happens to produce agreement is never allowed.
    for selected in possible:
        raw = bundle.read(selected)
        bound.add(selected)
        if selected == target_member and symbol == class_name:
            continue
        if not selected.endswith("/__init__.py"):
            raise AdmissionError("an alternate import root selects another source file", "ambiguous_input")
        tree = _tree(raw)
        imports = [(node, alias) for node in tree.body if isinstance(node, ast.ImportFrom)
            for alias in node.names if (alias.asname or alias.name) == symbol]
        if len(imports) != 1:
            raise AdmissionError("package does not have one static class re-export", "ambiguous_input")
        declaration, alias = imports[0]
        if declaration.level != 1 or not declaration.module or alias.name != class_name:
            raise AdmissionError("only a direct sibling class re-export is admitted")
        relative = str(PurePosixPath(selected).parent / (declaration.module.replace(".", "/") + ".py"))
        if relative != target_member:
            raise AdmissionError("package re-export selects another source member", "ambiguous_input")
        require_import_bindings(raw, {symbol: (declaration.module, 1, class_name)})
        bound.add(target_member)
    return sorted(bound)


def _dependency(bundle, caller):
    for parent in PurePosixPath(caller).parents:
        path = str(parent / "requirements.txt")
        if path not in bundle.members:
            continue
        raw = bundle.read(path)
        text = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
        rows = [line.strip() for line in text.splitlines() if re.match(r"(?i)(?:py)?casbin\b", line.strip())]
        if len(rows) != 1 or re.fullmatch(r"(?:py)?casbin==[0-9]+\.[0-9]+\.[0-9]+", rows[0]) is None:
            raise AdmissionError("nearest declared engine dependency is not one exact supported pin", "dependency_missing")
        identity = engine_identity()
        if rows[0] != identity["distribution"] + "==" + identity["release"]:
            raise AdmissionError("source pin and isolated native engine differ", "dependency_missing")
        return {"path": path, "pin": rows[0], "runtime": identity}
    raise AdmissionError("no source-root engine dependency declaration", "missing_input")


def _instances(bundle, modules, member, descriptor, work_budget):
    found = []
    for caller, raw in modules.items():
        tree = _tree(raw)
        imports = [(node, alias) for node in tree.body if isinstance(node, ast.ImportFrom) and node.level == 0
            and node.module for alias in node.names if alias.name == descriptor["class"]]
        for declaration, alias in imports:
            local = alias.asname or alias.name
            constructors = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Call) and dotted(node.value.func) == local]
            if not constructors:
                continue
            try:
                exports = _exported_class(bundle, declaration.module, alias.name, member, descriptor["class"])
            except AdmissionError as error:
                found.extend({"caller": caller, "construction_line": node.lineno, "instance": node.targets[0].id,
                    "status": error.status, "accepted": None, "reason": str(error)} for node in constructors)
                continue
            for construction in constructors:
                row = {"caller": caller, "construction_line": construction.lineno,
                    "instance": construction.targets[0].id, "import_members": exports}
                try:
                    require_import_bindings(raw, {local: (declaration.module, 0, alias.name), "Path": ("pathlib", 0, "Path")})
                    require_static_definitions(tree, [], reserved=("__file__", "str"))
                    if construction.value.keywords or len(construction.value.args) != 2:
                        raise AdmissionError("native file constructor call is not two positional arguments")
                    environment = {}
                    for node in tree.body:
                        if node is construction:
                            break
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            environment[node.name] = _UNKNOWN
                            continue
                        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                            try:
                                environment[node.targets[0].id] = _path_value(node.value, environment, caller)
                            except AdmissionError:
                                environment[node.targets[0].id] = _UNKNOWN
                            continue
                        for value in ast.walk(node):
                            if isinstance(value, ast.Name) and isinstance(value.ctx, (ast.Store, ast.Del)):
                                environment[value.id] = _UNKNOWN
                            if isinstance(value, (ast.Import, ast.ImportFrom)):
                                for imported in value.names:
                                    environment[imported.asname or imported.name.split(".")[0]] = _UNKNOWN
                    paths = [_path_value(value, environment, caller) for value in construction.value.args]
                    if any(not isinstance(value, _SourcePath) for value in paths):
                        raise AdmissionError("relative CWD-based file paths are not a source-rooted contract")
                    model, policy = [str(value.path.relative_to("/archive")) for value in paths]
                    model_raw, policy_raw = bundle.read(model), bundle.read(policy)
                    dependency = _dependency(bundle, caller)
                    admitted = admit_native_literals(model_raw.decode("utf-8-sig"), policy_raw.decode("utf-8-sig"))
                    policy_domain = translate(admitted.family, admitted.rows)
                    work = (len(policy_domain["principals"]) * len(policy_domain["resources"]) * len(policy_domain["actions"])
                        * max(1, len(admitted.rows)) * len(descriptor["methods"]))
                    if work > work_budget[0]:
                        raise AdmissionError("aggregate selected native work exceeds the archive envelope", "inconclusive")
                    work_budget[0] -= work
                    comparisons = [compare_wrapper(modules[member], method["selector"], method["parameters"],
                        "self." + descriptor["engine_attribute"], model_raw.decode("utf-8-sig"), policy_raw.decode("utf-8-sig"),
                        line_syntax="native-literals") for method in descriptor["methods"]]
                    row.update(status="mismatch" if any(not value["accepted"] for value in comparisons) else "selected_boundary_equivalent",
                        accepted=all(value["accepted"] for value in comparisons), model=model, policy=policy,
                        dependency=dependency, comparisons=comparisons,
                        native_enforce_calls=sum(value["native_enforce_calls"] for value in comparisons))
                except AdmissionError as error:
                    row.update(status=error.status, accepted=None, reason=str(error))
                found.append(row)
    return found


def discover_file_wrappers(archive_path, *, ordered_argument_contract, max_python_members=2000):
    if ordered_argument_contract != ("principal", "resource", "action"):
        raise AdmissionError("explicit ordered three-argument boundary contract required", "invalid")
    if type(max_python_members) is not int or not 1 <= max_python_members <= 2000:
        raise ValueError("bounded complete Python inventory required")
    bundle = SourceArchive(archive_path)
    try:
        names = sorted(name for name in bundle.members if name.endswith(".py"))
        if len(names) > max_python_members:
            raise AdmissionError("complete source inventory exceeds the scan cap", "inconclusive")
        modules = {name: bundle.read(name) for name in names}
        candidates = []
        work_budget = [MAX_NATIVE_WORK]
        for member, raw in modules.items():
            if b"Enforcer" not in raw:
                continue
            tree = _tree(raw)
            for cls in (node for node in tree.body if isinstance(node, ast.ClassDef)):
                if not any(isinstance(node, ast.Call) and dotted(node.func) == "casbin.Enforcer" for node in ast.walk(cls)):
                    continue
                row = {"member": member, "class": cls.name, "line": cls.lineno, "accepted": None}
                try:
                    descriptor = _constructor(raw, cls)
                    instances = _instances(bundle, modules, member, descriptor, work_budget)
                    row.update(descriptor=descriptor, instances=instances,
                        status="selected_instances_found" if instances else "missing_input")
                except AdmissionError as error:
                    row.update(status=error.status, reason=str(error))
                candidates.append(row)
                if len(candidates) > 64:
                    raise AdmissionError("native class inventory exceeds the archive envelope", "inconclusive")
        instances = [value for row in candidates for value in row.get("instances", [])]
        compared = [value for value in instances if type(value.get("accepted")) is bool]
        mismatch = any(value["accepted"] is False for value in compared)
        complete = bool(candidates) and all(row.get("instances") for row in candidates) and len(compared) == len(instances)
        return {"status": "mismatch" if mismatch else "selected_boundary_equivalent" if complete else "partial" if candidates else "missing_input",
            "accepted": False if mismatch else True if complete else None,
            "python_members_scanned": len(names), "candidate_classes": candidates,
            "selected_instance_comparisons": len(compared), "native_enforce_calls": sum(value["native_enforce_calls"] for value in compared),
            "source_members_read": bundle.read_members,
            "archive_sha256": hashlib.sha256(bundle.path.read_bytes()).hexdigest(),
            "ordered_method_input_contract": list(ordered_argument_contract),
            "parameter_role_origin": "explicit ordered method contract; role meaning is not guessed from names or inferred as a production identity guarantee",
            "scope": "direct file constructor and pure native sink under the ordered local method interface",
            "source_modules_imported_or_executed": False, "whole_application_verified": False,
            "unverified_boundaries": ["startup chooses the syntactically unique import root and package",
                "ordinary __file__/pathlib/str/import semantics and no monkey patches or intervening mutations",
                "callers supply principal/resource/action in the declared method argument order",
                "credentials, authentication, endpoint reachability, policy updates, all other classes and methods"]}
    finally:
        bundle.close()
