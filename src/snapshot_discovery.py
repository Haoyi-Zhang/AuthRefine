"""Path-free assembly of the explicit ready-snapshot producer/consumer API.

Inputs are one archive and supplied typed rows/owners/requests, not project paths
or class/import maps. Only source declarations are read. The caller's ready
state, immutable DB snapshot and parameter roles remain explicit premises.
"""
import ast
from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath
import re
import sys
import tomllib

from async_snapshot import METHODS, extract_snapshot_program
from native_casbin import AdmissionError, MAX_NATIVE_WORK
from native_runtime import engine_identity
from python_wrapper import dotted
from rest_source_chain import SourceArchive
from snapshot_policy import compare_snapshot, validate_snapshot
from snapshot_schema import bind_snapshot_schema, validate_projected_rows
from source_bindings import require_import_bindings, require_static_definitions


def tree(raw):
    try:
        return ast.parse(raw)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("snapshot source does not parse", "invalid") from error


@dataclass(frozen=True)
class RootedPath:
    value: PurePosixPath


def path_value(node, values, member, depth=0):
    if depth > 24:
        raise AdmissionError("source file path exceeds expression envelope", "inconclusive")
    resolve = lambda value: path_value(value, values, member, depth + 1)
    if isinstance(node, ast.Name):
        if node.id == "__file__":
            return RootedPath(PurePosixPath("/archive") / member)
        if node.id in values:
            return values[node.id]
    if isinstance(node, ast.Constant) and type(node.value) is str:
        SourceArchive._safe(node.value)
        return node.value
    if isinstance(node, ast.Call) and not node.keywords:
        if dotted(node.func) == "os.path.dirname" and len(node.args) == 1:
            source = resolve(node.args[0])
            if isinstance(source, RootedPath) and source.value.parent.is_relative_to("/archive"):
                return RootedPath(source.value.parent)
        if dotted(node.func) == "os.path.join" and 2 <= len(node.args) <= 8:
            parts = [resolve(argument) for argument in node.args]
            if isinstance(parts[0], RootedPath) and all(type(value) is str for value in parts[1:]):
                return RootedPath(parts[0].value.joinpath(*parts[1:]))
    raise AdmissionError("model path is not a closed source-rooted dirname/join expression")


def model_origin(raw, cls, member):
    require_import_bindings(raw, {"casbin": ("casbin", 0, None), "os": ("os", 0, None)})
    parsed = tree(raw)
    require_static_definitions(parsed, [cls.name], reserved=("__file__",))
    parents = {id(child): node for node in ast.walk(cls) for child in ast.iter_child_nodes(node)}
    calls = [node for node in ast.walk(cls) if isinstance(node, ast.Call) and dotted(node.func) == "casbin.Enforcer"]
    if len(calls) != 1:
        raise AdmissionError("ready snapshot class needs one declared native model constructor")
    call = calls[0]
    assignment = parents.get(id(call))
    if (not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1
            or dotted(assignment.targets[0]) != "self._enforcer" or len(call.args) != 1 or call.keywords):
        raise AdmissionError("model constructor must initialize the selected native field directly")
    owner = parents.get(id(assignment))
    blocks = [value for _, value in ast.iter_fields(owner) if isinstance(value, list)
        and any(item is assignment for item in value)] if owner is not None else []
    if len(blocks) != 1:
        raise AdmissionError("native model constructor statement sequence is ambiguous")
    scope, current = [], assignment
    while id(current) in parents:
        current = parents[id(current)]
        scope.append(current)
    methods = [node for node in scope if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if (len(methods) != 1 or not isinstance(methods[0], ast.AsyncFunctionDef) or methods[0].decorator_list
            or methods[0] not in cls.body or any(isinstance(node, (ast.For, ast.While, ast.Try)) for node in scope)):
        raise AdmissionError("native constructor is not in one direct async initializer body")
    protected = {"os", "casbin", "__file__"}
    if any(argument.arg in protected for argument in (*methods[0].args.posonlyargs, *methods[0].args.args, *methods[0].args.kwonlyargs)):
        raise AdmissionError("initializer parameters shadow path/native primitives")
    for item in ast.walk(methods[0]):
        if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)) and item.id in protected:
            raise AdmissionError("initializer shadows path/native primitives")
        if isinstance(item, (ast.Import, ast.ImportFrom)) and any((alias.asname or alias.name.split(".")[0]) in protected for alias in item.names):
            raise AdmissionError("initializer imports rebind the path/native primitives")
        if isinstance(item, ast.Attribute) and isinstance(item.ctx, (ast.Store, ast.Del)):
            base = item.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id in protected:
                raise AdmissionError("initializer mutates a selected path/native primitive")
    values = {}
    for node in blocks[0]:
        if node is assignment:
            break
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            try:
                values[name] = path_value(node.value, values, member)
            except AdmissionError:
                values.pop(name, None)
        else:
            for item in ast.walk(node):
                if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
                    values.pop(item.id, None)
    path = path_value(call.args[0], values, member)
    if not isinstance(path, RootedPath):
        raise AdmissionError("CWD-relative model file is outside the source-rooted contract")
    return str(path.value.relative_to("/archive")), {"initializer": methods[0].name,
        "constructor_line": assignment.lineno, "path_resolution": "declared __file__/os.path.dirname/join semantics",
        "initializer_locks_guards_admin_sync_and_reachability_verified": False}


def schema_origin(bundle, raw):
    parsed = tree(raw)
    imported = {}
    for name in ("CasbinRule", "ResourceOwner"):
        matches = [(node, alias) for node in parsed.body if isinstance(node, ast.ImportFrom)
            for alias in node.names if (alias.asname or alias.name) == name]
        if len(matches) != 1 or matches[0][1].name != name or matches[0][0].level or not matches[0][0].module:
            raise AdmissionError("snapshot table needs an unaliased direct absolute source import")
        imported[name] = matches[0][0].module
    if len(set(imported.values())) != 1:
        raise AdmissionError("snapshot tables require one declared source schema module")
    module = imported["CasbinRule"]
    if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", module):
        raise AdmissionError("snapshot schema module syntax is invalid")
    stem = module.replace(".", "/")
    suffixes = (stem + ".py", stem + "/__init__.py")
    matches = [name for name in bundle.members if any(name == suffix or name.endswith("/" + suffix) for suffix in suffixes)]
    if len(matches) != 1:
        raise AdmissionError("schema import has missing or competing source roots", "ambiguous_input")
    member = matches[0]
    return module, member, bind_snapshot_schema(bundle.read(member))


def dependency(bundle, source_member):
    for parent in PurePosixPath(source_member).parents:
        member = str(parent / "pyproject.toml")
        if member not in bundle.members:
            continue
        try:
            project = tomllib.loads(bundle.read(member).decode("utf-8-sig"))["project"]
        except (KeyError, ValueError, UnicodeError) as error:
            raise AdmissionError("nearest snapshot package manifest is not admitted PEP621 metadata") from error
        declarations = [value for value in project.get("dependencies", []) if type(value) is str
            and re.match(r"(?i)^(?:py)?casbin\b", value)]
        if len(declarations) != 1 or re.fullmatch(r"(?:py)?casbin>=[0-9]+\.[0-9]+\.[0-9]+", declarations[0]) is None:
            raise AdmissionError("snapshot engine constraint needs an unambiguous reviewed lower bound", "dependency_missing")
        runtime = engine_identity()
        minimum = tuple(map(int, declarations[0].split(">=")[1].split(".")))
        package = declarations[0].split(">=")[0]
        if runtime["distribution"] != package or tuple(map(int, runtime["release"].split("."))) < minimum:
            raise AdmissionError("selected isolated native engine violates the declared source dependency", "dependency_missing")
        required_python = project.get("requires-python")
        if type(required_python) is not str or not re.fullmatch(r">=[0-9]+\.[0-9]+", required_python):
            raise AdmissionError("snapshot host/source Python distinction needs a simple declared minimum")
        return {"manifest": member, "casbin_constraint": declarations[0], "native_runtime": runtime,
            "source_requires_python": required_python, "host_python": sys.version.split()[0],
            "host_meets_declared_python_minimum": sys.version_info[:2] >= tuple(map(int, required_python[2:].split("."))),
            "full_source_application_environment_verified": False}
    raise AdmissionError("no nearest source package manifest", "missing_input")


def discover_snapshot_chain(archive_path, rules, owners, requests, *, ready=False, max_python_members=2000):
    if ready is not True:
        raise AdmissionError("caller must explicitly supply the ready immutable-snapshot precondition", "input_rejected")
    validate_snapshot(rules, owners)
    if (type(requests) is not list or not 1 <= len(requests) <= 4096
            or type(max_python_members) is not int or not 1 <= max_python_members <= 2000):
        raise AdmissionError("snapshot discovery input or source inventory exceeds its envelope", "input_rejected")
    bundle = SourceArchive(archive_path)
    try:
        names = sorted(name for name in bundle.members if name.endswith(".py"))
        if len(names) > max_python_members:
            raise AdmissionError("complete Python inventory exceeds the discovery cap", "inconclusive")
        candidates, work = [], 0
        for member in names:
            raw = bundle.read(member)
            if b"Enforcer" not in raw:
                continue
            parsed = tree(raw)
            for cls in (node for node in parsed.body if isinstance(node, ast.ClassDef)):
                method_names = {node.name for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
                if not set(METHODS) <= method_names:
                    continue
                row = {"service_member": member, "class": cls.name, "accepted": None}
                try:
                    model_member, origin = model_origin(raw, cls, member)
                    try:
                        model_text = bundle.read(model_member).decode("utf-8-sig")
                    except UnicodeError as error:
                        raise AdmissionError("selected model is not UTF-8 source configuration", "invalid") from error
                    module, schema_member, schema = schema_origin(bundle, raw)
                    validate_projected_rows(schema, rules, owners)
                    extract_snapshot_program(raw, cls.name, module)
                    declared = dependency(bundle, member)
                    work += len(requests) * max(1, len(rules) + len(owners))
                    if work > MAX_NATIVE_WORK:
                        raise AdmissionError("aggregate snapshot discovery work exceeds its native envelope", "inconclusive")
                    result = compare_snapshot(raw, model_text, rules, owners, requests,
                        class_name=cls.name, model_import_module=module)
                    row.update(status=result["status"], accepted=result["accepted"], model_member=model_member,
                        model_origin=origin, schema_member=schema_member, schema_module=module,
                        projected_schema=schema, dependency=declared, comparison=result)
                except AdmissionError as error:
                    row.update(status=error.status, reason=str(error))
                candidates.append(row)
                if len(candidates) > 32:
                    raise AdmissionError("snapshot class candidates exceed the archive envelope", "inconclusive")
        compared = [row for row in candidates if type(row.get("accepted")) is bool]
        failed = any(row["accepted"] is False for row in compared)
        complete = bool(candidates) and len(compared) == len(candidates)
        return {"status": "mismatch" if failed else "equivalent" if complete else "partial" if candidates else "missing_input",
            "accepted": False if failed else True if complete else None, "candidate_services": candidates,
            "selected_source_chain_comparisons": len(compared), "python_members_scanned": len(names),
            "source_members_read": bundle.read_members, "archive_sha256": hashlib.sha256(bundle.path.read_bytes()).hexdigest(),
            "input_contract": "caller-supplied ready state, immutable typed policy/owner rows and explicit user/resource/action records",
            "manual_project_paths_classes_schema_imports_or_model_maps": False,
            "source_modules_orm_tests_or_services_executed": False, "whole_application_verified": False,
            "unverified_boundaries": ["actual startup, locks and administrator synchronization",
                "runtime import root, __file__/os semantics, monkey patches and source singleton binding",
                "real identity issuance, ORM queries, transaction/commit, policy mutations and concurrent calls",
                "complete source application Python/runtime dependency environment"]}
    finally:
        bundle.close()
