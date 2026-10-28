"""Assemble a declared YAML producer/store/consumer from archive source.

Inputs are a source archive, explicit user/group contexts and resource/action
domain. No per-project file paths, class name, field map or executable module is
supplied. Only the declared default configuration and a narrow constructor and
loader contract are admitted. Actual startup, env overrides, credentials and
endpoint reachability are separate from the resulting finite comparison.
"""
from __future__ import annotations

import ast
import hashlib
import re

from native_casbin import AdmissionError
from native_runtime import engine_identity
from policy_slice import METHODS
from rest_source_chain import SourceArchive
from source_bindings import (require_import_bindings, require_static_class_members,
                             require_static_definitions)
from yaml_policy import compare_yaml_policy, parse_yaml


def _body(node):
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and type(body[0].value.value) is str:
        body = body[1:]
    return body


def _shape(node):
    return ast.dump(node, include_attributes=False)


def _tree(source):
    try:
        return ast.parse(source)
    except (ValueError, SyntaxError, UnicodeError, RecursionError) as error:
        raise AdmissionError("potential YAML source chain does not parse", "invalid") from error


def _writes(tree, symbol, declaration):
    """Reject syntactic module-level writes, not arbitrary runtime effects."""
    pending = [node for node in tree.body if node is not declaration]
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == symbol:
                raise AdmissionError("source module redefines selected binding: " + symbol)
            continue
        if isinstance(node, ast.Name) and node.id == symbol and isinstance(node.ctx, (ast.Store, ast.Del)):
            raise AdmissionError("source module rebinds selected value: " + symbol)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            root = node.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id == symbol:
                raise AdmissionError("source module mutates selected binding: " + symbol)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*" or (alias.asname or alias.name.split(".")[0]) == symbol:
                    raise AdmissionError("source import makes selected binding ambiguous: " + symbol)
        pending.extend(ast.iter_child_nodes(node))


def _literal_path(value):
    if type(value) is not str or not value or len(value) > 240 or "\\" in value or ":" in value:
        raise AdmissionError("source default needs a relative archive path")
    if any(part in ("", ".", "..") for part in value.split("/")) or value.startswith("/"):
        raise AdmissionError("source default escapes or aliases the archive")
    return value


def _settings_defaults(bundle, module, symbol, fields):
    path = bundle.module_path(module)
    tree = _tree(bundle.read(path))
    declarations = [n for n in tree.body if isinstance(n, ast.Assign) and len(n.targets) == 1
                    and isinstance(n.targets[0], ast.Name) and n.targets[0].id == symbol]
    if len(declarations) != 1:
        raise AdmissionError("settings instance requires one direct declaration")
    declaration = declarations[0]
    call = declaration.value
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.args or call.keywords:
        raise AdmissionError("settings instance constructor has explicit/dynamic overrides")
    _writes(tree, symbol, declaration)
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == call.func.id]
    if len(classes) != 1 or classes[0].decorator_list or classes[0].keywords:
        raise AdmissionError("settings class has an ambiguous or dynamic declaration")
    cls = classes[0]
    require_static_definitions(tree, [cls.name])
    _writes(tree, cls.name, cls)
    values = {}
    declarations = {}
    for field in fields:
        matches = [n for n in cls.body if isinstance(n, ast.AnnAssign)
                   and isinstance(n.target, ast.Name) and n.target.id == field]
        if len(matches) != 1:
            raise AdmissionError("selected settings field has no unique literal default")
        node = matches[0]
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError) as error:
            raise AdmissionError("selected settings field is dynamic") from error
        _writes(cls, field, node)
        values[field] = _literal_path(value)
        declarations[field] = node.lineno
    return {"path": path, "instance": symbol, "class": cls.name,
            "field_lines": declarations, "defaults": values,
            "environment_or_settings_library_initialization_executed": False}


def _constructor_chain(source, cls):
    tree = _tree(source)
    matches = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls.name and n.lineno == cls.lineno]
    if len(matches) != 1:
        raise AdmissionError("selected policy class identity is ambiguous")
    cls = matches[0]
    require_static_definitions(tree, [cls.name], reserved=("str", "open"))
    _writes(tree, cls.name, cls)
    require_static_class_members(cls, (*METHODS, "__init__", "_load_yaml_policy", "_ensure_config_files"))
    def method(name):
        selected = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name]
        if len(selected) != 1:
            raise AdmissionError("selected helper is not one synchronous method: " + name)
        return selected[0]
    init = method("__init__")
    arguments = init.args
    names = [n.arg for n in arguments.args]
    if (len(names) != 4 or names[0] != "self" or len(set(names)) != 4
            or arguments.posonlyargs or arguments.kwonlyargs or arguments.kwarg or arguments.vararg
            or len(arguments.defaults) != 3 or init.decorator_list
            or any(not isinstance(n, ast.Constant) or n.value is not None for n in arguments.defaults)):
        raise AdmissionError("YAML constructor needs three distinct optional path parameters")
    body = _body(init)
    if len(body) != 8:
        raise AdmissionError("constructor has additional or missing operations")
    mappings = {}
    setting_names = set()
    for node in body[:3]:
        if (not isinstance(node, ast.If) or node.orelse or len(node.body) != 1
                or not isinstance(node.test, ast.Compare) or len(node.test.ops) != 1
                or not isinstance(node.test.ops[0], ast.Is) or not isinstance(node.test.left, ast.Name)
                or len(node.test.comparators) != 1 or not isinstance(node.test.comparators[0], ast.Constant)
                or node.test.comparators[0].value is not None):
            raise AdmissionError("constructor default selection is not a direct None guard")
        parameter = node.test.left.id
        assignment = node.body[0]
        if (parameter not in names[1:] or parameter in mappings
                or not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1
                or not isinstance(assignment.targets[0], ast.Name) or assignment.targets[0].id != parameter
                or not isinstance(assignment.value, ast.Attribute) or not isinstance(assignment.value.value, ast.Name)):
            raise AdmissionError("constructor default path is not an imported settings field")
        setting_names.add(assignment.value.value.id)
        mappings[parameter] = assignment.value.attr
    if len(setting_names) != 1 or set(mappings) != set(names[1:]):
        raise AdmissionError("constructor paths use ambiguous settings instances")
    setting_name = next(iter(setting_names))
    imported = [(n, alias) for n in tree.body if isinstance(n, ast.ImportFrom)
                for alias in n.names if (alias.asname or alias.name) == setting_name]
    if len(imported) != 1 or imported[0][0].level or not imported[0][0].module:
        raise AdmissionError("settings require one direct absolute import")
    import_node, alias = imported[0]
    require_import_bindings(source, {"casbin": ("casbin", 0, None), "yaml": ("yaml", 0, None),
        "Path": ("pathlib", 0, "Path"), setting_name: (import_node.module, 0, alias.name)})
    # Infer path roles from actual construction rather than parameter names.
    yaml_assignment, load_assignment, ensure, engine_assignment, sync = body[3:]
    if (not isinstance(yaml_assignment, ast.Assign) or len(yaml_assignment.targets) != 1
            or _shape(yaml_assignment.targets[0]) != _shape(ast.parse("self.yaml_policy_path = None").body[0].targets[0])
            or not isinstance(yaml_assignment.value, ast.Call) or not isinstance(yaml_assignment.value.func, ast.Name)
            or yaml_assignment.value.func.id != "Path" or yaml_assignment.value.keywords
            or len(yaml_assignment.value.args) != 1 or not isinstance(yaml_assignment.value.args[0], ast.Name)):
        raise AdmissionError("YAML source path construction is unbound")
    yaml_parameter = yaml_assignment.value.args[0].id
    if (not isinstance(engine_assignment, ast.Assign) or len(engine_assignment.targets) != 1
            or not isinstance(engine_assignment.value, ast.Call) or engine_assignment.value.keywords
            or len(engine_assignment.value.args) != 2):
        raise AdmissionError("native constructor is not one declared two-path call")
    constructor_arguments = []
    for argument in engine_assignment.value.args:
        if (not isinstance(argument, ast.Call) or not isinstance(argument.func, ast.Name)
                or argument.func.id != "str" or argument.keywords or len(argument.args) != 1
                or not isinstance(argument.args[0], ast.Name)):
            raise AdmissionError("native constructor path is not a bound path parameter")
        constructor_arguments.append(argument.args[0].id)
    model_parameter, policy_parameter = constructor_arguments
    if set((model_parameter, policy_parameter, yaml_parameter)) != set(names[1:]):
        raise AdmissionError("constructor path roles are duplicated or missing")
    expected_tail = ast.parse(f'''self.yaml_policy_path = Path({yaml_parameter})
self.yaml_policy = self._load_yaml_policy()
self._ensure_config_files(Path({model_parameter}), Path({policy_parameter}))
self.enforcer = casbin.Enforcer(str({model_parameter}), str({policy_parameter}))
self._sync_yaml_to_casbin()
''').body
    if [_shape(n) for n in body[3:]] != [_shape(n) for n in expected_tail]:
        raise AdmissionError("constructor ordering or native/producer binding differs")
    loader = method("_load_yaml_policy")
    loader_template = ast.parse('''if self.yaml_policy_path.exists():
 with open(self.yaml_policy_path, 'r') as f:
  return yaml.safe_load(f) or {}
return {'roles': {}, 'user_roles': {}, 'group_roles': {}, 'rules': [], 'default_policy': 'deny'}
''').body
    if (loader.decorator_list or [n.arg for n in loader.args.args] != ["self"]
            or loader.args.posonlyargs or loader.args.kwonlyargs or loader.args.vararg or loader.args.kwarg or loader.args.defaults
            or [_shape(n) for n in _body(loader)] != [_shape(n) for n in loader_template]):
        raise AdmissionError("YAML loader requires a separately reviewed conversion")
    ensure_fn = method("_ensure_config_files")
    ensure_names = [n.arg for n in ensure_fn.args.args]
    if (ensure_fn.decorator_list or len(ensure_names) != 3 or ensure_names[0] != "self"
            or len(set(ensure_names)) != 3 or ensure_fn.args.posonlyargs or ensure_fn.args.kwonlyargs
            or ensure_fn.args.vararg or ensure_fn.args.kwarg or ensure_fn.args.defaults
            or len(_body(ensure_fn)) != 2):
        raise AdmissionError("configuration-creation helper is not two existing-file guards")
    for statement, parameter in zip(_body(ensure_fn), ensure_names[1:]):
        expected_guard = ast.parse(f"not {parameter}.exists()", mode="eval").body
        if not isinstance(statement, ast.If) or statement.orelse or _shape(statement.test) != _shape(expected_guard):
            raise AdmissionError("configuration helper has reachable unreviewed behavior on existing files")
    return {"settings_module": import_node.module, "settings_symbol": alias.name,
            "class_name": cls.name, "constructor_line": init.lineno,
            "field_roles": {"model": mappings[model_parameter], "policy": mappings[policy_parameter], "yaml": mappings[yaml_parameter]},
            "configuration_creation_branch": "not entered under the explicit existing-file default snapshot contract"}


def _dependencies(bundle):
    lines = bundle.read("requirements.txt").decode("utf-8-sig").splitlines()
    selected = []
    for line in lines:
        line = line.partition("#")[0].strip()
        if re.match(r"(?i)^(?:pycasbin|casbin|pyyaml)(?:[<>=~!;\s\[]|$)", line):
            selected.append(line)
    found = {}
    for line in selected:
        match = re.fullmatch(r"(?i)(casbin|pycasbin|pyyaml)==(\d+\.\d+\.\d+)", line)
        if not match or match[1].casefold() in found:
            raise AdmissionError("source dependency needs one exact reviewed release", "dependency_missing")
        found[match[1].casefold()] = match[2]
    runtime = engine_identity()
    if (set(found) != {runtime["distribution"], "pyyaml"}
            or found[runtime["distribution"]] != runtime["release"] or found["pyyaml"] != "6.0.2"):
        raise AdmissionError("native engine/YAML releases differ from the source declaration", "dependency_missing")
    return {"declarations": found, "native_runtime": runtime, "source_dependencies_satisfied": True}


def discover_yaml_chain(archive_path, contexts, domain, *, max_python_members=2000):
    result = {"status": "inconclusive", "accepted": None, "discovery_complete": False,
        "candidate_classes": [], "whole_application_verified": False, "source_modules_imported_or_executed": False,
        "manual_inputs": ["source archive identity", "explicit user/group contexts", "finite resource/action domain"],
        "scope": "unique declared default YAML producer/native-store/consumer with existing input files"}
    bundle = None
    try:
        if type(max_python_members) is not int or not 1 <= max_python_members <= 2000:
            raise AdmissionError("invalid complete-source scan budget", "invalid")
        bundle = SourceArchive(archive_path)
        members = sorted(n for n in bundle.members if n.endswith(".py"))
        if len(members) > max_python_members:
            raise AdmissionError("complete source scan exceeds the declared budget", "inconclusive")
        cache = {}
        for name in members:
            source = bundle.read(name)
            cache[name] = source
            # Byte filter is not class admission or evidence of execution.
            if b"_sync_yaml_to_casbin" not in source:
                continue
            tree = _tree(source)
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and set(METHODS) <= {n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}:
                    result["candidate_classes"].append({"path": name, "class": node.name, "line": node.lineno})
        result.update(discovery_complete=True, python_members=len(members))
        if not result["candidate_classes"]:
            return {**result, "status": "missing_input", "reason": "no source-declared YAML producer/consumer class"}
        if len(result["candidate_classes"]) != 1:
            return {**result, "status": "ambiguous_input", "reason": "multiple source classes; no outcome-based selection"}
        selected = result["candidate_classes"][0]
        source = cache[selected["path"]]
        cls = next(n for n in _tree(source).body if isinstance(n, ast.ClassDef) and n.name == selected["class"] and n.lineno == selected["line"])
        chain = _constructor_chain(source, cls)
        settings = _settings_defaults(bundle, chain["settings_module"], chain["settings_symbol"], chain["field_roles"].values())
        paths = {role: settings["defaults"][field] for role, field in chain["field_roles"].items()}
        model, policy, yaml_text = (bundle.read(paths[role]).decode("utf-8-sig") for role in ("model", "policy", "yaml"))
        dependency = _dependencies(bundle)
        comparison = compare_yaml_policy(source, model, policy, parse_yaml(yaml_text), contexts, domain, class_name=selected["class"])
        return {**result, "status": comparison["status"], "accepted": comparison["accepted"],
            "source_chain": {"producer_consumer": selected, "constructor": chain, "settings": settings, "input_paths": paths},
            "source_dependency": dependency, "comparison": comparison,
            "selected_source_bindings": {name: {"bytes": len(cache.get(name, b"")) or size,
                "sha256": hashlib.sha256(cache[name] if name in cache else bundle.read(name)).hexdigest()}
                for name, size in list(bundle.read_members.items())
                if name in {selected["path"], settings["path"], *paths.values(), "requirements.txt"}},
            "unverified_boundaries": ["startup selects this class/default settings and repository-root working directory",
                "environment, constructor arguments, settings-library overrides and arbitrary module initialization",
                "actual file-loader locale and filesystem; the comparison consumes explicit decoded snapshot data",
                "authentication, issuer/groups, route reachability and endpoint or deployment effects",
                "ignored YAML metadata/condition fields retain their explicit uncertified meaning"]}
    except AdmissionError as error:
        return {**result, "status": error.status, "reason": str(error)}
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as error:
        return {**result, "status": "missing_input" if isinstance(error, FileNotFoundError) else "invalid",
                "reason": "source-chain input failed: " + type(error).__name__}
    finally:
        if bundle is not None:
            bundle.close()
