"""Non-executing source-chain assembly for one declared Django/REST fragment.

The caller supplies an archive, settings member, seed member and finite request
domain, not per-module model translations. Literal settings/imports locate the
selected permission, adapter, relational models and native configuration. This
does not execute Django, initializers, authentication or endpoint dispatch.
"""
import ast
from pathlib import Path, PurePosixPath
import re
import stat
import tomllib
import zipfile

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from native_runtime import engine_identity
from relational_policy import extract_relational_adapter, compile_relational_seed
from rest_policy import extract_rest_consumer, compare_rest_policy


class SourceArchive:
    def __init__(self, path):
        self.path = Path(path)
        if self.path.stat().st_size > 16 * 1024 * 1024:
            raise AdmissionError("source archive exceeds compressed envelope", "inconclusive")
        try:
            self.archive = zipfile.ZipFile(self.path)
            infos = self.archive.infolist()
            if not infos or len(infos) > 20000:
                raise AdmissionError("source archive member envelope exceeded", "inconclusive")
            roots = {info.filename.split("/")[0] for info in infos}
            if len(roots) != 1 or not all("/" in info.filename for info in infos):
                raise AdmissionError("source archive requires exactly one repository root")
            root = next(iter(roots))
            self._safe(root)
            self.members = {}
            for info in infos:
                relative = info.filename.partition("/")[2]
                if not relative or info.is_dir():
                    continue
                self._safe(relative)
                if relative in self.members:
                    raise AdmissionError("duplicate archive member is ambiguous", "invalid")
                self.members[relative] = info
            self.read_members = {}
            self.bytes_read = 0
        except (ValueError, zipfile.BadZipFile, OSError, AdmissionError) as error:
            if hasattr(self, "archive"):
                self.archive.close()
            if isinstance(error, zipfile.BadZipFile):
                raise AdmissionError("source archive is not a valid ZIP", "invalid") from error
            raise

    @staticmethod
    def _safe(path):
        if not isinstance(path, str) or not path or "\\" in path or ":" in path or "\x00" in path:
            raise AdmissionError("source member is not a safe relative path", "invalid")
        p = PurePosixPath(path)
        if p.is_absolute() or any(part in ("", ".", "..") for part in path.split("/")):
            raise AdmissionError("source member escapes or aliases its repository root", "invalid")

    def read(self, relative, limit=MAX_TEXT_BYTES):
        self._safe(relative)
        info = self.members.get(relative)
        if info is None:
            raise AdmissionError("source-chain member is missing: " + relative, "missing_input")
        if stat.S_ISLNK(info.external_attr >> 16) or info.flag_bits & 1:
            raise AdmissionError("selected source member is linked or encrypted", "unsupported")
        if info.file_size > limit or self.bytes_read + info.file_size > 16 * 1024 * 1024:
            raise AdmissionError("source-chain read envelope exceeded", "inconclusive")
        try:
            with self.archive.open(info) as stream:
                data = stream.read(limit + 1)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
            raise AdmissionError("selected source member cannot be decoded", "invalid") from error
        if len(data) > limit or len(data) != info.file_size:
            raise AdmissionError("selected source member size is inconsistent", "invalid")
        self.bytes_read += len(data)
        self.read_members[relative] = len(data)
        return data

    def module_path(self, module):
        if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", module):
            raise AdmissionError("source module needs a literal dotted name")
        stem = module.replace(".", "/")
        matches = [name for name in (stem + ".py", stem + "/__init__.py") if name in self.members]
        if len(matches) != 1:
            raise AdmissionError("source module is missing or ambiguous: " + module, "missing_input")
        return matches[0]

    def close(self):
        self.archive.close()


def _tree(source):
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("selected source-chain module does not parse", "invalid") from error


def literal_setting(tree, name):
    declarations = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    if len(declarations) != 1:
        raise AdmissionError("source setting needs one direct literal declaration: " + name)
    # Reject other direct, conditional, aliased or item-level uses of this setting.
    # Unrelated settings initializers remain explicitly outside this source contract.
    for node in tree.body:
        if node is not declarations[0] and any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node)):
            raise AdmissionError("source setting has an additional use or override: " + name)
    try:
        for node in ast.walk(declarations[0].value):
            if isinstance(node, ast.Dict):
                keys = [ast.literal_eval(key) for key in node.keys]
                if len(set(keys)) != len(keys):
                    raise AdmissionError("source setting has duplicate literal dictionary keys: " + name)
        return ast.literal_eval(declarations[0].value), declarations[0].lineno
    except (ValueError, TypeError, RecursionError) as error:
        raise AdmissionError("source setting is dynamic: " + name) from error


def _import_module(tree, symbol):
    matches = [(node, alias) for node in tree.body if isinstance(node, ast.ImportFrom)
               for alias in node.names if (alias.asname or alias.name) == symbol]
    if len(matches) != 1 or matches[0][1].name != symbol:
        raise AdmissionError("source-chain import is absent, aliased or ambiguous: " + symbol)
    return matches[0][0]


def _user_module(bundle, installed, declaration):
    if not isinstance(installed, (list, tuple)) or not installed or not all(isinstance(x, str) for x in installed):
        raise AdmissionError("installed application declarations are not literal strings")
    if not isinstance(declaration, str) or not re.fullmatch(r"[A-Za-z_]\w*\.UserProfile", declaration):
        raise AdmissionError("selected user model is outside the admitted UserProfile fragment")
    label = declaration.split(".")[0]
    matches = []
    for entry in installed:
        if entry.startswith("django.") or not entry.endswith("Config"):
            continue
        module, _, class_name = entry.rpartition(".")
        tree = _tree(bundle.read(bundle.module_path(module)))
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name]
        if len(classes) != 1:
            raise AdmissionError("application configuration class is ambiguous")
        names = [n for n in classes[0].body if isinstance(n, ast.Assign) and len(n.targets) == 1
                 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "name"]
        labels = [n for n in classes[0].body if isinstance(n, ast.Assign) and len(n.targets) == 1
                  and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "label"]
        if len(names) != 1 or len(labels) > 1:
            raise AdmissionError("application name/label needs one literal declaration")
        try:
            name = ast.literal_eval(names[0].value)
            actual_label = ast.literal_eval(labels[0].value) if labels else name.rsplit(".", 1)[-1]
        except (ValueError, TypeError, AttributeError) as error:
            raise AdmissionError("application name/label is dynamic") from error
        if actual_label == label:
            matches.append(name + ".models")
    if len(matches) != 1:
        raise AdmissionError("user model has no unique source-declared application", "missing_input")
    return matches[0]


def _declared_engine(bundle):
    try:
        manifest = tomllib.loads(bundle.read("pyproject.toml").decode("utf-8-sig"))
    except (ValueError, UnicodeError) as error:
        raise AdmissionError("source engine declaration does not parse", "invalid") from error
    deps = manifest.get("tool", {}).get("poetry", {}).get("dependencies", {})
    engine_deps = {name: deps[name] for name in ("casbin", "pycasbin") if name in deps}
    if len(engine_deps) != 1:
        raise AdmissionError("source needs exactly one declared engine distribution", "dependency_missing")
    package, constraint = next(iter(engine_deps.items()))
    if not isinstance(constraint, str) or not re.fullmatch(r"\^[1-9]\d*\.\d+\.\d+", constraint):
        raise AdmissionError("source dependency constraint needs a reviewed resolver", "dependency_missing")
    native = engine_identity()
    minimum = tuple(int(x) for x in constraint[1:].split("."))
    release = tuple(int(x) for x in native["release"].split("."))
    if package != native["distribution"] or not minimum <= release < (minimum[0] + 1, 0, 0):
        raise AdmissionError("selected native engine does not satisfy the source declaration", "dependency_missing")
    return {"distribution": package, "constraint": constraint, "selected_runtime": native,
            "source_dependency_satisfied": True, "full_application_environment_verified": False}


def compare_rest_source_chain(archive_path, settings_path, seed_path, domain):
    bundle = SourceArchive(archive_path)
    try:
        settings = _tree(bundle.read(settings_path))
        framework, framework_line = literal_setting(settings, "REST_FRAMEWORK")
        installed, _ = literal_setting(settings, "INSTALLED_APPS")
        user, _ = literal_setting(settings, "AUTH_USER_MODEL")
        if not isinstance(framework, dict):
            raise AdmissionError("REST settings must be one literal dictionary")
        permissions = framework.get("DEFAULT_PERMISSION_CLASSES")
        if not isinstance(permissions, (list, tuple)) or not all(isinstance(x, str) for x in permissions):
            raise AdmissionError("default permission classes are not literal strings")
        selected = [item for item in permissions if item != "rest_framework.permissions.IsAuthenticated"]
        if len(selected) != 1:
            raise AdmissionError("source default policy has multiple or absent application permissions")
        consumer_module, _, permission_class = selected[0].rpartition(".")
        consumer_path = bundle.module_path(consumer_module)
        consumer = bundle.read(consumer_path)
        tree = _tree(consumer)
        adapter_import = _import_module(tree, "Adapter")
        if adapter_import.level or adapter_import.module is None:
            raise AdmissionError("permission adapter requires a literal absolute import")
        paths = [n for n in ast.walk(tree) if isinstance(n, ast.Assign) and len(n.targets) == 1
                 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "model_conf_file"]
        if len(paths) != 1 or not isinstance(paths[0].value, ast.Call):
            raise AdmissionError("source model location is absent or ambiguous")
        call = paths[0].value
        if len(call.args) < 2 or not all(isinstance(n, ast.Constant) and type(n.value) is str for n in call.args[1:]):
            raise AdmissionError("source model location is dynamic")
        model_path = "/".join(n.value for n in call.args[1:])
        binding = extract_rest_consumer(consumer, class_name=permission_class,
            adapter_module=adapter_import.module, model_path=model_path)
        adapter_path = bundle.module_path(adapter_import.module)
        adapter = bundle.read(adapter_path)
        role_import = _import_module(_tree(adapter), "Role")
        rule_import = _import_module(_tree(adapter), "Rule")
        if (role_import.level, role_import.module) != (2, "models") or (rule_import.level, rule_import.module) != (2, "models"):
            raise AdmissionError("relational adapter model imports are outside the admitted fragment")
        model_module = ".".join(adapter_import.module.split(".")[:-2] + ["models"])
        model_source = bundle.read(bundle.module_path(model_module))
        user_module = _user_module(bundle, installed, user)
        user_source = bundle.read(bundle.module_path(user_module))
        descriptor = extract_relational_adapter(adapter, model_source, user_source, role_model_module=model_module)
        projection = compile_relational_seed(descriptor, bundle.read(seed_path, 4 * 1024 * 1024))
        dependency = _declared_engine(bundle)
        native = compare_rest_policy(bundle.read(model_path).decode("utf-8-sig"), projection["produced_rows"], domain, projection["reference_rows"])
        accepted = projection["accepted"] and native["accepted"]
        return {"status": "agreement" if accepted else "mismatch", "accepted": accepted,
                "scope": "source-declared default permission/relational seed/native consumer on a supplied finite domain",
                "source_chain": {"settings": settings_path, "default_permission_line": framework_line,
                    "permission_class": selected[0], "consumer": consumer_path, "adapter": adapter_path,
                    "role_rule_models": bundle.module_path(model_module), "user_model": bundle.module_path(user_module),
                    "native_model": model_path, "seed": seed_path},
                "selected_source_members": bundle.read_members, "consumer_binding": binding,
                "source_dependency": dependency, "adapter_projection": projection, "native_comparison": native,
                "native_enforce_calls": native["native_enforce_calls"],
                "manual_inputs": ["source archive identity", "settings member", "complete selected seed member", "finite request domain"],
                "unverified_boundaries": ["Django/application initializers and runtime setting overrides",
                    "ORM managers, inherited ordering and live database state", "authentication/credential issuance",
                    "endpoint permission overrides, HTTP dispatch and business effects"],
                "whole_application_verified": False, "source_modules_imported_or_executed": False}
    finally:
        bundle.close()
