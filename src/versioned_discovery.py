"""Bounded default-model version-cache source assembly, without app imports.

The supported idiom has the admitted five cache/snapshot methods and direct
frozen record declarations. Supplied stable epochs are not live repository,
transaction, issuer, startup or concurrency verification.
"""
import ast
import hashlib
from pathlib import PurePosixPath
import re
import sys
import tomllib

from native_casbin import AdmissionError, MAX_NATIVE_WORK
from native_runtime import engine_identity
from rest_source_chain import SourceArchive
from source_bindings import require_import_bindings, require_static_definitions
from versioned_cache import METHODS, SNAPSHOT_FIELDS, admit_epochs, compare_versioned_cache


def parsed(raw):
    try:
        return ast.parse(raw)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError('version-cache source cannot be parsed', 'invalid') from error


def frozen_fields(raw, name, expected):
    tree = parsed(raw)
    require_import_bindings(raw, {'dataclass': ('dataclasses', 0, 'dataclass')})
    require_static_definitions(tree, [name])
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name)
    decorator = ast.dump(ast.parse('@dataclass(frozen=True)\nclass R: pass').body[0].decorator_list[0], include_attributes=False)
    if (cls.bases or cls.keywords or len(cls.decorator_list) != 1
            or ast.dump(cls.decorator_list[0], include_attributes=False) != decorator):
        raise AdmissionError('record needs the direct frozen dataclass contract: ' + name)
    body = cls.body[1:] if cls.body and isinstance(cls.body[0], ast.Expr) and isinstance(cls.body[0].value, ast.Constant) and type(cls.body[0].value.value) is str else cls.body
    if any(not isinstance(node, ast.AnnAssign) or node.simple != 1 or not isinstance(node.target, ast.Name)
           or node.value is not None for node in body):
        raise AdmissionError('record methods, defaults or dynamic fields are not admitted: ' + name)
    fields = [(node.target.id, ast.dump(node.annotation, include_attributes=False)) for node in body]
    wanted = [(field, ast.dump(ast.parse(annotation, mode='eval').body, include_attributes=False))
              for field, annotation in expected]
    if fields != wanted:
        raise AdmissionError('record constructor fields/order/annotations differ: ' + name)
    return [{'field': node.target.id, 'annotation': ast.unparse(node.annotation)} for node in body]


def source_root_path(node, member):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        parent = source_root_path(node.left, member)
        if not isinstance(node.right, ast.Constant) or type(node.right.value) is not str:
            raise AdmissionError('default model path has a dynamic component')
        SourceArchive._safe(node.right.value)
        value = parent / node.right.value
        if not value.is_relative_to('/archive'):
            raise AdmissionError('default model leaves source root')
        return value
    if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == 'parents'
            and isinstance(node.slice, ast.Constant) and type(node.slice.value) is int and 0 <= node.slice.value <= 12):
        call = node.value.value
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'Path'
                and not call.keywords and len(call.args) == 1 and isinstance(call.args[0], ast.Name)
                and call.args[0].id == '__file__'):
            path = PurePosixPath('/archive') / member
            try:
                result = path.parents[node.slice.value]
            except IndexError as error:
                raise AdmissionError('default model parent exceeds source root') from error
            if result.is_relative_to('/archive'):
                return result
    raise AdmissionError('default model is not a closed Path(__file__).parents expression')


def model_origin(raw, cls, member):
    require_import_bindings(raw, {'Path': ('pathlib', 0, 'Path'), 'casbin': ('casbin', 0, None)})
    require_static_definitions(parsed(raw), [cls.name], reserved=('__file__',))
    initializers = [node for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == '__init__']
    if len(initializers) != 1 or not isinstance(initializers[0], ast.FunctionDef) or initializers[0].decorator_list:
        raise AdmissionError('one direct cache initializer declaration required')
    init = initializers[0]
    arguments = init.args
    parameters = arguments.posonlyargs + arguments.args
    defaults = dict(zip((arg.arg for arg in parameters[len(parameters) - len(arguments.defaults):]), arguments.defaults))
    if ('model_path' not in defaults or not isinstance(defaults['model_path'], ast.Constant)
            or defaults['model_path'].value is not None or arguments.vararg or arguments.kwarg or arguments.kwonlyargs):
        raise AdmissionError('default model parameter must explicitly default to None')
    if cls.bases or cls.keywords or cls.decorator_list or any(
            isinstance(node, (ast.Assign, ast.AnnAssign)) or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in ('model_path', 'repository', '_cache_state') for node in cls.body):
        raise AdmissionError('service state descriptors or class construction overrides are not admitted')
    protected = {'Path', '__file__', 'casbin', 'model_path'}
    if any(arg.arg in protected - {'model_path'} for arg in (*init.args.posonlyargs, *init.args.args, *init.args.kwonlyargs)):
        raise AdmissionError('initializer parameters shadow path primitives')
    if any(isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in protected
           for node in ast.walk(init)):
        raise AdmissionError('initializer overrides default path or primitive')
    for node in ast.walk(init):
        if isinstance(node, (ast.Import, ast.ImportFrom)) and any((alias.asname or alias.name.split('.')[0]) in protected for alias in node.names):
            raise AdmissionError('initializer reimports a path primitive')
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id in protected:
                raise AdmissionError('initializer mutates a path primitive')
    selected = [node for node in ast.walk(init) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
            and target.value.id == 'self' and target.attr == 'model_path' for target in node.targets)]
    if len(selected) != 1 or selected[0] not in init.body or len(selected[0].targets) != 1:
        raise AdmissionError('model path needs one direct initialization, not a conditional override')
    path_writes = [node for node in ast.walk(init) if isinstance(node, ast.Attribute)
        and isinstance(node.ctx, (ast.Store, ast.Del)) and isinstance(node.value, ast.Name)
        and node.value.id == 'self' and node.attr == 'model_path']
    if len(path_writes) != 1:
        raise AdmissionError('model path has another annotation, update or deletion')
    value = selected[0].value
    if (not isinstance(value, ast.BoolOp) or not isinstance(value.op, ast.Or) or len(value.values) != 2
            or not isinstance(value.values[0], ast.Name) or value.values[0].id != 'model_path'):
        raise AdmissionError('explicit default/no-override model branch required')
    path = source_root_path(value.values[1], member)
    return str(path.relative_to('/archive')), {'initializer': '__init__', 'assignment_line': selected[0].lineno,
        'default_model_override_absent_is_explicit_premise': True, 'initializer_or_call_site_reachability_verified': False}


def bind_records(bundle, raw):
    require_import_bindings(raw, {'AuthContext': ('app.entities.auth', 0, 'AuthContext'),
        'PermissionSnapshot': ('app.entities.auth', 0, 'PermissionSnapshot'),
        'AuthzPolicy': ('app.entities.authz_policy', 0, 'AuthzPolicy')})
    cache = frozen_fields(raw, '_PolicyCache', [('version', 'int'), ('enforcer', 'casbin.Enforcer'),
        ('policies', 'tuple[AuthzPolicy, ...]')])
    module = parsed(raw)
    require_static_definitions(module, ['AuthorizationError', 'AuthorizationUnavailableError'], reserved=('Exception',))
    for name in ('AuthorizationError', 'AuthorizationUnavailableError'):
        error = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == name)
        if (len(error.bases) != 1 or not isinstance(error.bases[0], ast.Name) or error.bases[0].id != 'Exception'
                or error.keywords or error.decorator_list or any(not isinstance(node, ast.Pass)
                    and not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                             and type(node.value.value) is str) for node in error.body)):
            raise AdmissionError('source error class behavior differs from supplied exception contract')
    member = bundle.module_path('app.entities.auth')
    auth_raw = bundle.read(member)
    snapshot = frozen_fields(auth_raw, 'PermissionSnapshot', [('policy_version', 'int'),
        *[(name, 'frozenset[str]') for name in SNAPSHOT_FIELDS], ('sql_fallback_allowed', 'bool')])
    return {'cache_record_fields': cache, 'snapshot_record_fields': snapshot,
        'snapshot_schema_member': member, 'auth_context_construction_or_token_fields_certified': False,
        'record_shape_binding_not_general_import_or_dataclass_runtime_theorem': True}


def dependency(bundle, source_member):
    for parent in PurePosixPath(source_member).parents:
        name = str(parent / 'pyproject.toml')
        if name.startswith('./'):
            name = name[2:]
        if name not in bundle.members:
            continue
        try:
            project = tomllib.loads(bundle.read(name).decode('utf-8-sig'))['project']
        except (ValueError, KeyError, UnicodeError) as error:
            raise AdmissionError('nearest package manifest is not admitted', 'dependency_missing') from error
        matches = [value for value in project.get('dependencies', []) if type(value) is str and re.match(r'(?i)^(?:py)?casbin\b', value)]
        if len(matches) != 1 or re.fullmatch(r'(?:py)?casbin==[0-9]+\.[0-9]+\.[0-9]+', matches[0]) is None:
            raise AdmissionError('source cache needs one exact native engine declaration', 'dependency_missing')
        package, release = matches[0].split('==')
        native = engine_identity()
        if (native['distribution'], native['release']) != (package, release):
            raise AdmissionError('selected engine differs from exact source declaration', 'dependency_missing')
        return {'manifest': name, 'native_constraint': matches[0], 'native_runtime': native,
            'source_requires_python': project.get('requires-python'), 'host_python': sys.version.split()[0],
            'full_application_environment_certified': False}
    raise AdmissionError('source manifest is missing', 'missing_input')


def discover_versioned_chain(archive_path, epochs, requests, *, default_model=False, stable_epochs=False, max_python_members=2000):
    if default_model is not True or stable_epochs is not True:
        raise AdmissionError('explicit absent-model-override and stable immutable epoch premises required', 'input_rejected')
    admit_epochs(epochs)
    if (type(requests) is not list or not 1 <= len(requests) <= 32
            or any(type(row) is not list or len(row) != 2 or any(type(x) is not str or not x or len(x) > 256 for x in row) for row in requests)
            or type(max_python_members) is not int or not 1 <= max_python_members <= 2000):
        raise AdmissionError('request or source inventory envelope invalid', 'input_rejected')
    bundle = SourceArchive(archive_path)
    try:
        names = sorted(name for name in bundle.members if name.endswith('.py'))
        if len(names) > max_python_members:
            raise AdmissionError('complete Python inventory exceeds cap', 'inconclusive')
        candidates, work = [], 0
        for member in names:
            raw = bundle.read(member)
            if b'Enforcer' not in raw:
                continue
            tree = parsed(raw)
            for cls in (node for node in tree.body if isinstance(node, ast.ClassDef)):
                methods = {node.name for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
                if not set(METHODS) <= methods:
                    continue
                row = {'service_member': member, 'class': cls.name, 'accepted': None}
                try:
                    model_member, origin = model_origin(raw, cls, member)
                    model = bundle.read(model_member).decode('utf-8-sig')
                    records = bind_records(bundle, raw)
                    declared = dependency(bundle, member)
                    work += 8 * len(epochs) * (2 * len(requests) + 3 * max(len(e['rows']) for e in epochs) + 4)
                    if work > MAX_NATIVE_WORK:
                        raise AdmissionError('aggregate source-cache native work cap exceeded', 'inconclusive')
                    comparison = compare_versioned_cache(raw, model, epochs, requests, class_name=cls.name)
                    row.update(status=comparison['status'], accepted=comparison['accepted'], model_member=model_member,
                        model_origin=origin, source_record_binding=records, dependency=declared, comparison=comparison)
                except (AdmissionError, UnicodeError) as error:
                    row.update(status=getattr(error, 'status', 'invalid'), reason=str(error))
                candidates.append(row)
                if len(candidates) > 16:
                    raise AdmissionError('candidate service cap exceeded', 'inconclusive')
        compared = [row for row in candidates if type(row['accepted']) is bool]
        failed = any(row['accepted'] is False for row in compared)
        complete = bool(candidates) and len(compared) == len(candidates)
        return {'status': 'mismatch' if failed else 'equivalent' if complete else 'partial' if candidates else 'missing_input',
            'accepted': False if failed else True if complete else None, 'candidate_services': candidates,
            'selected_source_chain_comparisons': len(compared), 'python_members_scanned': len(names),
            'archive_sha256': hashlib.sha256(bundle.path.read_bytes()).hexdigest(), 'source_members_read': bundle.read_members,
            'manual_project_paths_classes_schema_imports_or_model_maps': False,
            'supported_idiom': 'five admitted version-cache methods, fixed imported record protocol, direct default model and exact engine declaration',
            'explicit_given_contract': 'cold empty owned cache and serial lock, stable immutable repository epochs and no model override; not inferred actual issuer/database or startup state',
            'cold_empty_cache_and_serial_lock_are_supplied_premises': True,
            'source_applications_orm_tests_or_services_executed': False, 'whole_application_verified': False}
    finally:
        bundle.close()
