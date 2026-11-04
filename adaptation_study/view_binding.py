"""Passive source defaults admitted against a frozen native view-base MRO.

This checks the selected class-declaration profile, not router/action dispatch,
module initialization or runtime instance overrides. No application is loaded.
"""
import ast
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
ART = ROOT.parent
sys.path[:0] = [str(ART / 'src'), str(ART / 'source_study/code')]
from source_bindings import require_import_bindings, require_static_definitions
from native_casbin import AdmissionError
from credential_flow_ir import Unsupported

ITEM = 'src/pretix/api/views/item.py'
MIXIN = 'src/pretix/api/views/__init__.py'
MIXIN_SHA = '65b4a1947a20ce20dd8cd9a014d1a4f9830fb3076610d4573838ef2a09b15621'
FIELDS = frozenset(('permission', 'write_permission'))
HOOKS = frozenset(('_get_permission_name', '__getattr__', '__getattribute__', '__setattr__',
                   '__init__', 'initial', 'initialize_request', 'dispatch', 'as_view'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def declarations(item, mixin):
    """Resolve the selected literal slots, leaving native inheritance to its gate."""
    try:
        require_import_bindings(item, {'viewsets': ('rest_framework', 0, 'viewsets'),
                                      'ConditionalListView': ('pretix.api.views', 0, 'ConditionalListView')})
        tree, base_tree = ast.parse(item), ast.parse(mixin)
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name.endswith('ViewSet')]
        if not classes:
            raise Unsupported('no direct selected view declarations')
        require_static_definitions(tree, [n.name for n in classes])
        require_static_definitions(base_tree, ['ConditionalListView'])
    except (AdmissionError, SyntaxError, ValueError) as error:
        raise Unsupported('view source declaration is not admitted: '+str(error)) from error
    base = next(n for n in base_tree.body if isinstance(n, ast.ClassDef) and n.name == 'ConditionalListView')
    if base.bases or base.keywords or base.decorator_list:
        raise Unsupported('source mixin inheritance is not closed')
    # Only a business list method is present; the mixin cannot supply the
    # selected dynamic permission hook or a class/instance attribute protocol.
    if len(base.body) != 1 or any(not isinstance(n, ast.FunctionDef) or n.name != 'list' for n in base.body):
        raise Unsupported('unreviewed source mixin declaration')
    output = []
    for cls in classes:
        bases = [ast.unparse(n) for n in cls.bases]
        if (cls.keywords or cls.decorator_list or bases not in (
                ['viewsets.ModelViewSet'], ['ConditionalListView', 'viewsets.ModelViewSet'])):
            raise Unsupported('view base or decorator needs a separate admission')
        literals, locations = {}, {}
        for n in cls.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if n.name in HOOKS or n.name in FIELDS:
                    raise Unsupported('view overrides a permission/initialization hook')
                for child in ast.walk(n):
                    if (isinstance(child, ast.Attribute) and isinstance(child.ctx, (ast.Store, ast.Del))
                            and child.attr in FIELDS | HOOKS):
                        raise Unsupported('view method mutates a permission slot')
                    if (isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                            and child.func.id in ('setattr', 'delattr', 'exec', 'eval')):
                        raise Unsupported('reflective view mutation is not admitted')
                    if isinstance(child, ast.keyword) and child.arg in FIELDS | HOOKS:
                        raise Unsupported('action/initializer permission override is not admitted')
                continue
            selected = [x for x in ast.walk(n) if isinstance(x, ast.Name)
                        and isinstance(x.ctx, (ast.Store, ast.Del)) and x.id in FIELDS | HOOKS]
            if not selected:
                continue
            if (not isinstance(n, ast.Assign) or len(n.targets) != 1 or not isinstance(n.targets[0], ast.Name)
                    or n.targets[0].id not in FIELDS or not isinstance(n.value, ast.Constant)
                    or type(n.value.value) not in (str, type(None))):
                raise Unsupported('view permission slot is not a direct scalar declaration')
            name = n.targets[0].id
            if name in literals:
                raise Unsupported('view permission slot is rebound')
            literals[name] = n.value.value
            locations[name] = n.lineno
        if set(literals) != FIELDS:
            raise Unsupported('complete direct view defaults are required')
        output.append(dict(view=cls.name, class_line=cls.lineno, bases=bases,
                           fields=literals, source_lines=locations))
    return dict(views=output, mixin_line=base.lineno, mixin='ConditionalListView',
                declaration_profile='direct defaults with no dynamic/instance/action override',
                original_application_modules_executed=False)


def native_base_facts(base, framework):
    """Check the actual trusted base origin, MRO and absence of dynamic slots."""
    framework = Path(framework).resolve()
    runtime = json.loads(gzip.decompress((ROOT / 'native-header-runtime.json.gz').read_bytes()))
    if (type(base) is not type or base.__name__ != 'ModelViewSet'
            or base.__module__ != 'rest_framework.viewsets'):
        raise Unsupported('selected native base is not ModelViewSet')
    files, names = {}, []
    for cls in base.__mro__:
        if cls is object:
            continue
        if type(cls) is not type or set(vars(cls)) & {'_get_permission_name', '__getattr__', '__getattribute__', '__setattr__'}:
            raise Unsupported('native base adds dynamic permission lookup')
        module = sys.modules.get(cls.__module__)
        source = Path(getattr(module, '__file__', '')).resolve()
        if module is None or getattr(module, cls.__name__, None) is not cls or not source.is_relative_to(framework):
            raise Unsupported('native base origin is outside the frozen runtime')
        rel = source.relative_to(framework).as_posix()
        actual = sha(source.read_bytes())
        if runtime['unpacked_files'].get(rel) != actual:
            raise Unsupported('native base source identity differs')
        files[rel] = actual
        names.append(cls.__module__+'.'+cls.__qualname__)
    return dict(MRO=names, source_bindings=files, dynamic_permission_hook_absent=True)


def source_view_gate(base, framework, *, instance_overrides=None):
    if type(instance_overrides) not in (dict, type(None)) or instance_overrides not in (None, {}):
        raise Unsupported('runtime instance overrides are not admitted by source defaults')
    import pretix_event_profile as event
    item = event.source()[ITEM]
    mixin = (ROOT / 'pretix-view-base.txt').read_bytes()
    if sha(mixin) != MIXIN_SHA:
        raise Unsupported('original source mixin identity differs')
    report = declarations(item, mixin)
    report['native_base'] = native_base_facts(base, framework)
    selected = [row for row in report['views'] if row['view'] == 'ItemViewSet']
    if len(selected) != 1 or selected[0]['fields'] != {'permission': None, 'write_permission': 'event.items:write'}:
        raise Unsupported('source defaults do not match the existing finite item-permission consumer')
    report.update(source_bindings={ITEM: sha(item), MIXIN: sha(mixin)}, selected_view='ItemViewSet',
                  selected_fields=selected[0]['fields'], selected_fields_checked_against_consumer=True,
                  no_instance_overrides=True, router_dispatch_or_module_initialization_verified=False)
    return report
