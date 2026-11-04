"""Passive default-core registry to source team grants to selected item checks.

The registry is a fixed projection of one original receiver, not discovery of
the application's runtime signal/plugin configuration. No app module executes.
"""
import argparse
import ast
from copy import deepcopy
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parent
ART = ROOT.parent
sys.path[:0] = [str(ROOT), str(ART / 'src'), str(ART / 'source_study/code')]
import pretix_event_profile as event
from effect_slice import Capability, DataRecord, EffectInterpreter, Generator, extract_effect_program
from native_casbin import AdmissionError
from policy_slice import Call
from source_bindings import require_import_bindings, require_static_definitions
from profiles import Body, Record, Ref, TokenNative, AuthFailure, function
from chained_profiles import check_runtime, BoundaryMismatch

REGISTRY = 'src/pretix/base/permissions.py'
LEGACY = 'src/pretix/helpers/permission_migration.py'
SOURCES = {
    'pretix-core-registry.txt': (REGISTRY, '08df9d8e2d23f79348848afa18c0008e02fb1f72ea163043f60ef643515655b1'),
    'pretix-legacy-permissions.txt': (LEGACY, 'ce3b80c09a81ea089aaaf9112d08580f81e37bdd237cdd66958852961a7e7662'),
}


def unique(tree, kind, name):
    values = [n for n in tree.body if isinstance(n, kind) and n.name == name]
    if len(values) != 1:
        raise AdmissionError('ambiguous original declaration: '+name)
    return values[0]


def registry_projection(raw):
    tree = ast.parse(raw)
    require_import_bindings(raw, {'NamedTuple': ('typing', 0, 'NamedTuple'),
        'receiver': ('django.dispatch', 0, 'receiver'),
        'register_event_permission_groups': ('pretix.base.signals', 0, 'register_event_permission_groups')})
    name = 'register_default_event_permissions'
    require_static_definitions(tree, [name, 'PermissionGroup'], set())
    cls = unique(tree, ast.ClassDef, 'PermissionGroup')
    if (len(cls.bases) != 1 or ast.dump(cls.bases[0]) != "Name(id='NamedTuple', ctx=Load())"
            or cls.decorator_list or cls.keywords or any(not isinstance(n, ast.AnnAssign) for n in cls.body)
            or [n.target.id for n in cls.body] != ['name', 'label', 'actions', 'options', 'help_text']):
        raise AdmissionError('unadmitted permission-group shape')
    node = unique(tree, ast.FunctionDef, name)
    if (len(node.body) != 1 or not isinstance(node.body[0], ast.Return)
            or not isinstance(node.body[0].value, ast.List) or len(node.decorator_list) != 1):
        raise AdmissionError('registry must be a direct literal receiver result')
    decorator = node.decorator_list[0]
    if (not isinstance(decorator, ast.Call) or ast.unparse(decorator.func) != 'receiver'
            or len(decorator.args) != 1 or ast.unparse(decorator.args[0]) != 'register_event_permission_groups'
            or len(decorator.keywords) != 1 or decorator.keywords[0].arg != 'dispatch_uid'
            or ast.literal_eval(decorator.keywords[0].value) != 'base_register_default_event_permissions'):
        raise AdmissionError('unexpected source receiver binding')
    groups = {}
    for call in node.body[0].value.elts:
        if (not isinstance(call, ast.Call) or ast.unparse(call.func) != 'PermissionGroup' or call.args
                or len({k.arg for k in call.keywords}) != len(call.keywords)
                or set(k.arg for k in call.keywords) - {'name','label','actions','options','help_text'}):
            raise AdmissionError('registry entry is not direct keyword metadata')
        fields = {k.arg:k.value for k in call.keywords}
        if not {'name','label','actions','options'} <= set(fields):
            raise AdmissionError('registry entry is incomplete')
        try:
            name, actions = ast.literal_eval(fields['name']), ast.literal_eval(fields['actions'])
        except (ValueError, TypeError) as error:
            raise AdmissionError('registry names and actions must be literals') from error
        if (type(name) is not str or not name or ':' in name or len(name) > 128 or name in groups
                or type(actions) is not list or not 1 <= len(actions) <= 128
                or any(type(a) is not str or not a or ':' in a or len(a) > 128 for a in actions)
                or len(set(actions)) != len(actions)):
            raise AdmissionError('duplicate or malformed registry metadata')
        groups[name] = tuple(actions)
    if not 1 <= len(groups) <= 128:
        raise AdmissionError('registry group envelope exceeded')
    return groups, node.lineno


def legacy_projection(raw, modern):
    tree = ast.parse(raw)
    name = 'OLD_TO_NEW_EVENT_COMPAT'
    nodes = [n for n in tree.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    if len(nodes) != 1 or len(nodes[0].targets) != 1 or not isinstance(nodes[0].value, ast.Dict):
        raise AdmissionError('legacy mapping is not a unique literal')
    node = nodes[0]
    if any(isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, (ast.Store, ast.Del))
           and n is not node.targets[0] for n in ast.walk(tree)):
        raise AdmissionError('legacy mapping is rebound')
    try:
        keys = [ast.literal_eval(k) for k in node.value.keys]
        result = ast.literal_eval(node.value)
    except (ValueError, TypeError) as error:
        raise AdmissionError('legacy mapping requires literal metadata') from error
    if (len(keys) != len(set(keys)) or not 1 <= len(result) <= 128
            or any(type(k) is not str or not k.startswith('can_') or type(v) is not list
                or not 1 <= len(v) <= 128 or any(type(p) is not str or p not in modern for p in v)
                or len(set(v)) != len(v) for k,v in result.items())):
        raise AdmissionError('legacy mapping is malformed or outside core registry')
    return result, node.lineno


class GrantInterpreter(EffectInterpreter):
    """Narrow plain-data iteration, string-set updates and lazy all()."""
    def value(self, node, env):
        if isinstance(node, ast.Attribute) and node.attr in ('values', 'items', 'add'):
            base = self.value(node.value, env)
            if type(base) is dict and node.attr in ('values', 'items') and len(base) <= 128:
                return Call('grant-dict', base, node.attr)
            if type(base) is set and node.attr == 'add':
                self.string_set(base)
                return Call('grant-set', base, node.attr)
            raise AdmissionError('grant operation requires a bounded plain container')
        return super().value(node, env)

    def call(self, f, args, kwargs, env):
        self.charge()
        if f.kind == 'grant-dict' and not args and not kwargs:
            return list(f.value.values()) if f.method == 'values' else list(f.value.items())
        if f.kind == 'grant-set' and len(args) == 1 and not kwargs:
            if type(args[0]) is not str or len(args[0]) > 4096 or len(f.value) >= 128 and args[0] not in f.value:
                raise AdmissionError('grant set update exceeds its string envelope')
            f.value.add(args[0])
            return None
        if f.kind == 'effect-builtin' and f.value == 'set' and not args and not kwargs:
            return set()
        if f.kind == 'grant-all' and len(args) == 1 and not kwargs and isinstance(args[0], Generator):
            generator = args[0]
            if generator.consumed:
                return True
            generator.consumed = True
            gen = generator.node.generators[0]
            for item in self.sequence(self.value(gen.iter, generator.environment)):
                self.charge()
                local = {**generator.environment, gen.target.id:item}
                if all(self.truth(self.value(test, local)) for test in gen.ifs):
                    if not self.truth(self.value(generator.node.elt, local)):
                        return False
            return True
        return super().call(f, args, kwargs, env)


class CoreGrants:
    def __init__(self):
        raw = {}
        self.bindings = {}
        for name,(path,expected) in SOURCES.items():
            data = (ROOT / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                raise AdmissionError('passive source identity differs')
            raw[path] = data
            self.bindings[path] = expected
        self.groups, self.registry_line = registry_projection(raw[REGISTRY])
        self.modern = sorted(n+':'+a for n,actions in self.groups.items() for a in actions)
        self.legacy, self.legacy_line = legacy_projection(raw[LEGACY], set(self.modern))
        original = event.source()
        self.bindings[event.TOKEN] = event.SOURCE_HASHES[event.TOKEN]
        require_import_bindings(original[event.TOKEN], {
            'OLD_TO_NEW_EVENT_COMPAT': ('helpers.permission_migration', 3, 'OLD_TO_NEW_EVENT_COMPAT')})
        node = event.functions(original, event.TOKEN, 'Team', ('event_permission_set',))['event_permission_set']
        self.team_line = node.lineno
        imports = [n for n in ast.walk(node) if isinstance(n, (ast.Import, ast.ImportFrom))]
        if (len(imports) != 1 or node.body[0] is not imports[0]
                or ast.unparse(imports[0]) != 'from ..permissions import get_all_event_permission_groups'):
            raise AdmissionError('unexpected local registry import')
        # Resolve this one declaration to fixed core metadata; preserve every
        # remaining source statement. No Python application import executes.
        node.body = node.body[1:]
        validation = deepcopy(node)
        for child in ast.walk(validation):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store) and child.id in ('all','get_all_event_permission_groups','OLD_TO_NEW_EVENT_COMPAT'):
                raise AdmissionError('grant binding is shadowed')
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == 'all':
                if len(child.args) != 1 or child.keywords or not isinstance(child.args[0], ast.GeneratorExp):
                    raise AdmissionError('unadmitted quantifier shape')
                child.func.id = 'tuple'
        module = ast.Module(body=[ast.ClassDef(name='Selected', bases=[], keywords=[], body=[validation], decorator_list=[])], type_ignores=[])
        self.program = extract_effect_program(ast.unparse(ast.fix_missing_locations(module)).encode(), 'Selected', ('event_permission_set',))
        self.program['event_permission_set'].body = deepcopy(node.body)

    @staticmethod
    def validate(flag, stored, include):
        if (type(flag) is not bool or type(include) is not bool or type(stored) is not dict or len(stored) > 128
                or any(type(k) is not str or not k or len(k) > 128 or v is not True for k,v in stored.items())):
            raise AdmissionError('team input is outside the source-save-compatible raw JSON profile')

    def reference(self, flag, stored, include=True):
        self.validate(flag, stored, include)
        result = set(self.modern) if flag else set(self.modern) & set(stored)
        if include:
            result |= {old for old,new in self.legacy.items() if flag or set(new) <= set(stored)}
            if 'can_change_event_settings' in result:
                result.add('can_change_settings')
        return result

    def build(self, flag, stored, include=True):
        self.validate(flag, stored, include)
        groups = {n:DataRecord('PermissionGroup',dict(name=n,actions=list(a))) for n,a in self.groups.items()}
        machine = GrantInterpreter(self.program, DataRecord('Team', dict(all_event_permissions=flag,limit_event_permissions=dict(stored))), {
            'OLD_TO_NEW_EVENT_COMPAT':deepcopy(self.legacy), 'all':Call('grant-all'),
            'get_all_event_permission_groups':Capability('fixed default-core registry result',lambda:groups)})
        return machine.run('event_permission_set', [], {'include_legacy':include})


def raw_profiles():
    return [('empty',False,{}), ('item-write',False,{'event.items:write':True}),
        ('unregistered-item-read',False,{'event.items:read':True}), ('all-core',True,{}),
        ('general-settings',False,{'event.settings.general:write':True}),
        ('legacy-only',False,{'can_change_items':True}), ('order-write',False,{'event.orders:write':True}),
        ('item-and-unknown',False,{'event.items:write':True,'owned.unregistered:read':True})]


def run(framework, control=None):
    check_runtime(framework)
    sys.path.insert(0,str(Path(framework).resolve()))
    from django.conf import settings
    settings.configure(SECRET_KEY='owned-core-grant-study', INSTALLED_APPS=[], USE_I18N=False)
    import django
    django.setup()
    from django.http import HttpRequest
    from rest_framework.authentication import TokenAuthentication
    from rest_framework.exceptions import AuthenticationFailed
    from rest_framework.viewsets import ModelViewSet
    from view_binding import source_view_gate
    view = source_view_gate(ModelViewSet, framework)
    core = CoreGrants()
    raw = (ROOT/'pretix-token-source.txt').read_bytes()
    if hashlib.sha256(raw).hexdigest() != '3561f5434047af5f4115c0253993bf98d9ecd04c38f58e0846e7b92654c0ed10':
        raise AdmissionError('original token-authenticator identity differs')
    require_import_bindings(raw, {'TokenAuthentication':('rest_framework.authentication',0,'TokenAuthentication'),
        'TeamAPIToken':('pretix.base.models.organizer',0,'TeamAPIToken'), 'AnonymousUser':('django.contrib.auth.models',0,'AnonymousUser')})
    auth = function(raw.decode(), 'TeamTokenAuthentication', 'authenticate_credentials')
    # Exact authenticator declaration and native parent were already admitted
    # by the independently replayed header profile; bind its current result.
    old = json.loads(gzip.decompress((ROOT/'chained-header.json.gz').read_bytes()))
    if old['source_view_binding'] != view or old['framework']['authentication_module_sha256'] != hashlib.sha256(Path(sys.modules['rest_framework.authentication'].__file__).read_bytes()).hexdigest():
        raise AdmissionError('previously admitted native prefix identity differs')
    class Adapter(TokenAuthentication):
        def authenticate_credentials(self, key):
            try:
                return Body(auth,self.native,{'exceptions':Record('Exceptions',{'AuthenticationFailed':Ref('AuthenticationFailed')}), 'AnonymousUser':Ref('AnonymousUser')}).run([Record('Authenticator',{}),key])
            except AuthFailure as error:
                raise AuthenticationFailed(str(error)) from None
    exhaustive = 0
    for bits,flag,include in (() if control else itertools.product(range(1 << len(core.modern)), (False,True), (False,True))):
        stored = {name:True for i,name in enumerate(core.modern) if bits & (1 << i)}
        if core.build(flag,stored,include) != core.reference(flag,stored,include):
            raise BoundaryMismatch('core grant construction differs from direct equation')
        exhaustive += 1
    compiled = event.programs(event.source())
    rows = []
    base = [c for c in event.contexts() if not c['permissions']]
    for profile,flag,stored in raw_profiles():
        for c,condition in itertools.product(base, ('active','inactive','missing','malformed')):
            with sqlite3.connect(':memory:') as db:
                db.execute('CREATE TABLE owned_token(id INTEGER,token TEXT,active INTEGER)')
                db.execute('CREATE TABLE owned_team(id INTEGER,all_core INTEGER,raw_grants TEXT)')
                db.execute('INSERT INTO owned_team VALUES(1,?,?)',(int(flag),json.dumps(stored,sort_keys=True)))
                if condition != 'missing':
                    db.execute('INSERT INTO owned_token VALUES(1,?,?)',('owned-normal-token',int(condition!='inactive')))
                row = db.execute('SELECT all_core,raw_grants FROM owned_team WHERE id=1').fetchone()
                team = Record('Team',dict(all_core=bool(row[0]),raw_grants=json.loads(row[1])))
                records = {1:Record('Token',dict(team=team))}
                native = TokenNative(db, records)
                adapter = Adapter()
                adapter.native = native
                req = HttpRequest()
                req.META['HTTP_AUTHORIZATION'] = 'Token' if condition == 'malformed' else 'Token owned-normal-token'
                stage,permission,grant_calls,full = 'authenticated',None,[],None
                try:
                    user, returned = adapter.authenticate(req)
                except AuthenticationFailed:
                    stage = 'rejected'
                else:
                    if returned is not records[1] or returned.fields['team'] is not team or user.fields['is_authenticated'] is not False:
                        raise BoundaryMismatch('grant-chain token/team identity changed')
                    def grants():
                        nonlocal full
                        facts = returned.fields['team'].fields
                        actual_flag = False if control == 'drop_all' else facts['all_core']
                        full = core.build(actual_flag, facts['raw_grants'])
                        if control == 'raw_keys':
                            full |= set(facts['raw_grants'])
                        if control == 'drop_legacy':
                            full = {p for p in full if ':' in p}
                        grant_calls.append(sorted(full))
                        # Selected item view tests only this registered name.
                        return full & {'event.items:write'}
                    permission,_ = event.observe(c, compiled, grant_builder=grants)
                want_full = core.reference(flag,stored)
                expected_c = dict(c,permissions=sorted(want_full & {'event.items:write'}))
                want = event.reference(expected_c) if condition == 'active' else None
                access = condition == 'active' and event.reference(dict(c,permissions=[]))['organizer'] is not None
                if (stage != ('authenticated' if condition=='active' else 'rejected') or permission != want
                        or len(grant_calls) != int(access) or (access and full != want_full)
                        or native.lookups != int(condition!='malformed')):
                    raise BoundaryMismatch('raw team configuration / source grants / item boundary differs')
                rows.append(dict(profile=profile,event_context=c['id'],condition=condition,stage=stage,
                    credential_lookups=native.lookups,grant_calls=len(grant_calls),full_grants=sorted(full) if full is not None else None,
                    observed=permission,expected=want))
    from finite_observation_diagnosis import diagnose_observations
    properties = [dict(id=f'grant-chain-{i}',expected=True,observed=r['observed']==r['expected']) for i,r in enumerate(rows)]
    return dict(source_bindings=core.bindings, registry_groups=core.groups, modern_permissions=core.modern,
        compatibility=core.legacy, source_lines=dict(registry=core.registry_line,legacy=core.legacy_line,team=core.team_line),
        exhaustive_grant_configurations=exhaustive,contexts=len(rows),raw_profiles=[dict(name=n,all_core=f,raw_grants=s) for n,f,s in raw_profiles()],
        source_view_binding=view,source_authenticator_sha256=hashlib.sha256(raw).hexdigest(),
        authenticated=sum(r['stage']=='authenticated' for r in rows),grant_constructions=sum(r['grant_calls'] for r in rows),
        rows=rows,differences=0,diagnostic_consumer=diagnose_observations(properties),
        selected_legacy_alias_included=True,original_application_modules_executed=False,new_independent_applications=0,
        registry_scope='one fixed original default-core receiver; no extra/replacing runtime plugin receivers',
        configuration_scope='raw saved team JSON with true-only values; unknown names stored but not made core grants',
        consumer_scope='GET/HEAD and item write default only; full set retained, projected item-write membership; no arbitrary view or plugin equivalence',
        historical_given_grant_profiles_unchanged=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--framework',type=Path,required=True)
    p.add_argument('--check',action='store_true')
    p.add_argument('--control',choices=['drop_all','raw_keys','drop_legacy'])
    a = p.parse_args()
    try:
        report = run(a.framework,a.control)
    except BoundaryMismatch as error:
        if not a.control:
            raise
        print(json.dumps(dict(control=a.control,deliberate_fault_detected=True,reason=str(error))))
        return
    if a.control:
        raise ValueError('deliberate grant fault not detected')
    report = json.loads(json.dumps(report,sort_keys=True))
    target = ROOT/'source-grants.json.gz'
    if a.check:
        if json.loads(gzip.decompress(target.read_bytes())) != report:
            raise ValueError('source-grant result differs from current replay')
    else:
        target.write_bytes(gzip.compress(json.dumps(report,sort_keys=True).encode(),mtime=0))
    print(json.dumps({k:v for k,v in report.items() if k not in ('rows','diagnostic_consumer','source_view_binding')},indent=2))


if __name__ == '__main__':
    main()
