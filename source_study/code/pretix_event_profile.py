"""Bounded token/event permission-source projection on owned records.

Application AST is interpreted as data. Authentication success, resolved view
slots and a complete team permission set are explicit entry contracts, not
guessed implementations of sessions, OAuth, plugins or authentication.
"""
import ast
from copy import deepcopy
import hashlib
import itertools
import json
from pathlib import Path
import sqlite3
import sys
import zipfile

ROOT=Path(__file__).resolve().parent
PRIVATE=(ROOT/'source_archives').is_dir()
sys.path.insert(0,str(ROOT/'workspace/artifact/src' if PRIVATE else ROOT.parents[1]/'src'))
from effect_slice import Capability,DataRecord,EffectInterpreter,RecordType
from native_casbin import AdmissionError
from policy_slice import Call
from source_bindings import require_import_bindings,require_static_class_members

SNAPSHOT='da622e67528c9ff15ecd998dc3e452ec42f0fc9c'
PERMISSION='src/pretix/api/auth/permission.py'
TOKEN='src/pretix/base/models/organizer.py'
MEMBERS=(PERMISSION,TOKEN,'src/pretix/base/models/auth.py','src/pretix/api/views/item.py')
VALID=frozenset(('event.items:read','event.items:write'))
SOURCE_HASHES={PERMISSION:'fd6b76ca6a039a9bc4b60e3a916fb69764dc7de7b47b0f18485898ec65e62fb9',
    TOKEN:'8e5a6e38022d37ecc6d411bc72251dd64ef9513aa78049bbc662cdf3ea6c5473',
    'src/pretix/base/models/auth.py':'acf52f385a5527f3e0a603f08c4a1ba8ca297abf9425cfce2830a81aa6c56866',
    'src/pretix/api/views/item.py':'f3f24db4d15f14f141e6516d0a0fb35ce881256df17558ad6aa15daf8abb5ef1'}


def source():
    if PRIVATE:
        with zipfile.ZipFile(ROOT/'source_archives/23791087.zip') as z:
            members={n.partition('/')[2]:n for n in z.namelist() if not n.endswith('/')}
            raw={p:z.read(members[p]) for p in MEMBERS}
    else:raw={p:(ROOT.parent/'source/pretix'/p).read_bytes() for p in MEMBERS}
    for p in MEMBERS:
        if hashlib.sha256(raw[p]).hexdigest()!=SOURCE_HASHES[p]:raise ValueError('selected source changed')
    require_import_bindings(raw[PERMISSION],{'TeamAPIToken':('pretix.base.models.organizer',0,'TeamAPIToken'),
        'Event':('pretix.base.models',0,'Event'),'EventPermissionSet':('pretix.base.models.auth',0,'EventPermissionSet')})
    return raw


def functions(raw,path,cls,names):
    tree=ast.parse(raw[path]);classes=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==cls]
    if len(classes)!=1:raise AdmissionError('ambiguous selected source class')
    require_static_class_members(classes[0],names)
    return {n.name:deepcopy(n) for n in classes[0].body if isinstance(n,ast.FunctionDef) and n.name in names}


def programs(raw):
    # Only the original complete function bodies are selected. Class construction,
    # imports, decorators and module-level application code never execute.
    from effect_slice import extract_effect_program
    methods=functions(raw,PERMISSION,'EventPermission',('has_permission',))
    token=functions(raw,TOKEN,'TeamAPIToken',('get_event_permission_set','has_event_permission'))
    def compile_selected(nodes):
        module=ast.Module(body=[ast.ClassDef(name='Selected',bases=[],keywords=[],body=list(nodes.values()),decorator_list=[])],type_ignores=[])
        validation=deepcopy(module)
        # The generic admission validator recognizes bounded collection
        # consumers, but not lazy any(). Validate only its generator shape as
        # a tuple consumer; execute the untouched original function bodies.
        # The current scalar-permission profile never reaches these list-only
        # branches. If reached, any remains unbound and fails closed.
        for call in ast.walk(validation):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='any':
                if len(call.args)!=1 or call.keywords or not isinstance(call.args[0],ast.GeneratorExp):
                    raise AdmissionError('unreviewed quantifier syntax')
                call.func.id='tuple'
        checked=extract_effect_program(ast.unparse(ast.fix_missing_locations(validation)).encode(),'Selected',tuple(nodes))
        for name,node in checked.items():node.body=deepcopy(nodes[name].body)
        return checked
    return compile_selected(methods),compile_selected(token)


class ProfileInterpreter(EffectInterpreter):
    """Typed ordinary-value operations missing from the generic effect profile."""
    @staticmethod
    def record_equal(a,b):
        if not isinstance(a,DataRecord) or not isinstance(b,DataRecord) or a.kind not in ('Event','Organizer') or b.kind not in ('Event','Organizer'):
            raise AdmissionError('model equality is outside the selected primary-key contract')
        return a.kind==b.kind and a.fields['pk']==b.fields['pk']

    def value(self,node,env):
        if isinstance(node,ast.Compare) and len(node.ops)==1 and isinstance(node.ops[0],(ast.Eq,ast.NotEq)):
            a=self.value(node.left,env);b=self.value(node.comparators[0],env)
            if isinstance(a,DataRecord) or isinstance(b,DataRecord):
                same=self.record_equal(a,b)
                return same if isinstance(node.ops[0],ast.Eq) else not same
            # Re-evaluating a source call could duplicate an effect. Non-record
            # comparisons in this profile need only these plain scalar values.
            if type(a) is type(b) and type(a) in (str,bool,int,type(None)):
                return (a==b) if isinstance(node.ops[0],ast.Eq) else (a!=b)
            raise AdmissionError('unsupported scalar comparison')
        if isinstance(node,ast.Compare) and len(node.ops)==1 and isinstance(node.ops[0],(ast.In,ast.NotIn)):
            a=self.value(node.left,env);b=self.value(node.comparators[0],env)
            if isinstance(a,DataRecord):
                if type(b) not in (list,tuple) or len(b)>8:raise AdmissionError('unbounded model membership')
                present=any(self.record_equal(a,v) for v in b)
            elif type(a) is str and type(b) in (tuple,list,dict,set,frozenset):present=a in b
            else:raise AdmissionError('unsupported membership profile')
            return present if isinstance(node.ops[0],ast.In) else not present
        return super().value(node,env)

    def call(self,function,args,kwargs,env):
        if function.kind=='effect-builtin' and not kwargs:
            if function.value=='set' and not args:return set()
            if function.value=='isinstance' and len(args)==2 and type(args[1]) is tuple:
                if not args[1] or not all(isinstance(t,RecordType) or isinstance(t,Call) and t.kind=='effect-builtin' and t.value in ('list','tuple') for t in args[1]):
                    raise AdmissionError('unbound type tuple')
                def match(t):
                    if isinstance(t,RecordType):return isinstance(args[0],DataRecord) and args[0].kind==t.kind
                    return type(args[0]) is {'list':list,'tuple':tuple}[t.value]
                return any(match(t) for t in args[1])
            if function.value=='getattr' and len(args)==2 and isinstance(args[0],DataRecord) and type(args[1]) is str:
                if args[1] not in args[0].fields:raise AdmissionError('missing selected source attribute')
                return args[0].fields[args[1]]
        return super().call(function,args,kwargs,env)


def contexts():
    return [dict(id=f'token-event-{i:04d}',all_events=all_events,limited_events=limited,
        query=query,method=method,permissions=list(perms),authenticated=False,token_kind='TeamAPIToken',
        validated_active_token=True,resolved_view_contract='event.items')
        for i,(all_events,limited,query,method,perms) in enumerate(itertools.product(
            (False,True),((),(1,),(2,)),('own-a','own-b','other','missing'),('GET','POST','HEAD'),
            ((),('event.items:read',),('event.items:write',),tuple(sorted(VALID)))))]


def reference(c):
    pk={'own-a':1,'own-b':2,'other':3,'missing':None}[c['query']]
    access=pk is not None and (c['all_events'] and pk in (1,2) or pk in c['limited_events'])
    return dict(allow=bool(access and (c['method'] in ('GET','HEAD') or 'event.items:write' in c['permissions'])),
        event=pk,organizer=1 if access else None,permissions=sorted(c['permissions']) if access else None)


def observe(c,compiled,*,omit_owner_contract=False):
    if (c.get('authenticated') is not False or c.get('token_kind')!='TeamAPIToken'
            or c.get('validated_active_token') is not True or c.get('resolved_view_contract')!='event.items'
            or c.get('method') not in ('GET','POST','HEAD') or c.get('query') not in ('own-a','own-b','other','missing')
            or type(c.get('all_events')) is not bool or type(c.get('permissions')) is not list
            or len(c['permissions'])>2 or any(p not in VALID for p in c['permissions']) or len(set(c['permissions']))!=len(c['permissions'])
            or type(c.get('limited_events')) not in (tuple,list) or len(c['limited_events'])>2
            or any(type(p) is not int or p not in (1,2) for p in c['limited_events']) or len(set(c['limited_events']))!=len(c['limited_events'])):
        raise AdmissionError('not in the validated team-token/event profile')
    organizers={i:DataRecord('Organizer',dict(pk=i,slug=f'o{i}')) for i in (1,2)}
    events={i:DataRecord('Event',dict(pk=i,slug=('a' if i in (1,3) else 'b'),organizer=organizers[1 if i in (1,2) else 2])) for i in (1,2,3)}
    team=DataRecord('Team',dict(organizer=organizers[1],all_events=c['all_events'],
        limit_events=DataRecord('GivenEventRelation',dict(all=Capability('owned related rows',lambda:[events[i] for i in c['limited_events']]))),
        event_permission_set=Capability('given complete team permission-set contract',lambda:set(c['permissions']))))
    token=DataRecord('TeamAPIToken',dict(team=team))
    bindings={n:RecordType(n,()) for n in ('Device','TeamAPIToken','User','OAuthAccessToken')}
    request=DataRecord('Request',dict(user=DataRecord('AnonymousUser',dict(is_authenticated=False)),auth=token,method=c['method']),
        frozenset(('event','organizer','eventpermset')))
    query_pk={'own-a':1,'own-b':2,'other':3,'missing':None}[c['query']]
    query_event=events.get(query_pk)
    request.fields['resolver_match']=DataRecord('Resolver',dict(kwargs={'organizer':query_event.fields['organizer'].fields['slug'] if query_event else 'o1',
        'event':query_event.fields['slug'] if query_event else 'absent'}))
    sql=[]
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE owned_event(id INTEGER PRIMARY KEY,slug TEXT,organizer_slug TEXT)')
        db.executemany('INSERT INTO owned_event VALUES(?,?,?)',[(i,e.fields['slug'],e.fields['organizer'].fields['slug']) for i,e in events.items()])
        def filtered(*,slug,organizer__slug):
            def first():
                row=db.execute('SELECT id FROM owned_event WHERE slug=? AND organizer_slug=? ORDER BY id LIMIT 1',(slug,organizer__slug)).fetchone()
                sql.append([slug,organizer__slug]);return events[row[0]] if row else None
            query=DataRecord('GivenQuery',dict(first=Capability('actual owned SQLite first',first)))
            def select_related(name):
                if name!='organizer':raise AdmissionError('unbound eager relation')
                return query
            query.fields['select_related']=Capability('given eager organizer relation',select_related)
            return query
        bindings.update(SAFE_METHODS=('GET','HEAD','OPTIONS'),
            hasattr=Capability('bounded attribute presence',lambda obj,name:isinstance(obj,DataRecord) and name in obj.fields),
            Event=DataRecord('EventClass',dict(objects=DataRecord('EventManager',dict(filter=Capability('owned event query',filtered))))),
            EventPermissionSet=Capability('given valid permission-name set class',lambda v:set(v)))
        token_machine=ProfileInterpreter(compiled[1],token,bindings)
        closures={name:token.fields[name] for name in compiled[1]}
        # Cross-receiver calls preserve the exact token and team records.
        for name in compiled[1]:
            token.fields[name]=Capability('source token method '+name,lambda *args,_name=name,**kwargs:token_machine.invoke(closures[_name],list(args),kwargs))
        if omit_owner_contract:
            token.fields['has_event_permission']=Capability('owned deliberately wrong handoff',lambda *args,**kwargs:True)
        machine=ProfileInterpreter(compiled[0],DataRecord('Permission',{}),bindings)
        allow=machine.run('has_permission',[request,DataRecord('ResolvedView',dict(permission=None,write_permission='event.items:write'))])
    event=request.fields.get('event');organizer=request.fields.get('organizer');perms=request.fields.get('eventpermset')
    actual=dict(allow=allow,event=event.fields['pk'] if event else None,
        organizer=organizer.fields['pk'] if organizer else None,permissions=sorted(perms) if perms is not None else None)
    return actual,dict(actual_SELECTs=len(sql),exact_event_identity=(event is events.get(query_pk)),source_modules_executed=False)


def run():
    raw=source();compiled=programs(raw);rows=[]
    for c in contexts():
        got,meta=observe(c,compiled);want=reference(c)
        if got!=want:raise ValueError('source/normal reference differs: '+json.dumps(dict(context=c,expected=want,actual=got)))
        rows.append(dict(context=c,expected=want,observed=got,**meta))
    return dict(repository='pretix/pretix',snapshot=SNAPSHOT,source_bindings={p:hashlib.sha256(v).hexdigest() for p,v in raw.items()},
        complete_source_bodies=['EventPermission.has_permission','TeamAPIToken.has_event_permission','TeamAPIToken.get_event_permission_set'],
        contexts=len(rows),differences=0,actual_SELECTs=sum(r['actual_SELECTs'] for r in rows),rows=rows,
        entry_contracts=['validated active TeamAPIToken; anonymous request.user','resolved concrete event.items view slots',
            'complete team grant set supplied; plugin registry/legacy expansion is not inferred',
            'coherent same-organizer limited-event relation','given primary-key equality and eager organizer mapping'],
        other_authentication_profiles='not admitted,not silently treated as false or passed',
        authentication_or_plugin_registry_certified=False,independent_gold_claimed=False)


if __name__=='__main__':
    report=run()
    if PRIVATE:
        out=ROOT/'verification/remaining-gap-closure';out.mkdir(exist_ok=True)
        (out/'pretix-event-profile.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))
