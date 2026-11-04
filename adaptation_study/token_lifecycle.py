"""Source EteSync token lifecycle connected to source-lowered owned queries.

Only passive original AST, standard datetime primitives and owned SQLite rows
are used. No application model, web service, framework dispatcher or test runs.
"""
import argparse
import ast
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parent
ART = ROOT.parent
sys.path[:0] = [str(ART/'src'),str(ART/'source_study/code')]
from effect_slice import Capability,DataRecord,EffectInterpreter,ErrorType,SliceFault,extract_effect_program
from policy_slice import Call,Return
from native_casbin import AdmissionError
from source_bindings import require_import_bindings,require_static_definitions
from query_guard_ir import compile_function,run_query

RID = 111317770
DEPENDENCIES = 'etebase_server/fastapi/dependencies.py'
MODELS = 'etebase_server/django/token_auth/models.py'
NOW = datetime(2026,1,1,tzinfo=timezone.utc)


class LifecycleMismatch(ValueError):
    pass


class CollectionMissing(Exception):
    pass


def source():
    data = json.loads(gzip.decompress((ROOT/'sources.json.gz').read_bytes()))
    case = next(r for r in data['rows'] if r['repository_id']==RID)
    modules = {m['path']:m for m in case['modules']}
    texts = {}
    for path in (DEPENDENCIES,MODELS):
        module = modules[path]
        raw = module['text'].encode('utf-8')
        if hashlib.sha256(raw).hexdigest()!=module['utf8_text_sha256']:
            raise AdmissionError('original selected EteSync text changed')
        texts[path] = raw
    return case,texts


def programs():
    case,raw = source()
    require_import_bindings(raw[DEPENDENCIES],{'timezone':('django.utils',0,'timezone'),
        'AuthToken':('etebase_server.django.token_auth.models',0,'AuthToken'),
        'get_default_expiry':('etebase_server.django.token_auth.models',0,'get_default_expiry'),
        'AuthenticationFailed':('exceptions',1,'AuthenticationFailed'),
        'models':('etebase_server.django',0,'models'),
        'get_object_or_404':('utils',1,'get_object_or_404')})
    require_import_bindings(raw[MODELS],{'timezone':('django.utils',0,'timezone')})
    trees = {k:ast.parse(v) for k,v in raw.items()}
    nodes = {}
    for path,names in ((DEPENDENCIES,('__renew_token','__get_authenticated_user')),
                       (MODELS,('get_default_expiry',))):
        require_static_definitions(trees[path],names)
        for name in names:
            values = [n for n in trees[path].body if isinstance(n,ast.FunctionDef) and n.name==name]
            if len(values)!=1:
                raise AdmissionError('ambiguous lifecycle body')
            nodes[name] = deepcopy(values[0])
    constants = {}
    for name,want in (('AUTO_REFRESH',True),('MIN_REFRESH_INTERVAL',60)):
        assignments = [n for n in trees[DEPENDENCIES].body if isinstance(n,ast.Assign)
                       and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
        if len(assignments)!=1 or len(assignments[0].targets)!=1 or not isinstance(assignments[0].value,ast.Constant):
            raise AdmissionError('lifecycle configuration is not literal')
        value = assignments[0].value.value
        if type(value) is not type(want) or value!=want:
            raise AdmissionError('default source lifecycle configuration differs')
        constants[name] = value
    validation = ast.Module(body=deepcopy(list(nodes.values())),type_ignores=[])
    for child in ast.walk(validation):
        if isinstance(child,ast.BinOp) and isinstance(child.op,(ast.Add,ast.Sub)):
            child.op = ast.BitOr()  # admission shape only; original nodes run below
        if isinstance(child,ast.ExceptHandler):
            if ast.unparse(child.type)!='AuthToken.DoesNotExist':
                raise AdmissionError('unadmitted source exception target')
            child.type = ast.Name(id='OwnedMissingToken',ctx=ast.Load())
    checked = extract_effect_program(ast.unparse(ast.fix_missing_locations(validation)).encode(),None,(),tuple(nodes))
    for name,node in checked.items():
        node.body = deepcopy(nodes[name].body)
    queries = {}
    declared = {'get_collection_queryset':'Depends(get_authenticated_user)',
                'get_collection':'Depends(get_collection_queryset)',
                'get_item_queryset':'Depends(get_collection)'}
    for name in ('get_collection_queryset','get_collection','get_item_queryset'):
        values = [n for n in trees[DEPENDENCIES].body if isinstance(n,ast.FunctionDef) and n.name==name]
        if len(values)!=1:
            raise AdmissionError('ambiguous source query consumer')
        if len(values[0].args.defaults)!=1 or ast.unparse(values[0].args.defaults[0])!=declared[name]:
            raise AdmissionError('source-declared query dependency differs')
        queries[name] = compile_function(values[0],{'models.Collection.objects':'collection','models.CollectionItem.objects':'item'},('get_object_or_404',))
    return checked,queries,constants,dict(repository=case['repository'],snapshot=case['snapshot'],
        original_text_bindings={k:hashlib.sha256(v).hexdigest() for k,v in raw.items()},
        functions={name:dict(line=n.lineno,end_line=n.end_lineno) for name,n in nodes.items()})


class TimeInterpreter(EffectInterpreter):
    @staticmethod
    def instant(value):
        return type(value) is datetime and value.tzinfo is timezone.utc

    def value(self,node,env):
        if isinstance(node,ast.Attribute):
            base = self.value(node.value,env)
            if type(base) is str and node.attr=='split':
                return Call('lifecycle-split',base)
            if type(base) is timedelta and node.attr=='total_seconds':
                return Call('lifecycle-seconds',base)
            if isinstance(base,DataRecord) and node.attr in base.fields:
                return base.fields[node.attr]
            raise AdmissionError('lifecycle attribute has no typed binding')
        if isinstance(node,ast.BinOp) and isinstance(node.op,(ast.Add,ast.Sub)):
            left,right = self.value(node.left,env),self.value(node.right,env)
            if isinstance(node.op,ast.Add) and self.instant(left) and type(right) is timedelta:
                return left+right
            if isinstance(node.op,ast.Sub) and self.instant(left) and self.instant(right):
                return left-right
            raise AdmissionError('lifecycle time operation is outside UTC datetime arithmetic')
        if isinstance(node,ast.Compare) and len(node.ops)==1 and isinstance(node.ops[0],(ast.Lt,ast.Gt)):
            left,right = self.value(node.left,env),self.value(node.comparators[0],env)
            time_pair = self.instant(left) and self.instant(right)
            numeric = (type(left) in (int,float) and type(right) in (int,float)
                       and math.isfinite(left) and math.isfinite(right) and abs(left)<10**12 and abs(right)<10**12)
            if not (time_pair or numeric):
                raise AdmissionError('lifecycle comparison has unbound time/numeric types')
            return left<right if isinstance(node.ops[0],ast.Lt) else left>right
        if isinstance(node,ast.Subscript):
            base,index = self.value(node.value,env),self.value(node.slice,env)
            if type(base) in (tuple,list) and type(index) is int and len(base)<=128:
                if not 0<=index<len(base):
                    raise SliceFault('IndexError','source token split has no second field')
                return base[index]
            raise AdmissionError('lifecycle subscription is not a bounded sequence')
        return super().value(node,env)

    def call(self,f,args,kwargs,env):
        self.charge()
        if f.kind=='lifecycle-split' and not args and not kwargs:
            if len(f.value)>4096:
                raise AdmissionError('header exceeds declared string envelope')
            values = f.value.split()
            if len(values)>128:
                raise AdmissionError('header split exceeds declared sequence envelope')
            return values
        if f.kind=='lifecycle-seconds' and not args and not kwargs:
            return f.value.total_seconds()
        return super().call(f,args,kwargs,env)

    def invoke(self,f,args,kwargs):
        if isinstance(f,ErrorType) and f.name=='AuthenticationFailed' and not args and set(kwargs)=={'detail'} and type(kwargs['detail']) is str:
            return SliceFault(f.name,kwargs['detail'])
        return super().invoke(f,args,kwargs)

    def statements(self,body,env):
        for node in body:
            if not isinstance(node,ast.Try):
                result = super().statements([node],env)
            else:
                self.charge()
                if node.orelse or node.finalbody or len(node.handlers)!=1:
                    raise AdmissionError('unadmitted lifecycle exception suite')
                handler = node.handlers[0]
                error_type = self.value(handler.type,env)
                if not isinstance(error_type,ErrorType) or error_type.name!='DoesNotExist' or handler.name:
                    raise AdmissionError('exception target differs from selected token manager')
                try:
                    result = self.statements(node.body,env)
                except SliceFault as fault:
                    if fault.name!=error_type.name:
                        raise
                    result = self.statements(handler.body,env)
            if isinstance(result,Return):
                return result
        return None


def stamp(value):
    return None if value is None else value.isoformat()


class Relation:
    def __init__(self,store,kind,filters=None):
        self.store,self.kind,self.filters = store,kind,dict(filters or {})
    def all(self):
        return self
    def filter(self,**kwargs):
        if set(kwargs)&set(self.filters):
            raise AdmissionError('query filter rebinding not declared')
        return Relation(self.store,self.kind,{**self.filters,**kwargs})
    def rows(self):
        f = self.filters
        if self.kind=='collection' and set(f) in ({'members__user'},{'members__user','uid'}):
            user = f['members__user']
            if not isinstance(user,DataRecord) or user is not self.store.users.get(user.fields.get('pk')):
                raise AdmissionError('query principal is not an exact owned user record')
            self.store.query_user = user
            sql = 'SELECT c.id FROM owned_collection c JOIN owned_member m ON m.collection_id=c.id WHERE m.user_id=?'
            params = [user.fields['pk']]
            if 'uid' in f:
                sql += ' AND c.uid=?'
                params.append(f['uid'])
            return [self.store.collections[r[0]] for r in self.store.db.execute(sql+' ORDER BY c.id',params)]
        if self.kind=='item' and set(f)=={'collection__pk','revisions__current'}:
            if type(f['collection__pk']) is not int or f['revisions__current'] is not True:
                raise AdmissionError('item query arguments outside current-revision contract')
            return [dict(pk=r[0],uid=r[1]) for r in self.store.db.execute(
                'SELECT i.id,i.uid FROM owned_item i JOIN owned_revision r ON r.item_id=i.id WHERE i.collection_id=? AND r.current=1 ORDER BY i.id',(f['collection__pk'],))]
        raise AdmissionError('query relation/filter outside selected source consumer')
    def get(self,**kwargs):
        values = self.filter(**kwargs).rows()
        if not values:
            raise CollectionMissing()
        if len(values)!=1:
            raise AdmissionError('duplicate-row lookup is outside this finite query profile')
        return values[0]


class Store:
    def __init__(self,user=1,active=True,expiry=None,present=True,control=None):
        self.db = sqlite3.connect(':memory:')
        self.user,self.control = user,control
        self.users = {i:DataRecord('User',dict(pk=i,is_active=active if i==user else True)) for i in (1,2)}
        self.db.executescript('CREATE TABLE owned_token(key TEXT PRIMARY KEY,user_id INTEGER,expiry TEXT);'
            'CREATE TABLE owned_collection(id INTEGER PRIMARY KEY,uid TEXT);'
            'CREATE TABLE owned_member(collection_id INTEGER,user_id INTEGER,PRIMARY KEY(collection_id,user_id));'
            'CREATE TABLE owned_item(id INTEGER PRIMARY KEY,collection_id INTEGER,uid TEXT);'
            'CREATE TABLE owned_revision(item_id INTEGER,current INTEGER,PRIMARY KEY(item_id,current));')
        if present:
            self.db.execute('INSERT INTO owned_token VALUES(?,?,?)',('owned-token',user,stamp(expiry)))
        self.db.execute('INSERT INTO owned_token VALUES(?,?,?)',('unrelated-token',3-user,stamp(NOW+timedelta(days=90))))
        self.collections = {i:dict(pk=i,uid='c'+str(i)) for i in (1,2)}
        self.db.executemany('INSERT INTO owned_collection VALUES(?,?)',[(i,'c'+str(i)) for i in (1,2)])
        self.db.executemany('INSERT INTO owned_item VALUES(?,?,?)',[(2*(c-1)+i,c,'i'+str(i)) for c in (1,2) for i in (1,2)])
        self.effects = Counter()
        self.returned_tokens = []
    def snapshot(self):
        return [list(r) for r in self.db.execute('SELECT key,user_id,expiry FROM owned_token ORDER BY key')]
    def lookup(self,*,key):
        self.effects['lookups'] += 1
        row = self.db.execute('SELECT key,user_id,expiry FROM owned_token WHERE key=?',(key,)).fetchone()
        if row is None:
            raise SliceFault('DoesNotExist','owned token absent')
        token = DataRecord('AuthToken',dict(user=self.users[row[1]],expiry=datetime.fromisoformat(row[2]) if row[2] else None),frozenset({'expiry'}))
        def delete():
            if self.control!='omit_delete':
                self.effects['deletes'] += self.db.execute('DELETE FROM owned_token WHERE key=?',(key,)).rowcount
        def save(*,update_fields):
            if update_fields!=('expiry',):
                raise AdmissionError('save field contract changed')
            if self.control!='omit_save':
                self.effects['saves'] += self.db.execute('UPDATE owned_token SET expiry=? WHERE key=?',(stamp(token.fields['expiry']),key)).rowcount
        token.fields.update(delete=Capability('owned token deletion',delete),save=Capability('owned expiry field save',save))
        self.returned_tokens.append(token)
        return token
    def authenticate(self,compiled,constants,header,clock):
        if not TimeInterpreter.instant(clock) or type(header) is not str or len(header)>4096:
            raise AdmissionError('entry requires a bounded header and fixed UTC request clock')
        def related(field):
            if field!='user':
                raise AdmissionError('unadmitted eager relation')
            return DataRecord('TokenQuery',dict(get=Capability('owned SQLite token lookup',self.lookup)))
        manager = DataRecord('TokenManager',dict(select_related=Capability('eager user identity contract',related)))
        bindings = dict(constants)
        bindings.update(timezone=DataRecord('UTC clock',dict(now=Capability('fixed request clock',lambda:clock),
            timedelta=Capability('standard thirty-day duration',lambda *,days:timedelta(days=days) if type(days) is int and days==30 else _unsupported_duration()))),
            AuthToken=DataRecord('TokenClass',dict(objects=manager,DoesNotExist=ErrorType('DoesNotExist'))),
            AuthenticationFailed=ErrorType('AuthenticationFailed'))
        machine = TimeInterpreter(compiled,DataRecord('Owned',{}),bindings)
        return machine.run('__get_authenticated_user',[header])
    def queries(self,programs,user,context):
        members,revisions,cuid,iuid = context
        self.db.execute('DELETE FROM owned_member')
        self.db.execute('DELETE FROM owned_revision')
        self.db.executemany('INSERT INTO owned_member VALUES(?,?)',[(c,u) for bit,(c,u) in enumerate(((1,1),(1,2),(2,1),(2,2))) if members&(1<<bit)])
        self.db.executemany('INSERT INTO owned_revision VALUES(?,?)',[(2*(c-1)+i,current) for c in (1,2) for i in (1,2) for current in (0,1) if not current or revisions&(1<<(i-1))])
        relations = {'collection':Relation(self,'collection'),'item':Relation(self,'item')}
        with self.db:
            query = run_query(programs['get_collection_queryset']['query'],{'user':user},relations)
            visible = [r['pk'] for r in query.rows()]
            try:
                collection = run_query(programs['get_collection']['query'],{'queryset':query,'collection_uid':cuid},relations)
                if collection is not self.collections[collection['pk']]:
                    raise LifecycleMismatch('queried collection identity was not transferred')
                items = run_query(programs['get_item_queryset']['query'],{'collection':collection},relations).rows()
                values = [r['pk'] for r in items if r['uid']==iuid]
                state = 'collection_found'
            except CollectionMissing:
                values,state = [],'collection_not_found'
        return dict(collections=visible,state=state,items=values)
    def close(self):
        self.db.close()


def _unsupported_duration():
    raise AdmissionError('unadmitted duration configuration')


def query_contexts():
    return [(0,0,'c1','i1'),(1,1,'c1','i1'),(1,0,'c1','i1'),(1,2,'c1','i2'),
        (2,3,'c1','i1'),(4,1,'c2','i1'),(8,2,'c2','i2'),(15,3,'c2','i1'),
        (15,3,'absent','i1'),(15,3,'c1','absent'),(6,2,'c1','i1'),(9,1,'c2','i2')]


def query_reference(user,context):
    mask,revisions,cuid,iuid = context
    members = {(1+bit//2,1+bit%2) for bit in range(4) if mask&(1<<bit)}
    visible = [c for c in (1,2) if (c,user) in members]
    cid = {'c1':1,'c2':2}.get(cuid)
    found = cid in visible
    items = [2*(cid-1)+i for i in (1,2) if found and iuid=='i'+str(i) and revisions&(1<<(i-1))]
    return dict(collections=visible,state='collection_found' if found else 'collection_not_found',items=items)


def states():
    return [('missing',True,None,False),('inactive-expired',False,NOW-timedelta(seconds=1),True),
        ('no-expiry',True,None,True),('expired',True,NOW-timedelta(seconds=1),True),
        ('equal-now',True,NOW,True),('renew-61',True,NOW+timedelta(days=30,seconds=-61),True),
        ('threshold-60',True,NOW+timedelta(days=30,seconds=-60),True),
        ('threshold-59',True,NOW+timedelta(days=30,seconds=-59),True),
        ('later-expiry',True,NOW+timedelta(days=31),True)]


def step(store,compiled,queries,constants,header,clock,control=None,query_checks=False):
    before = store.snapshot()
    old_effects = store.effects.copy()
    parts = header.split()
    record = next((r for r in before if len(parts)>=2 and r[0]==parts[1]),None)
    expected_state = 'malformed_source_error' if len(parts)<2 else 'rejected'
    expiry = datetime.fromisoformat(record[2]) if record and record[2] else None
    active = bool(record and store.users[record[1]].fields['is_active'])
    expected = deepcopy(before)
    saves = deletes = 0
    if record and active:
        if expiry is not None and expiry<clock:
            expected.remove(record)
            deletes = 1
        else:
            expected_state = 'authenticated'
            if expiry is not None and (clock+timedelta(days=30)-expiry).total_seconds()>60:
                next(r for r in expected if r[0]==record[0])[2] = stamp(clock+timedelta(days=30))
                saves = 1
    result = None
    try:
        result = store.authenticate(compiled,constants,header,clock)
        state = 'authenticated'
    except SliceFault as fault:
        if fault.name=='AuthenticationFailed':
            state = 'rejected'
        elif fault.name=='IndexError':
            state = 'malformed_source_error'
        else:
            raise
    delta = dict(lookups=store.effects['lookups']-old_effects['lookups'],
        saves=store.effects['saves']-old_effects['saves'],deletes=store.effects['deletes']-old_effects['deletes'])
    wanted_delta = dict(lookups=int(len(parts)>=2),saves=saves,deletes=deletes)
    if state!=expected_state or store.snapshot()!=expected or delta!=wanted_delta:
        raise LifecycleMismatch('source authentication/time/persisted credential state differs')
    observations = []
    if result is not None:
        user,token = result
        if token is not store.returned_tokens[-1] or user is not token.fields['user'] or user is not store.users[record[1]]:
            raise LifecycleMismatch('source returned user/token identity differs')
        mapped = store.users[3-record[1]] if control=='wrong_user' else user
        if query_checks:
            for context in query_contexts():
                actual = store.queries(queries,mapped,context)
                want = query_reference(record[1],context)
                if actual!=want or store.query_user is not user:
                    raise LifecycleMismatch('authenticated user to membership/revision consumer differs')
                observations.append(dict(context=list(context),expected=want,observed=actual))
        if store.snapshot()!=expected:
            raise LifecycleMismatch('query consumer unexpectedly mutated credential state')
    return dict(state=state,credential_effects=delta,credential_state=expected,query_observations=observations,
        exact_returned_identity=result is not None,clock=stamp(clock))


def run(control=None):
    compiled,queries,constants,identity = programs()
    if control=='disable_refresh':
        constants['AUTO_REFRESH'] = False
    if control=='eager_refresh':
        constants['MIN_REFRESH_INTERVAL'] = 59
    rows = []
    headers = [('canonical','Token owned-token'),('other-prefix','Bearer owned-token'),
               ('unknown-token','Token unknown-token'),('missing-second-field','Token')]
    for name,active,expiry,present in states():
        for owner in (1,2):
            for header_name,header in headers:
                store = Store(owner,active,expiry,present,control)
                try:
                    row = step(store,compiled,queries,constants,header,NOW,control,True)
                    rows.append(dict(token_state=name,owner=owner,header=header_name,**row))
                finally:
                    store.close()
    sequential = []
    for owner in (1,2):
        for name,expiry,times in [('renew-throttle',NOW+timedelta(days=30,seconds=-61),(0,60,61)),
                                  ('delete-then-missing',NOW-timedelta(seconds=1),(0,1)),
                                  ('no-expiry',None,(0,60*86400))]:
            store = Store(owner,True,expiry,True,control)
            try:
                serial = [step(store,compiled,queries,constants,'Token owned-token',NOW+timedelta(seconds=t),control) for t in times]
                sequential.append(dict(owner=owner,scenario=name,steps=serial))
            finally:
                store.close()
    return dict(source=identity,entry_observations=len(rows),state_counts=dict(Counter(r['state'] for r in rows)),
        credential_saves=sum(r['credential_effects']['saves'] for r in rows),
        expired_token_deletes=sum(r['credential_effects']['deletes'] for r in rows),
        connected_query_observations=sum(len(r['query_observations']) for r in rows),rows=rows,
        sequential_scenarios=sequential,sequential_steps=sum(len(r['steps']) for r in sequential),differences=0,
        original_application_modules_executed=False,new_independent_applications=0,
        exact_source_bodies_interpreted=True,configuration='source AUTO_REFRESH=True, MIN_REFRESH_INTERVAL=60 and thirty-day default; one fixed UTC clock per request',
        query_scope='source-lowered membership/collection/current-revision calls over owned SQLite relations; not original ORM managers or web/DI dispatch',
        malformed_header_scope='missing second split field is the selected source IndexError, not a fabricated authentication denial or HTTP result',
        credential_mutation_is_not_business_write=True,whole_application_or_concurrent_revocation_certified=False)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--check',action='store_true')
    p.add_argument('--control',choices=['omit_save','omit_delete','wrong_user','disable_refresh','eager_refresh'])
    a = p.parse_args()
    try:
        value = run(a.control)
    except LifecycleMismatch as error:
        if not a.control:
            raise
        print(json.dumps(dict(control=a.control,deliberate_fault_detected=True,reason=str(error))))
        return
    if a.control:
        raise ValueError('deliberate lifecycle fault not detected')
    value = json.loads(json.dumps(value,sort_keys=True))
    path = ROOT/'token-lifecycle.json.gz'
    if a.check:
        if json.loads(gzip.decompress(path.read_bytes()))!=value:
            raise ValueError('source lifecycle result differs from replay')
    else:
        path.write_bytes(gzip.compress(json.dumps(value,sort_keys=True).encode(),mtime=0))
    print(json.dumps({k:v for k,v in value.items() if k not in ('rows','sequential_scenarios')},indent=2))


if __name__ == '__main__':
    main()
