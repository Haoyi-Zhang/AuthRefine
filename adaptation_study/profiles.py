"""Two source-bound adaptation extensions over owned normal database records.

Original application AST is read as data, never imported, eval'ed or compiled
as Python. The small dispatcher admits only explicit capabilities. It extends
the observed boundary, not the number of independent application samples.
"""
import ast,gzip,itertools,json,sqlite3,sys,uuid
from dataclasses import dataclass
from pathlib import Path
ROOT=Path(__file__).resolve().parent
ART=ROOT.parent
sys.path.insert(0,str(ART/'source_study/code'))
from credential_flow_ir import Machine,Record,Ref,Unsupported,NotFound,QueryMiss
from credential_flow_native import Native,initialize,globals_for,prepare_rows
from credential_flow_contexts import token,check_code
import pretix_event_profile as event
from finite_observation_diagnosis import diagnose_observations

class AuthFailure(Exception):pass
@dataclass
class Response:
    status_code:int
    payload:object=None

class Body:
    """Interpret the selected finite straight-line/conditional source bodies."""
    def __init__(self,node,native,globals):
        self.node=node;self.native=native;self.globals=globals;self.steps=0
    def value(self,n,env):
        self.steps+=1
        if self.steps>1000:raise Unsupported('selected body step bound')
        if isinstance(n,ast.Constant) and type(n.value) in (str,int,bool,type(None)):return n.value
        if isinstance(n,ast.Name):
            if n.id in env:return env[n.id]
            if n.id in self.globals:return self.globals[n.id]
            raise Unsupported('unbound body name: '+n.id)
        if isinstance(n,ast.Attribute):
            obj=self.value(n.value,env)
            if not isinstance(obj,Record):raise Unsupported('untyped body receiver')
            if n.attr in obj.fields:return obj.fields[n.attr]
            return self.native.attribute(obj,n.attr)
        if isinstance(n,(ast.Tuple,ast.List)):return tuple(self.value(v,env) for v in n.elts)
        if isinstance(n,ast.Dict):
            if any(k is None for k in n.keys):raise Unsupported('body dictionary expansion')
            return {self.value(k,env):self.value(v,env) for k,v in zip(n.keys,n.values)}
        if isinstance(n,ast.UnaryOp) and isinstance(n.op,ast.Not):return not self.value(n.operand,env)
        if isinstance(n,ast.Compare) and len(n.ops)==1:
            a,b=self.value(n.left,env),self.value(n.comparators[0],env)
            if isinstance(n.ops[0],ast.Eq):return a==b
            if isinstance(n.ops[0],ast.NotEq):return a!=b
            raise Unsupported('body comparison not admitted')
        if isinstance(n,ast.Call):
            if any(k.arg is None for k in n.keywords) or any(isinstance(x,ast.Starred) for x in n.args):raise Unsupported('body argument expansion')
            f=self.value(n.func,env)
            if not isinstance(f,Ref):raise Unsupported('body capability required')
            return self.native.call(f,[self.value(v,env) for v in n.args],{k.arg:self.value(k.value,env) for k in n.keywords})
        raise Unsupported('body expression not admitted: '+type(n).__name__)
    def block(self,nodes,env):
        for n in nodes:
            if isinstance(n,ast.Assign) and len(n.targets)==1:
                value=self.value(n.value,env);target=n.targets[0]
                if isinstance(target,ast.Name):env[target.id]=value
                elif isinstance(target,ast.Attribute):
                    obj=self.value(target.value,env)
                    if not isinstance(obj,Record) or obj.kind!='Check' or target.attr not in ('status','last_start','last_ping','alert_after'):
                        raise Unsupported('body write outside admitted check fields')
                    obj.fields[target.attr]=value
                else:raise Unsupported('body assignment form')
            elif isinstance(n,ast.Return):return True,self.value(n.value,env)
            elif isinstance(n,ast.If):
                done,value=self.block(n.body if self.value(n.test,env) else n.orelse,env)
                if done:return done,value
            elif isinstance(n,ast.Expr):self.value(n.value,env)
            elif isinstance(n,ast.Raise) and n.cause is None:
                error=self.value(n.exc,env)
                if not isinstance(error,AuthFailure):raise Unsupported('unadmitted raised value')
                raise error
            elif isinstance(n,ast.Try) and not n.orelse and not n.finalbody:
                try:done,value=self.block(n.body,env)
                except QueryMiss:
                    handler=next((h for h in n.handlers if not h.name and self.value(h.type,env) is QueryMiss),None)
                    if handler is None:raise
                    done,value=self.block(handler.body,env)
                if done:return done,value
            else:raise Unsupported('body statement not admitted: '+type(n).__name__)
        return False,None
    def run(self,args):
        p=self.node.args
        if p.defaults or p.kwonlyargs or p.vararg or p.kwarg or p.posonlyargs or len(args)!=len(p.args):raise Unsupported('body signature')
        return self.block(self.node.body,{p.arg:v for p,v in zip(p.args,args)})[1]

def function(text,owner,name):
    tree=ast.parse(text)
    nodes=tree.body if owner is None else next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==owner).body
    return next(n for n in nodes if isinstance(n,ast.FunctionDef) and n.name==name)

class WriteNative(Native):
    def __init__(self,db,node,programs,control=None):
        super().__init__(db);self.node=node;self.programs=programs;self.effects=[];self.control=control
    def attribute(self,obj,name):
        if obj.kind=='Check' and name in ('create_flip','save','to_dict'):return Ref('Check.'+name,obj)
        return super().attribute(obj,name)
    def call(self,ref,args,kwargs):
        name=ref.name
        if name=='resume':return Body(self.node,self,globals_for('write')|{'HttpResponse':Ref('HttpResponse')}).run(args)
        if name=='get_object_or_404':
            if args!=[Ref('CheckModel')] or set(kwargs)!={'code'}:raise Unsupported('write lookup signature')
            with self.db['connection'].cursor() as c:
                c.execute('SELECT id,project_id,status,last_start,last_ping,alert_after FROM owned_write_check WHERE code=%s',[kwargs['code']]);row=c.fetchone()
            if row is None:raise NotFound('owned absent check')
            return Record('Check',dict(zip(('id','project_id','status','last_start','last_ping','alert_after'),row)))
        if name=='Check.create_flip':
            if args!=['new'] or kwargs!={'mark_as_processed':True}:raise Unsupported('write flip signature')
            with self.db['connection'].cursor() as c:c.execute('INSERT INTO owned_write_flip(check_id,status,processed) VALUES(%s,%s,%s)',[ref.receiver.fields['id'],args[0],1])
            self.effects.append('flip');return None
        if name=='Check.save':
            fields=kwargs.get('update_fields')
            if args or set(kwargs)!={'update_fields'} or fields!=('status','last_start','last_ping','alert_after'):raise Unsupported('write save signature')
            if self.control=='drop_save':return None
            values=[ref.receiver.fields[f] for f in fields]+[ref.receiver.fields['id']]
            with self.db['connection'].cursor() as c:c.execute('UPDATE owned_write_check SET status=%s,last_start=%s,last_ping=%s,alert_after=%s WHERE id=%s',values)
            self.effects.append('save');return None
        if name=='Check.to_dict':
            if args or set(kwargs)!={'v'}:raise Unsupported('write serialization signature')
            self.effects.append('serialize');return {'check':ref.receiver.fields['id'],'status':ref.receiver.fields['status']}
        if name=='HttpResponseForbidden':return Response(403)
        if name=='HttpResponse':
            if len(args)!=1 or set(kwargs)!={'status'}:raise Unsupported('write response signature')
            return Response(kwargs['status'],args[0])
        if name=='JsonResponse':return Response(kwargs.get('status',200),args[0])
        return super().call(ref,args,kwargs)

def healthchecks(control=None):
    binding=json.loads(gzip.decompress((ART/'source_study/data/credential-input.json.gz').read_bytes()))['binding']
    source=(ART/'source_study/source/healthchecks/hc/api/views.py').read_text()
    node=function(source,None,'resume');db=initialize();connection=db.fields['connection']
    with connection.cursor() as c:
        c.execute('CREATE TABLE owned_write_check(id INTEGER PRIMARY KEY,code TEXT,project_id INTEGER,status TEXT,last_start TEXT,last_ping TEXT,alert_after TEXT)')
        c.execute('CREATE TABLE owned_write_flip(check_id INTEGER,status TEXT,processed INTEGER)')
    rows=[]
    for profile in ('plain','stored_mac'):
        db.fields['Check'].objects.all().delete();db.fields['Project'].objects.all().delete();prepare_rows(db,binding,profile)
        for keychoice,target,status in itertools.product(('1w','1r','2w','2r','3w','3r','missing'),(1,2,3,99),('paused','up')):
            with connection.cursor() as c:
                c.execute('DELETE FROM owned_write_check');c.execute('DELETE FROM owned_write_flip')
                for i in (1,2,3):c.execute('INSERT INTO owned_write_check VALUES(%s,%s,%s,%s,%s,%s,%s)',[i,check_code(i),i,status,'start','ping','alert'])
            key='' if keychoice=='missing' else token(profile,int(keychoice[0]),keychoice[1])
            request=Record('Request',dict(method='POST',body=b'',headers={'X-Api-Key':key},path_info='/api/v3/checks/'))
            native=WriteNative(db,node,binding['programs'],control);globs=globals_for('write')|{'f':Ref('resume')}
            machine=Machine(binding['programs'],globs,native)
            try:reply=machine.call(Ref('authorize.wrapper'),[request,check_code(target)]);code=reply.status_code
            except NotFound:code=404
            with connection.cursor() as c:
                c.execute('SELECT id,status,last_start,last_ping,alert_after FROM owned_write_check ORDER BY id');after=[list(r) for r in c.fetchall()]
                c.execute('SELECT check_id,status,processed FROM owned_write_flip');flips=[list(r) for r in c.fetchall()]
            writable=keychoice!='missing' and keychoice.endswith('w')
            expected_code=401 if not writable else 404 if target==99 else 403 if int(keychoice[0])!=target else 409 if status!='paused' else 200
            wanted=[[i,('new' if expected_code==200 and i==target else status),
                     None if expected_code==200 and i==target else 'start',None if expected_code==200 and i==target else 'ping',
                     None if expected_code==200 and i==target else 'alert'] for i in (1,2,3)]
            wanted_flips=[[target,'new',1]] if expected_code==200 else []
            agrees=code==expected_code and after==wanted and flips==wanted_flips and (native.effects==['flip','save','serialize'] if code==200 else not native.effects)
            if not agrees:raise ValueError('write profile differs from independent contract')
            rows.append(dict(profile=profile,keychoice=keychoice,target=target,initial_status=status,status=code,
                database_after=after,flips=flips,effects=native.effects,agrees=agrees,
                expected=dict(status=expected_code,database_after=wanted,flips=wanted_flips)))
    properties=[dict(id=f'write-{i}-{field}',expected=True,observed=(row[field]==row['expected'][field]))
        for i,row in enumerate(rows) for field in ('status','database_after','flips')]
    return dict(case='Healthchecks',operation='selected resume source body after actual source authorize wrapper',
        source_path='hc/api/views.py',source_function='resume',source_line=node.lineno,contexts=len(rows),
        successful_updates=sum(r['status']==200 for r in rows),denied_or_conflicting_without_writes=sum(r['status']!=200 for r in rows),
        differences=0,actual_owned_SQLite_updates_observed=True,readback_all_three_objects=True,rows=rows,
        diagnostic_consumer=diagnose_observations(properties),
        boundary='complete selected status/flip/save/response flow; native call contracts, not original ORM/serializer/transaction implementation',
        remaining=['outer POST/CSRF middleware','concurrent transactions','other write endpoints','notification/background consumers'])

class TokenNative:
    def __init__(self,db,records):self.db=db;self.records=records;self.lookups=0
    def attribute(self,obj,name):
        allowed={('Authenticator','get_model'):'get_model',('TokenModel','objects'):'objects',('TokenModel','DoesNotExist'):QueryMiss,
            ('TokenManager','select_related'):'select_related',('TokenQuery','get'):'get'}
        value=allowed.get((obj.kind,name))
        if value is QueryMiss:return value
        if value=='objects':return Record('TokenManager',{})
        if value:return Ref(value,obj)
        raise Unsupported('token attribute outside selected profile')
    def call(self,f,args,kwargs):
        if f.name=='get_model' and not args and not kwargs:return Record('TokenModel',{})
        if f.name=='select_related' and args==['team','team__organizer'] and not kwargs:return Record('TokenQuery',{})
        if f.name=='get' and not args and set(kwargs)=={'token'}:
            self.lookups+=1;row=self.db.execute('SELECT id,active FROM owned_token WHERE token=?',(kwargs['token'],)).fetchone()
            if row is None:raise QueryMiss('owned missing token')
            record=self.records[row[0]];record.fields['active']=bool(row[1])
            return record
        if f.name=='AuthenticationFailed' and len(args)==1 and not kwargs:return AuthFailure(args[0])
        if f.name=='AnonymousUser' and not args and not kwargs:return Record('AnonymousUser',{'is_authenticated':False})
        raise Unsupported('token call outside selected profile')

def pretix(control=None):
    node=function((ROOT/'pretix-token-source.txt').read_text(),'TeamTokenAuthentication','authenticate_credentials')
    if control=='skip_active':node.body=[n for n in node.body if not isinstance(n,ast.If)]
    raw=event.source();compiled=event.programs(raw);rows=[]
    for condition,c in itertools.product(('active','inactive','deleted','missing'),event.contexts()):
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE owned_token(id INTEGER,token TEXT,active INTEGER)')
            team=Record('Team',dict(organizer=1,all_events=c['all_events'],
                limited_events=tuple(c['limited_events']),permissions=tuple(c['permissions'])))
            records={1:Record('Token',dict(active=condition=='active',team=team))}
            if condition not in ('deleted','missing'):db.execute('INSERT INTO owned_token VALUES(1,?,?)',('owned-normal-token',int(condition=='active')))
            native=TokenNative(db,records)
            globals={'exceptions':Record('Exceptions',{'AuthenticationFailed':Ref('AuthenticationFailed')}),'AnonymousUser':Ref('AnonymousUser')}
            error=None
            try:user,token_record=Body(node,native,globals).run([Record('Authenticator',{}),'owned-normal-token'])
            except AuthFailure as e:error=str(e)
            wanted_error=None if condition=='active' else 'Token inactive or deleted.' if condition=='inactive' else 'Invalid token.'
            if error!=wanted_error:raise ValueError('token source/reference mismatch')
            permission=None
            if error is None:
                if token_record is not records[1] or user.fields['is_authenticated'] is not False:raise ValueError('token identity not preserved')
                returned_team=token_record.fields['team']
                if returned_team is not team or returned_team.fields['organizer']!=1:raise ValueError('authenticated team changed')
                connected=dict(c,all_events=returned_team.fields['all_events'],
                    limited_events=returned_team.fields['limited_events'],permissions=list(returned_team.fields['permissions']))
                permission,_=event.observe(connected,compiled)
                if permission!=event.reference(c):raise ValueError('chained event comparison differs')
            rows.append(dict(token_condition=condition,event_context=c['id'],authentication_error=error,
                permission_observation=permission,permission_reached=error is None,token_lookups=native.lookups,
                expected=dict(authentication_error=wanted_error,permission_observation=event.reference(c) if condition=='active' else None)))
    properties=[dict(id=f'entry-{i}-{field}',expected=True,observed=row[field]==row['expected'][field])
        for i,row in enumerate(rows) for field in ('authentication_error','permission_observation')]
    return dict(case='Pretix',source_path='src/pretix/api/auth/token.py',source_function='TeamTokenAuthentication.authenticate_credentials',
        source_line=node.lineno,contexts=len(rows),authenticated_then_permission=sum(r['permission_reached'] for r in rows),
        denied_before_permission=sum(not r['permission_reached'] for r in rows),differences=0,rows=rows,
        diagnostic_consumer=diagnose_observations(properties),
        complete_selected_authentication_body_interpreted=True,active_token_no_longer_assumed=True,
        identity_connection='returned token/team facts mapped into the existing permission-profile representation; not physical object identity across two interpreters; complete grant-set and resolved-view inputs remain supplied',
        remaining=['HTTP header extraction by DRF TokenAuthentication','session/device/OAuth flows','plugin grant expansion','concurrent token revocation'])

def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');parser.add_argument('--control',choices=['drop_save','skip_active']);args=parser.parse_args()
    if args.control:
        try:
            (healthchecks if args.control=='drop_save' else pretix)(args.control)
        except ValueError:
            print(json.dumps(dict(control=args.control,deliberate_fault_detected=True)));return
        raise ValueError('deliberate fault was not detected')
    report=dict(Healthchecks=healthchecks(),Pretix=pretix(),original_application_modules_executed=False,
        trusted_framework_and_owned_SQLite_only=True,new_independent_applications=0)
    path=ROOT/'profiles.json.gz'
    if args.check:
        if json.loads(gzip.decompress(path.read_bytes()))!=report:raise ValueError('source profile output differs from saved current result')
    else:path.write_bytes(gzip.compress(json.dumps(report,sort_keys=True).encode(),mtime=0))
    print(json.dumps({k:{n:v for n,v in r.items() if n not in ('rows','diagnostic_consumer')} if isinstance(r,dict) else r for k,r in report.items()},indent=2))
if __name__=='__main__':main()
