"""State-carrying writes and native header-to-permission admission.

Original application bodies stay AST data. Only frozen framework primitives
and owned in-memory stores execute. Historical reset-profile results remain
separate from these connected interfaces.
"""
import argparse,ast,gzip,hashlib,io,itertools,json,sqlite3,sys,urllib.request,zipfile
from copy import deepcopy
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parent
ART=ROOT.parent
sys.path[:0]=[str(ROOT),str(ART/'source_study/code'),str(ART/'src')]
from profiles import (Body,Record,Ref,Unsupported,NotFound,AuthFailure,WriteNative,
    TokenNative,function,Machine,globals_for,prepare_rows,token,check_code,event)
from language import normalize
from source_family import diagnose_source_family
from baseline_checks import ordinary_bfs

class BoundaryMismatch(ValueError):pass

def load(name):return json.loads(gzip.decompress((ROOT/name).read_bytes()))
def sha(raw):return hashlib.sha256(raw).hexdigest()

def prepare_runtime(directory,cache=None):
    directory=Path(directory).resolve();directory.mkdir(parents=True,exist_ok=True)
    runtime=load('native-header-runtime.json.gz')
    for p in runtime['packages']:
        cached=None if cache is None else Path(cache)/p['wheel_file']
        if cached is not None and cached.is_file():raw=cached.read_bytes()
        else:
            if not p['wheel_url'].startswith('https://files.pythonhosted.org/'):raise ValueError('primary wheel host required')
            with urllib.request.urlopen(p['wheel_url'],timeout=30) as response:
                if not response.url.startswith('https://files.pythonhosted.org/'):raise ValueError('unexpected wheel redirect')
                raw=response.read(30_000_001)
        if len(raw)>30_000_000 or sha(raw)!=p['wheel_sha256']:raise ValueError('frozen native wheel differs')
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            for info in z.infolist():
                rel=PurePosixPath(info.filename)
                if rel.is_absolute() or '..' in rel.parts or '\\' in info.filename or ':' in info.filename or (info.external_attr>>16)&0o170000==0o120000:
                    raise ValueError('unsafe native wheel member')
                if info.is_dir():continue
                target=directory.joinpath(*rel.parts).resolve();data=z.read(info)
                if not target.is_relative_to(directory):raise ValueError('native wheel escaped directory')
                if info.file_size>10_000_000 or sha(data)!=runtime['unpacked_files'][info.filename]:raise ValueError('unreviewed native wheel file')
                if target.exists() and target.read_bytes()!=data:raise ValueError('do not overwrite modified framework')
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    check_runtime(directory)

def check_runtime(directory):
    directory=Path(directory).resolve();runtime=load('native-header-runtime.json.gz')
    if sha((ROOT/'pretix-pyproject.toml').read_bytes())!=runtime['source_pyproject_sha256']:raise ValueError('original dependency declaration changed')
    for rel,h in runtime['unpacked_files'].items():
        p=directory/rel
        if not p.resolve().is_relative_to(directory) or p.is_symlink() or sha(p.read_bytes())!=h:raise ValueError('native framework identity differs: '+rel)
    return runtime

def write_policy():
    return normalize(dict(principals=['1w','1r','2w','2r','3w','3r','missing'],
        resources=['check-1','check-2','check-3','absent'],actions=['resume'],roles=['project-1','project-2','project-3'],
        members=[[f'{i}w',f'project-{i}'] for i in (1,2,3)],
        state=[[f'resumed-{i}',False] for i in (1,2,3)],
        aliases=[dict(name=f'owner-{i}',kind='role',candidates=[f'project-{j}' for j in (1,2,3)]) for i in (1,2,3)],
        rules=[dict(decision='allow',guard=[dict(field='resource',name=f'check-{i}',negated=False),
            dict(field='role',alias=f'owner-{i}',negated=False),dict(field='state',name=f'resumed-{i}',value=False)],
            updates=[dict(name=f'resumed-{i}',value=True)]) for i in (1,2,3)]))

def expected_write(mask,key,target):
    if type(mask) is not int or not 0<=mask<8 or key not in ('1w','1r','2w','2r','3w','3r','missing') or type(target) is not int or target not in (1,2,3,99):
        raise Unsupported('outside selected sequential write domain')
    writable=key!='missing' and key.endswith('w')
    status=401 if not writable else 404 if target==99 else 403 if int(key[0])!=target else 409 if mask&(1<<(target-1)) else 200
    return status,mask|(1<<(target-1)) if status==200 else mask

class WriteSession:
    def __init__(self,db,binding,profile,control=None):
        self.db=db;self.connection=db.fields['connection'];self.binding=binding;self.profile=profile;self.control=control
        self.node=function((ART/'source_study/source/healthchecks/hc/api/views.py').read_text(),None,'resume')
        if control=='repeat_write':
            selected=[n for n in self.node.body if isinstance(n,ast.If) and isinstance(n.test,ast.Compare)
                and isinstance(n.test.left,ast.Attribute) and n.test.left.attr=='status']
            if len(selected)!=1:raise Unsupported('selected status guard differs')
            self.node.body.remove(selected[0])
        self.reset()
    def reset(self):
        with self.connection.cursor() as c:
            c.execute('DELETE FROM owned_write_check');c.execute('DELETE FROM owned_write_flip')
            for i in (1,2,3):c.execute('INSERT INTO owned_write_check VALUES(%s,%s,%s,%s,%s,%s,%s)',[i,check_code(i),i,'paused','start','ping','alert'])
        self.mask=0
    def snapshot(self):
        with self.connection.cursor() as c:
            c.execute('SELECT id,code,project_id,status,last_start,last_ping,alert_after FROM owned_write_check ORDER BY id');rows=[list(r) for r in c.fetchall()]
            c.execute('SELECT check_id,status,processed FROM owned_write_flip ORDER BY check_id,status,processed');flips=[list(r) for r in c.fetchall()]
        mask=sum(1<<(r[0]-1) for r in rows if r[3]=='new')
        canonical=[[i,check_code(i),i,'new' if mask&(1<<(i-1)) else 'paused',
            None if mask&(1<<(i-1)) else 'start',None if mask&(1<<(i-1)) else 'ping',
            None if mask&(1<<(i-1)) else 'alert'] for i in (1,2,3)]
        expected_flips=[[i,'new',1] for i in (1,2,3) if mask&(1<<(i-1))]
        if rows!=canonical or flips!=expected_flips:raise BoundaryMismatch('write projection invariant: persisted fields or event multiplicity differs')
        return mask,dict(records=rows,events=flips)
    def step(self,request):
        key,resource,action=request
        if action!='resume' or resource not in ('check-1','check-2','check-3','absent'):raise Unsupported('unsupported write action/resource')
        target=99 if resource=='absent' else int(resource[-1])
        expected_write(self.mask,key,target)
        credential='' if key=='missing' else token(self.profile,int(key[0]),key[1])
        native=WriteNative(self.db,self.node,self.binding['programs'],'drop_save' if self.control=='lost_save' else None)
        machine=Machine(self.binding['programs'],globals_for('write')|{'f':Ref('resume')},native)
        before=self.mask
        req=Record('Request',dict(method='POST',body=b'',headers={'X-Api-Key':credential},path_info='/api/v3/checks/'))
        try:status=machine.call(Ref('authorize.wrapper'),[req,check_code(target)]).status_code
        except NotFound:status=404
        after,store=self.snapshot();expected_status,expected_mask=expected_write(before,key,target)
        if (status,after)!=(expected_status,expected_mask):raise BoundaryMismatch('state-carrying request/reference disagreement')
        if native.effects!=(['flip','save','serialize'] if status==200 else []):raise BoundaryMismatch('per-request effect order differs')
        self.mask=after
        return dict(request=request,status=status,before=before,after=after,effects=native.effects,store=store)

def stateful_writes(control=None):
    from credential_flow_native import initialize
    binding=load_from_artifact('source_study/data/credential-input.json.gz')['binding']
    db=initialize()
    with db.fields['connection'].cursor() as c:
        c.execute('CREATE TABLE owned_write_check(id INTEGER PRIMARY KEY,code TEXT,project_id INTEGER,status TEXT,last_start TEXT,last_ping TEXT,alert_after TEXT)')
        c.execute('CREATE TABLE owned_write_flip(check_id INTEGER,status TEXT,processed INTEGER)')
    p=write_policy();alphabet=[list(r) for r in itertools.product(p['principals'],p['resources'],p['actions'])];profiles=[]
    for profile in ('plain','stored_mac'):
        db.fields['Check'].objects.all().delete();db.fields['Project'].objects.all().delete();prepare_rows(db,binding,profile)
        session=WriteSession(db,binding,profile,control);paths={0:[]};rows=[];table=[None]*8;todo=[0]
        while todo:
            state=todo.pop(0);edges=[]
            for index,request in enumerate(alphabet):
                session.reset();prefix=[session.step(alphabet[i]) for i in paths[state]]
                if session.mask!=state:raise BoundaryMismatch('actual prefix does not reach recorded state')
                observed=session.step(request);successor=observed['after']
                rows.append(dict(state=state,index=index,prefix_indices=paths[state],prefix_observations=prefix,observed=observed))
                edges.append(['allow' if observed['status']==200 else 'deny',successor])
                if successor not in paths:paths[successor]=paths[state]+[index];todo.append(successor)
            table[state]=edges
        if len(paths)!=8 or any(r is None for r in table):raise BoundaryMismatch('incomplete state-carrying closure')
        m=dict(state_names=[r[0] for r in p['state']],alphabet=alphabet,observations=list(range(8)),initial=0,transitions=table)
        diagnosis=diagnose_source_family(p,m)
        correct={f'owner-{i}':f'project-{i}' for i in (1,2,3)}
        if diagnosis['matching_interpretations']!=[correct] or diagnosis['strata']!={'1':26,'infinity':1}:raise BoundaryMismatch('stateful binding diagnosis differs')
        fixed=deepcopy(p)
        for a in fixed['aliases']:a['candidates']=[correct[a['name']]]
        bfs=ordinary_bfs(normalize(fixed),m)
        if not bfs['equivalent']:raise BoundaryMismatch('fixed-reference ordinary BFS differs')
        witness_replays=[]
        for row in diagnosis['profiles']:
            if row['equivalent']:continue
            session.reset();trace=[session.step(alphabet[i]) for i in row['indices']]
            if any(['allow' if r['status']==200 else 'deny',r['after']]!=t['target'] for r,t in zip(trace,row['trace'])):
                raise BoundaryMismatch('diagnostic witness does not replay against the native store')
            witness_replays.append(dict(binding=row['binding'],indices=row['indices'],native_trace=trace))
        profiles.append(dict(credential_form=profile,reachable_states=8,request_symbols=len(alphabet),
            measured_edges=len(rows),paths={str(k):v for k,v in paths.items()},rows=rows,
            policy=p,machine=m,diagnosis=diagnosis,fixed_reference_BFS=bfs,native_witness_replays=witness_replays))
    return dict(case='Healthchecks',profiles=profiles,reachable_states_each=8,request_symbols=28,
        measured_edges=448,complete_reset_per_request=False,
        execution='reset only before replaying a reachable prefix,then carry actual store into the next request',
        observed_store_invariant='three fixed-owner records; one event and cleared fields exactly for each resumed object; other records unchanged',
        state_projection='three resumed bits only after validating the complete owned store invariant at every step',
        native_witness_replays=52,differences=0,
        scope='selected sequential resume operation over fixed three-object store; no concurrent writers, original ORM, background notifications or transaction guarantee')

def load_from_artifact(name):return json.loads(gzip.decompress((ART/name).read_bytes()))

def header_cases():
    return [('absent',None,'not_attempted'),('empty',b'','not_attempted'),('other_scheme',b'Bearer owned-normal-token','not_attempted'),
        ('missing_key',b'Token','malformed'),('extra_fields',b'Token a b','malformed'),('bad_encoding',b'Token \xff','malformed'),
        ('wrong_key',b'Token not-found','unknown_key'),('canonical',b'Token owned-normal-token','key'),
        ('lower_scheme',b'token owned-normal-token','key'),('upper_scheme',b'TOKEN owned-normal-token','key'),
        ('outer_spaces',b'  Token   owned-normal-token  ','key'),('tab_separator',b'Token\towned-normal-token','key'),
        ('text_header','Token owned-normal-token','key'),('non_ascii_text','Token caf\u00e9','malformed')]

def header_reference(kind,condition,c):
    if kind not in ('not_attempted','malformed','unknown_key','key') or condition not in ('active','inactive','deleted','missing'):
        raise Unsupported('outside selected token/header domain')
    if kind=='not_attempted':return 'not_attempted',None
    if kind!='key' or condition!='active':return 'rejected',None
    return 'authenticated',event.reference(c)

def header_chain(directory,control=None):
    runtime=check_runtime(directory);sys.path.insert(0,str(Path(directory).resolve()))
    from django.conf import settings
    settings.configure(SECRET_KEY='owned-native-header-study',INSTALLED_APPS=[],USE_I18N=False)
    import django;django.setup()
    from django.http import HttpRequest
    from rest_framework.authentication import TokenAuthentication
    from rest_framework.exceptions import AuthenticationFailed
    import rest_framework
    if django.get_version()!='5.2.17' or rest_framework.VERSION!='3.18.3':raise ValueError('native primitive version differs')
    raw=(ROOT/'pretix-token-source.txt').read_text()
    from source_bindings import require_import_bindings,require_static_class_members
    require_import_bindings(raw.encode(),{'TokenAuthentication':('rest_framework.authentication',0,'TokenAuthentication'),
        'TeamAPIToken':('pretix.base.models.organizer',0,'TeamAPIToken'),
        'AnonymousUser':('django.contrib.auth.models',0,'AnonymousUser')})
    cls=next(n for n in ast.parse(raw).body if isinstance(n,ast.ClassDef) and n.name=='TeamTokenAuthentication')
    require_static_class_members(cls,('authenticate_credentials',))
    if len(cls.bases)!=1 or not isinstance(cls.bases[0],ast.Name) or cls.bases[0].id!='TokenAuthentication':raise Unsupported('unadmitted authentication base')
    declarations=[n for n in cls.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='model' for t in n.targets)]
    if len(declarations)!=1 or not isinstance(declarations[0].value,ast.Name) or declarations[0].value.id!='TeamAPIToken':raise Unsupported('unadmitted token model binding')
    node=function(raw,'TeamTokenAuthentication','authenticate_credentials')
    if control=='skip_active':
        guards=[n for n in node.body if isinstance(n,ast.If)]
        if len(guards)!=1:raise Unsupported('selected token activity guard differs')
        node.body.remove(guards[0])
    compiled=event.programs(event.source());rows=[]
    class Adapter(TokenAuthentication):
        def authenticate_credentials(self,key):
            try:return Body(node,self.native,{'exceptions':Record('Exceptions',{'AuthenticationFailed':Ref('AuthenticationFailed')}),
                'AnonymousUser':Ref('AnonymousUser')}).run([Record('Authenticator',{}),key])
            except AuthFailure as error:raise AuthenticationFailed(str(error)) from None
    for name,header,kind in header_cases():
        for condition,c in itertools.product(('active','inactive','deleted','missing'),event.contexts()):
            with sqlite3.connect(':memory:') as db:
                db.execute('CREATE TABLE owned_token(id INTEGER,token TEXT,active INTEGER)')
                team=Record('Team',dict(organizer=1,all_events=c['all_events'],limited_events=tuple(c['limited_events']),permissions=tuple(c['permissions'])))
                records={1:Record('Token',dict(team=team))}
                if condition not in ('deleted','missing'):db.execute('INSERT INTO owned_token VALUES(1,?,?)',('owned-normal-token',int(condition=='active')))
                native=TokenNative(db,records);adapter=Adapter();adapter.native=native
                req=HttpRequest()
                if header is not None:req.META['HTTP_AUTHORIZATION']=header
                detail=None;permission=None;identity=False
                try:
                    result=(adapter.authenticate_credentials('owned-normal-token') if control=='header_bypass' else adapter.authenticate(req))
                    stage='not_attempted' if result is None else 'authenticated'
                except AuthenticationFailed as error:stage='rejected';detail=str(error)
                if stage=='authenticated':
                    user,returned=result
                    if returned is not records[1] or returned.fields['team'] is not team or user.fields['is_authenticated'] is not False:
                        raise BoundaryMismatch('authenticated record identity changed')
                    identity=True;facts=returned.fields['team'].fields
                    connected=dict(c,all_events=facts['all_events'],limited_events=facts['limited_events'],permissions=list(facts['permissions']))
                    permission,_=event.observe(connected,compiled)
                expected_stage,expected_permission=header_reference(kind,condition,c)
                expected_lookups=1 if kind in ('key','unknown_key') else 0
                if (stage,permission,native.lookups)!=(expected_stage,expected_permission,expected_lookups):
                    raise BoundaryMismatch('header/token/permission boundary differs from declared contract')
                rows.append(dict(header=name,header_kind=kind,condition=condition,event_context=c['id'],stage=stage,
                    credential_lookups=native.lookups,authentication_error=detail,permission=permission,
                    exact_token_and_team_identity=identity))
    from collections import Counter
    return dict(case='Pretix',header_profiles=len(header_cases()),contexts=len(rows),
        stage_counts=dict(Counter(r['stage'] for r in rows)),rows=rows,differences=0,
        framework=dict(Django=django.get_version(),DRF=rest_framework.VERSION,
            source_declared_minimums_satisfied=True,authentication_module_sha256=sha(Path(sys.modules['rest_framework.authentication'].__file__).read_bytes()),
            native_methods=['get_authorization_header','TokenAuthentication.authenticate']),
        original_application_modules_executed=False,
        mapping='exact source-authenticator token/team followed by explicit representation map into existing event profile',
        scope='selected Token scheme and source token-authentication method; resolved view/grants supplied; no fallback session, OAuth, HTTP server or deployment claim')

def main():
    p=argparse.ArgumentParser();p.add_argument('component',choices=['prepare','health','header']);p.add_argument('--framework',type=Path)
    p.add_argument('--wheel-cache',type=Path);p.add_argument('--check',action='store_true')
    p.add_argument('--control',choices=['lost_save','repeat_write','header_bypass','skip_active']);a=p.parse_args()
    if a.component=='prepare':
        if a.framework is None:raise ValueError('owned native framework directory required')
        prepare_runtime(a.framework,a.wheel_cache);print('frozen native header primitives prepared');return
    if a.component=='header' and a.framework is None:raise ValueError('frozen native header runtime required')
    if a.control and ((a.component=='health')!=(a.control in ('lost_save','repeat_write'))):raise ValueError('control/component mismatch')
    try:report=stateful_writes(a.control) if a.component=='health' else header_chain(a.framework,a.control)
    except BoundaryMismatch as error:
        if not a.control:raise
        print(json.dumps(dict(control=a.control,deliberate_fault_detected=True,reason=str(error))));return
    if a.control:raise ValueError('deliberate boundary fault not detected')
    # Core replay pairs use tuples in memory; the published JSON interface
    # represents them as arrays. Compare that exact wire representation.
    report=json.loads(json.dumps(report,sort_keys=True))
    path=ROOT/f'chained-{a.component}.json.gz'
    if a.check:
        if load(path.name)!=report:raise ValueError('connected source-profile result differs')
    else:path.write_bytes(gzip.compress(json.dumps(report,sort_keys=True).encode(),mtime=0))
    print(json.dumps({k:v for k,v in report.items() if k not in ('profiles','rows')},indent=2))
if __name__=='__main__':main()
