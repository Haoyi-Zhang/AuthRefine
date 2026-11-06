"""Declared normal-data/provider boundaries for remaining fixed-source cases.

These providers are NOT independent intent gold or whole application runtimes.
Casbin uses actual source model text and the retained installed engine. External
identity/ORM services remain named finite data providers,never live connections.
"""
import base64,builtins,contextlib,hashlib,types
from datetime import datetime,timezone
from enum import Enum
from types import SimpleNamespace as NS
from delegated_runtime import finish,Unknown

class HTTPException(Exception):
    def __init__(self,status_code=403,detail='',headers=None,**kwargs):
        self.status_code=status_code;self.detail=detail;self.headers=headers;super().__init__(detail)
class AuthError(HTTPException):
    def __init__(self,detail=''):super().__init__(401,detail)
class AuthorizationError(HTTPException):
    def __init__(self,detail=''):super().__init__(403,detail)
class NoResultFound(Exception):pass
class TokenError(Exception):pass
class DoesNotExist(Exception):pass
class ForbiddenScope(HTTPException):
    # Source DtkError takes message/details,not HTTPException's status-first
    # signature. HTTP_STATUS maps FORBIDDEN_SCOPE to403 at the API boundary.
    def __init__(self,message='',details=None):
        self.details=details;super().__init__(403,message)

class Record(NS):
    def __getattr__(self,name):
        props=vars(self).get('_properties',{})
        if name in props:return finish(props[name](self))
        raise AttributeError(name)

class RoleTable(dict):
    def __getattr__(self,k):return self[k]

class World:
    def __init__(self,case,sample):
        self.case=case;self.sample=sample;self.c=sample['fixture'];self.globals={};self.native_environments=[];self.refs={};self.objects=[];self.trace=[];self.tracked={}
        self.allowed_imports={};self.source_methods=[];self.properties=[];self.entry_args={};self.factory_args=None;self.pipeline=[]
        self.builtins={n:getattr(builtins,n) for n in ('any','all','bool','dict','frozenset','getattr','hasattr','isinstance','len','list','set','sorted','str','tuple','int','Exception','ValueError','AssertionError','PermissionError')}
        self.globals.update(HTTPException=HTTPException,AuthError=AuthError,AuthorizationError=AuthorizationError,NoResultFound=NoResultFound,
            ForbiddenScope=ForbiddenScope,status=NS(HTTP_401_UNAUTHORIZED=401,HTTP_403_FORBIDDEN=403),
            Depends=lambda fn=None,**kw:None,Security=lambda fn=None,**kw:None,
            logger=NS(**{name:(lambda *a,**kw:None) for name in ('debug','info','warning','error','exception')}))
        getattr(self,'setup_'+case['project'])()

    def record(self,label,**kw):
        r=Record(**kw);self.objects.append(r);self.refs[id(r)]=label;return r
    def event(self,name,fn,async_=False):
        def call(*args,**kwargs):
            self.trace.append(dict(provider=name,args=self.pack(list(args)),kwargs=self.pack(kwargs)))
            return fn(*args,**kwargs)
        if not async_:return call
        async def async_call(*args,**kwargs):return call(*args,**kwargs)
        return async_call
    def method(self,obj,name,binding):self.source_methods.append((obj,name,binding))
    def property(self,obj,name,binding):self.properties.append((obj,name,binding))
    def bind_source_methods(self,mode):
        for obj,name,binding in self.source_methods:
            setattr(obj,name,lambda *a,_o=obj,_b=binding,**kw:self.globals[_b](_o,*a,**kw))
        for obj,name,binding in self.properties:
            vars(obj).setdefault('_properties',{})[name]=lambda x,_b=binding:self.globals[_b](x)
        if self.case['project']=='R09':
            auth=self.globals['Authentication'];auth.configuration_is_locked=self.globals['configuration_is_locked'];auth.config_lock_allows=self.globals['config_lock_allows']
        if self.case['project']=='R17':
            self.globals['SimpleAuthManager']._is_admin=self.globals['_is_admin']
            self.self._is_authorized=self.globals['_is_authorized']
        if self.case['project']=='R40':
            for r,meta in zip(self.globals['CHECK_RULES'],self.case['constants']['rules']):r.predicate=self.globals[meta['predicate']]

    def native_builtins(self):
        def imp(name,globals=None,locals=None,fromlist=(),level=0):
            key=f'{level}:{name}' if level else name
            if key not in self.allowed_imports:raise Unknown('undeclared import:'+key)
            return self.allowed_imports[key]
        return {**self.builtins,'__import__':imp}
    def pack(self,v):
        if id(v) in self.refs:return {'ref':self.refs[id(v)]}
        if isinstance(v,Enum):return {'enum':v.name,'value':v.value}
        if v is None or type(v) in (bool,str,int,float):return v
        if isinstance(v,bytes):return {'bytes_hex':v.hex()}
        if isinstance(v,datetime):return {'datetime':v.isoformat()}
        if isinstance(v,tuple):return {'tuple':[self.pack(x) for x in v]}
        if isinstance(v,(set,frozenset)):return {'set':sorted([self.pack(x) for x in v],key=repr)}
        if isinstance(v,list):return [self.pack(x) for x in v]
        if isinstance(v,dict):return {str(k):self.pack(x) for k,x in sorted(v.items(),key=lambda kv:str(kv[0]))}
        if callable(v):return {'callable_boundary':True}
        if isinstance(v,NS):return {k:self.pack(x) for k,x in vars(v).items() if not k.startswith('_') and not callable(x)}
        raise Unknown('unserializable provider value:'+type(v).__name__)
    def snapshot(self):
        return {name:{k:self.pack(v) for k,v in vars(obj).items() if k!='_properties' and not callable(v)} for name,obj in self.tracked.items()}
    def engine(self):
        # Imported only in a non-root,no-network child with readonly bindings.
        import casbin
        model=casbin.Model();model.load_model_from_text(self.case['model']['text'])
        engine=casbin.Enforcer(model)
        for row in self.c.get('policies',self.case.get('policies',[])):
            kind,*fields=row
            if kind=='p':engine.add_policy(*fields)
            elif kind=='g':engine.add_grouping_policy(*fields)
            elif kind=='g2':engine.add_named_grouping_policy('g2',*fields)
            else:raise Unknown('policy row kind')
        return NS(enforce=self.event('casbin.enforce',engine.enforce))

    def invoke(self):
        if self.case.get('dependency_graph'):
            def resolve(name,seen):
                if name in seen:raise Unknown('dependency cycle')
                if name not in self.entry_args:return finish(self.globals[name]())
                args=dict(self.entry_args[name])
                for param,provider in self.case['dependency_graph'].get(name,{}).items():args[param]=resolve(provider,seen|{name})
                return finish(self.globals[name](**args))
            return resolve(self.sample.get('entry',self.case['entry']),set())
        for step in self.case.get('dependency_pipeline',[]):
            target=self.globals[step];arg=self.entry_args[step]
            finish(target(**arg))
        target=self.globals[self.sample.get('entry',self.case['entry'])]
        if self.factory_args is not None:target=finish(target(*self.factory_args))
        return finish(target(**self.entry_args[self.sample.get('entry',self.case['entry'])]))

    def setup_R02(self):
        self.globals.update({k:set(v) for k,v in self.case['constants'].items()})
        ctx=self.record('context',roles=tuple(self.c['roles']))
        self.entry_args={'authorize':dict(context=ctx,action=self.c['action'])}
    def setup_R03(self):
        c=self.c;org=self.record('organizer',pk=1);ev=self.record('event',pk=10);other=self.record('other_event',pk=20)
        self.self=self.record('device',all_events=c['all_events'],organizer=org,
            limit_events=NS(all=self.event('selected_events',lambda:[ev] if c['selected'] else [])),
            _event_permission_set=self.event('event_permission_cache',lambda:set(c['permissions'])))
        self.entry_args={'device_has_event_permission':dict(self=self.self,organizer=org if c['same_organizer'] else self.record('other_organizer',pk=2),event=ev,
            perm_name=self.c['required'],request=None,session_key=None)}
    def setup_R07(self):
        roles=[self.record('role-'+str(i),name=r['name'],permissions=[self.record('permission-'+str(i)+'-'+str(j),name=p) for j,p in enumerate(r['permissions'])]) for i,r in enumerate(self.c['roles'])]
        user=self.record('user',roles=roles);self.globals['get_current_user']=lambda:user
        self.factory_args=[self.c['required']];self.entry_args={'require_permissions':dict(current_user=user)}
    def setup_R09(self):
        c=self.c;request=self.record('request',globally_authenticated=c['global_auth'])
        self.globals.update(settings=NS(APPRISE_CONFIG_LOCK=c['global_lock'],APPRISE_AUTH_REQUIRED=c['auth_required']),
            Authentication=NS(config_state=self.event('config_state',lambda key,request:NS(config_locked=c['key_lock']))))
        self.allowed_imports['1:utils']=NS(stateful_store_enabled=self.event('stateful_store_enabled',lambda:c['stateful']))
        self.entry_args={'config_lock_allows':dict(request=request,key='fixture-key')}
    def setup_R11(self):
        c=self.c;user=self.record('user',username='alice');enforcer=self.engine()
        storage=NS(smembers=self.event('storage.smembers',lambda key:list(c['roles']),True))
        rbac=NS(get_all_inherited_roles=self.event('rbac.inherited_roles',lambda role:c['inherited'].get(role,[role]),True))
        self.globals.update(get_rbac_manager=lambda:rbac,run_in_thread=self.event('run_in_thread',lambda fn,*a:fn(*a),True),create_authorization_error=lambda msg:AuthorizationError(msg))
        self.entry_args={'check_permission':dict(required_permission=c['required'],user=user,storage=storage,enforcer=enforcer)}
    def setup_R12(self):
        c=self.c;user=self.record('user',is_active=c['active']);session=self.record('session')
        def decode(token):
            if c['token_error']:raise TokenError('fixture invalid token')
            return c['payload']
        self.globals.update(settings=NS(auth_mode=c['mode']),jwt=NS(PyJWTError=TokenError),
            decode_token=self.event('verified_token_claims',decode),
            authenticate_connector=self.event('connector_identity',lambda session,token:user if c['connector'] else None,True),
            get_user=self.event('user_lookup',lambda session,uid:user if c['known_user'] else None,True))
        self.entry_args={'authenticate_principal':dict(session=session,token='fixture-token')}
    def setup_R13(self):
        c=self.c;self.user=self.record('user',id=1,is_superuser=c['superuser']);self.tracked['user']=self.user
        token=self.record('token_data',username='alice',email='fixture@example.invalid',scopes=c['token_scopes'],roles=c['roles'])
        def get_user(*args):
            if c['create_user']:raise NoResultFound()
            return self.user
        self.globals.update(extract_token_data=self.event('declared_decoded_token_data',lambda token_str:token if c['valid_token'] else None),
            usr_dbapi=NS(get_user=self.event('user_lookup',get_user,True),create_user=self.event('user_create',lambda *a,**kw:self.user,True),get_user_scopes_from_roles=self.event('role_scope_lookup',lambda *a,**kw:c['role_scopes'],True)),
            scopes=NS(SCOPES={x:x for x in self.case['constants']['all_scopes']}),exc=NS(HTTP403Forbidden=lambda:HTTPException(403,'required scope missing')))
        self.entry_args={'authenticate_jwt':dict(token='fixture-token',db_session=self.record('session'),security_scopes=self.record('security_scopes',scopes=c['required']))}
    def setup_R14(self):
        config=self.record('auth_config',scopes=self.c['scopes'])
        self.globals.update(api_key_header=lambda:None,get_current_auth=self.event('validated_auth_context',lambda request,key:config,True))
        self.factory_args=[self.c['required']];self.entry_args={'require_scope':dict(request=self.record('request'),api_key='fixture-key')}
    def setup_R15(self):
        self.globals['enforcer']=self.engine();request=self.record('request',url=self.record('url',path=self.c['path']),method=self.c['method'])
        self.entry_args={'authorization_middleware':dict(request=request,user_info={'role':self.c['role'],'username':'alice'})}
    def setup_R16(self):
        obj=self.record('policy_engine',_enforcer=self.engine())
        self.entry_args={'authorize':dict(self=obj,subject=self.c['subject'],skill_id=self.c['object'],action=self.c['action'])}
    def setup_R17(self):
        table=RoleTable({k:self.record('role-'+k,name=k,order=v) for k,v in self.case['constants']['roles'].items()})
        user=self.record('user',role=self.c['role'],teams=self.c['teams'])
        self.self=self.record('manager');self.globals.update(SimpleAuthManagerRole=table,SimpleAuthManager=NS())
        details=None if self.c['team'] is None else self.record('details',team_name=self.c['team'])
        entry=self.sample['entry'];self.entry_args={entry:dict(self=self.self,method=self.c['method'],user=user,details=details)}
    def setup_R19(self):
        c=self.c
        user=None if c['absent'] else self.record('user',is_active=c['active'],is_authenticated=c['authenticated'],is_superuser=c['superuser'],
            has_perm=self.event('user.has_perm',lambda permission:permission in c['permissions']))
        self.entry_args={'has_global_statistics_permission':dict(user=user)}
    def setup_R20(self):
        c=self.c;salt=bytes(range(32)) # Fixed normal fixture salt,non-secret.
        if len(salt)!=32:raise Unknown('salt length')
        raw=salt+hashlib.pbkdf2_hmac('sha256',b'fixture-correct-password',salt,100000)
        stored=base64.b64encode(raw).decode();self.allowed_imports.update(base64=base64,hashlib=hashlib)
        self.globals.update(os=NS(getenv=lambda key,default=None:stored if c['environment_source'] and key=='SALTED_PASS' else default),
            datastore=NS(data={'settings':{'application':{'password':stored}}}))
        self.user=self.record('login_user',id=None);self.tracked['user']=self.user;self.method(self.user,'check_password','check_password')
        self.globals.update(User=lambda:self.user,request=self.record('request',args={'redirect':'/watchlist'},form={'password':c['password']},method=c['method']),
            is_safe_url=lambda path:path=='/watchlist',url_for=lambda endpoint,**kw:'/watchlist' if endpoint=='watchlist.index' else '/login',
            gettext=lambda message:message,flash=lambda *a,**kw:None,render_template=lambda template,**kw:'login-form',redirect=lambda path:{'redirect':path},
            flask_login=NS(current_user=self.record('current_user',is_authenticated=c['authenticated']),login_user=self.event('session.login_user',lambda user,remember:True)))
        self.entry_args={'login':{}}
    def setup_R22(self):
        enc=self.engine();self.globals.update(_get_enforcer=lambda:enc,get_current_tenant_and_roles=lambda:None)
        self.factory_args=[self.c['object'],self.c['action']]
        self.entry_args={'require_permission':dict(tenant_roles=(self.c['tenant'],self.c['roles']))}
    def setup_R23(self):
        registry=None if not self.c['registry'] else NS(resolve_token=self.event('registry.resolve_token',lambda token:{'agent_id':'agent-1'} if token=='fixture-agent-token' else None))
        self.globals['registry']=registry;self.entry_args={'resolve_agent':dict(request=self.record('request',headers=self.c['headers']))}
    def setup_R25(self):
        Role=Enum('UserRole',self.case['constants']['roles'],type=str);self.globals['UserRole']=Role
        user=self.record('user',role=Role(self.c['role']))
        obj=self.record('team_service',_raise_forbidden=lambda msg:(_ for _ in ()).throw(HTTPException(403,msg)))
        entry=self.sample['entry'];self.entry_args={entry:(dict(current_user=user) if entry=='require_only_system_admin' else dict(self=obj,team=self.record('team',creator_id=self.c['owner']),user_id=self.c['actor']))}
    def setup_R27(self):
        user=self.record('user',roles=self.c['roles']);self.globals['get_current_user']=lambda:user
        self.factory_args=[self.c['required']];self.entry_args={'require_role':dict(current_user=user)}
    def setup_R28(self):
        Scope=Enum('Scope',self.case['constants']['scopes'],type=str);Platform=Enum('Platform',self.case['constants']['platforms'],type=str)
        self.globals['Scope']=Scope
        principal=self.record('principal',scoped=True,scopes=frozenset(Scope(x) for x in self.c['scopes']))
        principal.denial=lambda **kw:{'subject':'fixture-key','scopes':[x.value for x in principal.scopes]}
        self.method(principal,'permits','principal_permits')
        self.entry_args={'authorize':dict(principal=principal,platform=Platform(self.c['platform']))}
    def setup_R31(self):
        obj=self.record('authorization_handler',enforcer=self.engine())
        self.entry_args={'verify_authorization':dict(self=obj,username=self.c['subject'],parameter_name=self.c['object'],action=self.c['action'])}
    def setup_R32(self):
        principal=self.record('principal',tenant_id=self.c['tenant'],is_admin=self.c['admin'])
        self.globals.update(DEFAULT_TENANT_ID=self.case['constants']['default_tenant'],get_principal=lambda:principal)
        self.entry_args={'require_admin':dict(principal=principal),'require_operator':dict(principal=principal)}
    def setup_R33(self):
        c=self.c;now=datetime.fromisoformat(c['now']);self.globals.update(datetime=NS(now=lambda tz:now),timezone=timezone)
        token=self.record('token',approved_by=c['approved_by'],required_approvals=c['required_approvals'],expires_at=datetime.fromisoformat(c['expires']),revoked=c['revoked'],scope=c['scope'])
        for name in ('is_approved','is_expired','is_active'):self.property(token,name,'token_'+name)
        obj=self.record('protocol',_tokens={} if c['missing'] else {'fixture-token':token})
        self.entry_args={'check_scope':dict(self=obj,token_id='fixture-token',required_scope=c['required'])}
    def setup_R35(self):
        c=self.c;user=self.record('user',username='alice',role='reader',permissions=['read'])
        def decode(*a,**kw):
            if c['token_error']:raise TokenError('invalid fixture token')
            return c['payload']
        self.globals.update(jwt=NS(decode=self.event('verified_token_claims',decode),PyJWTError=TokenError),SECRET_KEY='fixture-placeholder-not-a-secret',ALGORITHM='HS256',
            get_user=self.event('user_lookup',lambda username:user if c['known_user'] else None),oauth2_scheme=lambda:None)
        self.entry_args={'get_current_user':dict(token='fixture-token')}
    def setup_R37(self):
        c=self.c;user=self.record('user',is_authenticated=c['authenticated']);form=self.record('form',publish_public=c['public'],database=self.record('database',id=1))
        def get(**kwargs):
            if not c['collaborator']:raise DoesNotExist()
            return self.record('mapping')
        self.globals['UserDatabaseRoleMap']=NS(objects=NS(get=self.event('database_role_mapping',get)),DoesNotExist=DoesNotExist)
        self.entry_args={'has_permission_for_form':dict(user=user,form_model=form)}
    def setup_R40(self):
        c=self.c;self.self=self.record('permission_service');self.method(self.self,'check','service_check')
        enc=self.engine();db=self.record('session') if c['db'] else None
        token=None if c['token_mode'] is None else self.record('token',scope_mode=c['token_mode'],scopes=c['token_scopes'])
        group=self.record('group',headquarters_tenant_id='headquarters')
        self.globals.update(CheckContext=lambda **kw:self.record('check_context',**kw),current_token_ctx=NS(get=lambda:token),
            PLATFORM_WRITER_ROLES=tuple(self.case['constants']['platform_writers']),GROUP_ADMIN_HQ_ROLES=frozenset(self.case['constants']['group_admin_roles']),
            _casbin_mod=NS(get_enforcer=lambda:enc,enforcer_lock=contextlib.nullcontext),run_in_threadpool=self.event('threadpool',lambda fn:fn(),True),
            GroupRepository=lambda session:NS(list_for_tenant=self.event('tenant_group_lookup',lambda tenant:[group] if c['group'] else [],True)),
            UserTenantRepository=lambda session:NS(current_role=self.event('headquarters_membership',lambda user,tenant:None if c['group_role'] is None else self.record('membership',role=c['group_role']),True)))
        rules=[]
        for meta in self.case['constants']['rules']:
            r=self.record('rule-'+meta['name'],objs=None if meta['objs'] is None else frozenset(meta['objs']),acts=None if meta['acts'] is None else frozenset(meta['acts']),needs_db=meta['needs_db'],decision=meta['decision'])
            self.method(r,'applies','rule_applies');rules.append(r)
        self.globals['CHECK_RULES']=tuple(rules)
        args=dict(self=self.self,user_id='alice',tenant_id=c['tenant'],obj=c['object'],act=c['action'],platform_role=c['platform_role'],db=db)
        self.entry_args={'service_require':args}
