"""Explicit normal entry profiles and separate source-functional references."""
import base64
from copy import deepcopy
import hashlib
import sqlite3
if __package__:
    from .interpreter import (Capability,DataRecord,Deferred,ErrorType,Interpreter,SerialContext,SliceFault,AdmissionError,program_for,RecordType)
else:
    from interpreter import (Capability,DataRecord,Deferred,ErrorType,Interpreter,SerialContext,SliceFault,AdmissionError,program_for,RecordType)

SAFE=('GET','HEAD','OPTIONS')
def record(kind,**fields):return DataRecord(kind,fields)
def ret(value):return dict(kind='return',value=value)
def ref(name):return {'ref':name}
def err(name,status=None,code=None):
    d=dict(kind='error',name=name)
    if status is not None:d['status']=status
    if code is not None:d['code']=code
    return d

class World:
    def __init__(self,inputs,control=None):
        self.i=inputs;self.control=control;self.events=[];self.identities={};self.kept=[];self.closed=False
        self.db=sqlite3.connect(':memory:')
        self.db.execute('create table share_counter(id integer primary key,value integer)')
        self.db.execute('insert into share_counter values(1,?)',(inputs.get('share_count',1),))
        self.cache={};self.state=dict(selected_company=None,scheduled_active=[],active_updates=[],deleted_cookies=[])
        self.user=self.named('user',record('User',pk=1,id='u1',email='one@example.invalid',role=inputs.get('role','user'),
            is_authenticated=inputs.get('authenticated',True),is_superuser=inputs.get('superuser',False),is_active=inputs.get('active',True)))
        self.other=self.named('other',record('User',pk=2,id='u2',email='two@example.invalid',role='user',is_authenticated=True,is_superuser=False,is_active=True))
        self.space=record('Space',pk=1,created_by=self.user,no_sharing_limit=inputs.get('unlimited',False))
        self.token=self.named('token',record('Token',pk=1))
        self.request=self.named('request',record('Request',user=self.user,method=inputs.get('method','GET'),
            space=self.space,query_params={'share':inputs.get('share')},DATA=deepcopy(inputs.get('data',{})),
            META={'HTTP_AUTHORIZATION':inputs.get('header','')},COOKIES={'preview':inputs.get('preview_cookie')},cookies=deepcopy(inputs.get('cookies',{})),
            scope={'path':inputs.get('path','/api/items')},headers=deepcopy(inputs.get('headers',{}))))
        self.request.fields['_request']=self.request
        self.request.fields['state']=record('RequestState',**({'token':record('Credential',credentials='middleware-normal')} if inputs.get('middleware_token') else {}))
        self.request.fields['state'].writable=frozenset({'user','auth_type','claims'})
        self.request.fields['app']=record('App',state=record('AppState',redis=None))
        self.view=record('View',kwargs={'pk':1} if inputs.get('has_pk',True) else {})
        owner=self.user if inputs.get('owner',True) else self.other
        self.obj=self.named('object',record('Recipe',pk=10,owner=owner,user=owner,created_by=owner,
            project_id=1,project=record('Project',pk=1),space=self.space if inputs.get('same_space',True) else record('Space',pk=2),
            private=inputs.get('private',False)))
        self.obj.fields.update(get_owner=self.cap('get_owner',lambda:'orphan' if inputs.get('orphan') else owner),
            get_space=self.cap('get_space',lambda:self.space if inputs.get('space_owner',True) else record('Space',pk=2,get_owner=self.cap('other_space_owner',lambda:self.other))),
            get_shared=self.cap('get_shared',lambda:[self.user] if inputs.get('shared') else []),
            shared=record('Sharing',all=self.cap('shared_rows',lambda:[self.user] if inputs.get('shared') else [])),
            userspace_set=record('RelatedSpaces',all=self.cap('related_spaces',lambda:[self.space] if inputs.get('same_space',True) else [])))
        self.space.fields['get_owner']=self.cap('space_owner',lambda:self.user)
    def named(self,name,x):self.identities[id(x)]=name;self.kept.append(x);return x
    def normalize(self,x):
        if id(x) in self.identities:return ref(self.identities[id(x)])
        if isinstance(x,DataRecord):return dict(record=x.kind,fields={k:self.normalize(v) for k,v in x.fields.items() if not isinstance(v,(Capability,DataRecord))})
        if type(x) in (list,tuple):return [self.normalize(v) for v in x]
        if type(x) in (set,frozenset):return sorted(self.normalize(v) for v in x)
        if type(x) is dict:return {str(k):self.normalize(v) for k,v in x.items()}
        if isinstance(x,SliceFault):return dict(error=x.name)
        if isinstance(x,Deferred):
            name,args,kwargs=getattr(x,'owned_call',(None,(),{}))
            return dict(deferred=name,args=[self.normalize(a) for a in args],kwargs={k:self.normalize(v) for k,v in kwargs.items()})
        if type(x) is bytes:return dict(bytes=x.hex())
        return x
    def cap(self,name,fn,asynchronous=False):
        def action(*a,**k):
            self.events.append(dict(call=name,args=[self.normalize(v) for v in a],kwargs={key:self.normalize(v) for key,v in k.items()}))
            return fn(*a,**k)
        return Capability(name,action,asynchronous)
    def error(self,name,*a,**k):
        f=SliceFault(name,str(a[0]) if a else '')
        if name=='HTTPException':f.status=k.get('status_code',a[0] if a else None)
        if 'code' in k:f.code=k['code']
        return f
    def query(self,rows):
        return record('Query',rows=rows,first=self.cap('query.first',lambda:rows[0] if rows else None),
            exists=self.cap('query.exists',lambda:bool(rows)),values_list=self.cap('query.values_list',lambda *a,**k:rows))
    def source(self,key,args):return self.machine.run(key.replace('.','__'),args)
    def attach(self,receiver,attribute,key):
        receiver.fields[attribute]=self.cap('source:'+key,lambda *a,**k:self.machine.run(key.replace('.','__'),[receiver,*a],k))
    def outcome(self,value=None,fault=None):
        if fault is None:return ret(self.normalize(value))
        return err(fault.name,getattr(fault,'status',None),getattr(fault,'code',None))
    def snapshot(self):
        return dict(share_count=self.db.execute('select value from share_counter where id=1').fetchone()[0],
            cache=dict(self.cache),request_state={k:self.normalize(v) for k,v in self.request.fields['state'].fields.items() if k in ('user','auth_type','claims')},**self.state)
    def close(self):
        if not self.closed:self.db.close();self.closed=True

def recipe_setup(w,qualified):
    i=w.i;receiver=record('Receiver');helpers=['is_object_owner','is_space_owner','is_object_shared','is_object_household',
        'get_allowed_groups','has_group_permission','share_link_valid','has_recipe_permission']
    helpers += ['CustomIsOwner.has_permission','CustomIsOwner.has_object_permission']
    helpers=[h for h in helpers if h!=qualified]
    def group_rows(*a,**k):
        groups=list(i.get('groups',['user']))
        group=record('Groups',values_list=w.cap('group_names',lambda *a,**k:groups))
        us=record('UserSpace',groups=group)
        return w.query([us] if i.get('active_spaces',1)==1 else [us,us] if i.get('active_spaces',1)>1 else [])
    w.user.fields['userspace_set']=record('UserSpaces',filter=w.cap('active_spaces',group_rows),values_list=w.cap('households',lambda *a,**k:[5]),all=w.cap('related_spaces',lambda:[w.space] if i.get('same_space',True) else []))
    if i.get('global_provider'):w.obj.fields['space']=None
    w.obj.fields['get_owner']=w.cap('get_owner',lambda:'orphan' if i.get('orphan') else w.user if i.get('owner',True) else w.other)
    w.other.fields['userspace_set']=w.user.fields['userspace_set']
    def cache_get(k,default=None):return w.cache.get(k,default)
    def cache_set(k,v,timeout=None):
        if w.control!='drop_cache':w.cache[k]=v
    if i.get('cached_groups'):w.cache['GROUP_CACHE_1_1']=list(i['cached_groups'])
    if i.get('share_cached'):w.cache['recipe_share_10_share-normal']=True
    share=record('ShareLink',request_count=i.get('share_count',1),space=w.space)
    share.writable=frozenset({'request_count'})
    def save_share():
        if w.control!='drop_save':w.db.execute('update share_counter set value=? where id=1',(share.fields['request_count'],))
    share.fields['save']=w.cap('share.save',save_share)
    def select_share(*a,**k):return w.query([share] if i.get('share_exists',True) and k.get('uuid')=='share-normal' else [])
    b=dict(cache=record('Cache',get=w.cap('cache.get',cache_get),set=w.cap('cache.set',cache_set)),
        settings=record('Settings',SHARING_LIMIT=i.get('sharing_limit',3)),SAFE_METHODS=SAFE,
        ShareLink=record('Model',objects=record('Manager',filter=w.cap('share.filter',select_share))),
        UserSpace=record('Model',objects=record('Manager',filter=w.cap('household.filter',lambda *a,**k:w.query([1] if i.get('household') else [])))),
        ValidationError=ErrorType('ValidationError'),Http404=ErrorType('Http404'))
    def super_receiver():
        if not w.machine.frames:raise AdmissionError('super outside source frame')
        owner,current=w.machine.frames[-1]
        if owner not in ('CustomIsOwnerReadOnly','CustomIsOwnerDestroyOnly'):raise AdmissionError('super owner outside fixed selected inheritance')
        return record('Base',has_permission=w.cap('source:CustomIsOwner.has_permission',lambda *a:w.source('CustomIsOwner.has_permission',[current,*a])),
            has_object_permission=w.cap('source:CustomIsOwner.has_object_permission',lambda *a:w.source('CustomIsOwner.has_object_permission',[current,*a])))
    if qualified.startswith(('CustomTokenHasScope.','CustomTokenHasReadWriteScope.')):
        def super_receiver():return record('TokenScopeBase',has_permission=w.cap('oauth_scope',lambda *a:bool(i.get('scope_ok',True))))
    b['super']=Capability('selected fixed super',super_receiver)
    # The source isinstance dispatch distinguishes a bound AccessToken record.
    b['AccessToken']=RecordType('AccessToken',())
    w.request.fields['auth']=record('AccessToken') if i.get('oauth') else None
    args=[receiver,w.request,w.view]
    if qualified.endswith('has_object_permission'):args.append(w.user if qualified.startswith('CustomUserPermission') and i.get('self_object') else w.obj)
    return helpers,b,args

def taiga_setup(w,qualified,path):
    i=w.i;receiver=record('Receiver',project_perm='view',comment_perm='comment',update_perm='update')
    auth=w.user.fields['is_authenticated']
    # This source uses the old callable is_authenticated interface in the
    # private-profile component; other selected entries use the Boolean field.
    if qualified=='CanRetrieveUser.check_permissions':w.user.fields['is_authenticated']=Capability('legacy authentication accessor',lambda:auth)
    def perm(user,permission,obj):
        if user is not w.user:raise AdmissionError('permission primitive received another principal')
        return bool(i.get('comment_allowed') if permission=='comment' else i.get('update_allowed') if permission=='update' else i.get('permission',False))
    def admin(user,obj):
        if user is not w.user:raise AdmissionError('admin primitive received another principal')
        return bool(i.get('admin',False))
    def can_leave(*a):
        if i.get('membership_missing'):raise SliceFault('MembershipDoesNotExist')
        return bool(i.get('can_leave',True))
    b=dict(user_has_perm=w.cap('permission',perm),is_project_admin=w.cap('admin',admin),
        services=record('Services',user_has_perm=w.cap('permission',perm),is_project_admin=w.cap('admin',admin),can_user_leave_project=w.cap('can_leave',can_leave)),
        settings=record('Settings',PRIVATE_USER_PROFILES=i.get('private_profiles',False)),
        exc=record('Errors',PermissionDenied=ErrorType('PermissionDenied')),
        models=record('Models',Membership=record('Membership',DoesNotExist=ErrorType('MembershipDoesNotExist'))),
        _=Capability('literal translation',lambda s:s))
    w.obj.fields['webhook']=record('Webhook',project=w.obj.fields['project'])
    b['apps']=record('Apps',get_model=w.cap('project_model',lambda *a:record('ProjectModel',objects=record('Manager',get=w.cap('project.get',lambda **k:record('Project',pk=k['pk']))))))
    if i.get('absent_object'):obj=None
    else:obj=w.obj
    if qualified=='CanUseToken.check_permissions':w.obj.fields['user']=w.user if i.get('owner',True) else w.other
    if qualified=='IsObjectOwner.check_permissions' and i.get('absent_owner'):w.obj.fields['owner']=None
    if qualified in ('Not.check_permissions','Or.check_permissions','And.check_permissions'):
        components=[]
        for n,value in enumerate(i.get('components',[])):
            components.append(record('Component',check_permissions=w.cap('component'+str(n),lambda *a,_value=value,**k:_value)))
        receiver.fields['components']=components
    if 'authentication.py' not in path:return [],b,[receiver,w.request,w.view,obj]
    # All credentials are owned dummy strings; these are contracts for the
    # selected source handoff,not cryptographic validation or network requests.
    def authenticate(*a,**k):
        return None if i.get('missing_user') else w.user
    def decode(value):
        try:return base64.b64decode(value)
        except (ValueError,TypeError):raise SliceFault('TypeError')
    b.update(get_authorization_header=w.cap('header',lambda req:i.get('header','').encode()),
        base64=record('Base64',b64decode=w.cap('base64_decode',decode)),HTTP_HEADER_ENCODING='utf-8',
        authenticate=w.cap('credential_lookup',authenticate),exceptions=record('Errors',AuthenticationFailed=ErrorType('AuthenticationFailed')))
    if qualified=='JWTAuthentication.authenticate':
        receiver.fields.update(get_header=w.cap('header',lambda req:None if i.get('no_header') else 'owned-header'),
            get_raw_token=w.cap('raw_token',lambda header:None if i.get('no_raw') else 'owned-normal-token'),
            get_validated_token=w.cap('validate_token',lambda token:token_result(w)),get_user=w.cap('user_lookup',lambda token:w.user))
    if qualified=='SessionAuthentication.authenticate':
        def csrf(*a):
            if i.get('csrf_denied'):raise SliceFault('PermissionDenied')
        receiver.fields['enforce_csrf']=w.cap('csrf',csrf)
    args=[receiver,w.request];helpers=[]
    if qualified=='BasicAuthentication.authenticate':
        helpers=['BasicAuthentication.authenticate_credentials'];w.attach(receiver,'authenticate_credentials',helpers[0])
    if qualified=='BasicAuthentication.authenticate_credentials':args=[receiver,'owned-user','owned-password']
    return helpers,b,args

def token_result(w):
    if w.i.get('invalid_token'):raise SliceFault('InvalidToken')
    return w.token

def auth_setup(w,repo,qualified):
    i=w.i;receiver=record('Receiver');helpers=[]
    e=record('Errors',AuthenticationFailed=w.cap('AuthenticationFailed',lambda *a,**k:w.error('AuthenticationFailed',*a,**k)))
    b=dict(exceptions=e,_=Capability('literal translation',lambda s:s))
    if repo=='horilla/horilla-hr':
        b.update(AuthenticationFailed=ErrorType('AuthenticationFailed'),PermissionDenied=ErrorType('PermissionDenied'),
            logger=record('Logger',warning=w.cap('warning',lambda *a:None)))
        def jwt(req):
            if i.get('jwt_error'):raise SliceFault('InvalidToken')
            return None if i.get('jwt_none') else (w.user,w.token)
        b['JWTAuthentication']=Capability('fixed JWT provider',lambda:record('JWTProvider',authenticate=w.cap('jwt',jwt)))
        if qualified=='TenantScopedJWTAuthentication.authenticate':
            b['super']=Capability('fixed JWT base',lambda:record('Base',authenticate=w.cap('jwt',jwt)))
            b['resolve_company_id']=w.cap('resolve_company',lambda user:i.get('company'))
            def choose(company):
                if w.control!='drop_tenant':w.state['selected_company']=company
            b['set_selected_company']=w.cap('set_company',choose)
        if qualified=='CandidateAuthenticationBackend.authenticate':
            candidates=[]
            for n,ok in enumerate(i.get('password_matches',[False,True])):
                user=w.named('candidate'+str(n),record('Candidate',pk=n+1,check_portal_password=w.cap('check_password'+str(n),lambda pw,_ok=ok:_ok)))
                candidates.append(user)
            b['Candidate']=record('CandidateModel',objects=record('Manager',filter=w.cap('candidate.filter',lambda **k:candidates)))
            return [],b,[receiver,w.request,i.get('username',' One@Example.invalid '),i.get('password','owned-password')]
        return [],b,[receiver,w.request]
    if repo=='argilla-io/argilla':
        receiver.fields['scheme']=w.cap('scheme',lambda req:None if i.get('no_credentials') else record('Credentials',credentials='owned-normal-token'),True)
        def decode(t):
            if i.get('invalid_token'):raise SliceFault('JWTDecodeError')
            return dict(id='u1',**({'scope':['read','write']} if i.get('with_scope',True) else {}))
        b['JWT']=record('JWT',decode=w.cap('decode',decode))
        b['UserInfo']=Capability('plain user-info construction',lambda d:dict(d))
        b['AuthCredentials']=Capability('scope construction',lambda scopes:record('AuthCredentials',scopes=scopes))
        return [],b,[receiver,w.request]
    if repo=='langgenius/dify':
        def kind(token):return i.get('token_type','known')
        row=record('TokenRow',subject_email='one@example.invalid',subject_issuer='owned-issuer',account_id='a1',client_id='c1',token_id='t1',expires_at=2000)
        def limit(value):
            if i.get('rate_limited'):raise SliceFault('RateLimitExceeded')
        receiver.fields['_resolvers']={'known':record('Resolver',resolve=w.cap('resolve',lambda value:None if i.get('missing_row') else row))}
        b.update(TokenType=record('TokenType',for_token=w.cap('classify_token',kind)),InvalidBearerError=ErrorType('InvalidBearerError'),
            sha256_hex=w.cap('token_fingerprint',lambda token:hashlib.sha256(token.encode()).hexdigest()),
            enforce_bearer_rate_limit=w.cap('rate_limit',limit),AuthContext=Capability('context construction',lambda **k:record('AuthContext',**k)))
        return [],b,[receiver,'owned-normal-token']
    raise AdmissionError('no declared authentication setup')

def baserow_setup(w,qualified):
    i=w.i;receiver=record('Receiver',use_user_source_authentication_header=i.get('service_header',False))
    b=dict(exceptions=record('Errors',AuthenticationFailed=w.cap('AuthenticationFailed',lambda *a,**k:w.error('AuthenticationFailed',*a,**k))),
        InvalidToken=ErrorType('InvalidToken'),DeactivatedUserException=ErrorType('DeactivatedUserException'))
    if qualified=='JSONWebTokenAuthentication.authenticate':
        def base_auth(request):
            if i.get('invalid_token'):raise SliceFault('InvalidToken')
            return None if i.get('no_credentials') else (w.user,w.token)
        b['super']=Capability('declared JWT base entry',lambda:record('JWTBase',authenticate=w.cap('jwt_base',base_auth)))
        w.user.fields['profile']=record('Profile',is_jwt_token_valid=w.cap('profile_token_valid',lambda token:bool(i.get('profile_valid',True))))
        b.update(ERROR_INVALID_ACCESS_TOKEN=('ERROR_INVALID_ACCESS_TOKEN',401,'Access token is expired or invalid.'),
            set_user_session_data_from_request=w.cap('session_setup',lambda *a:None),
            set_user_impersonated_from_token=w.cap('impersonation_setup',lambda *a:None),
            setup_user_in_baggage_and_spans=w.cap('span_context',lambda *a:SerialContext(lambda:w.events.append(dict(call='span.enter')),lambda:w.events.append(dict(call='span.exit')),False)),
            setup_user_in_sentry=w.cap('sentry_setup',lambda *a:None))
    elif qualified=='UserSourceJSONWebTokenAuthentication.authenticate':
        fields={'user_source':10,'user_id':1}
        if i.get('missing_claim'):fields.pop('user_id')
        w.token=w.named('token',fields)
        def parse(raw):
            if i.get('invalid_token'):raise SliceFault('TokenError')
            return w.token
        def selected_user(source,user_id):
            if i.get('missing_user'):raise SliceFault('UserNotFound')
            if source is not source_record or user_id!=1:raise AdmissionError('user lookup consumed another source or identity')
            return w.user
        source_type=record('SourceType',get_user=w.cap('source_user',selected_user))
        workspace=w.named('workspace',record('Workspace',pk=3))
        source_record=w.named('user_source',record('UserSource',pk=10,application=record('Application',workspace=workspace),get_type=w.cap('source_type',lambda:source_type)))
        def lookup(*a,**k):
            if i.get('lookup_error'):raise SliceFault(i['lookup_error'])
            return source_record
        def check(user,operation,*,workspace,context):
            if user is not w.user or context is not source_record or workspace is not source_record.fields['application'].fields['workspace']:
                raise AdmissionError('source permission check lost exact identity/context')
            if i.get('permission_error'):raise SliceFault(i['permission_error'])
        receiver.fields.update(get_header=w.cap('header',lambda request:None if i.get('no_header') else 'owned-header'),
            get_raw_token=w.cap('raw_token',lambda header:None if i.get('no_raw') else 'owned-normal-token'))
        b.update(UserSourceAccessToken=w.cap('source_token',parse),USER_SOURCE_CLAIM='user_source',jwt_settings=record('JWTSettings',USER_ID_CLAIM='user_id'),
            TokenError=ErrorType('TokenError'),UserSourceDoesNotExist=ErrorType('UserSourceDoesNotExist'),
            PermissionDenied=ErrorType('PermissionDenied'),UserNotInWorkspace=ErrorType('UserNotInWorkspace'),UserNotFound=ErrorType('UserNotFound'),
            Application=record('ApplicationModel',DoesNotExist=ErrorType('ApplicationDoesNotExist')),
            AnonymousUser=Capability('explicit anonymous default',lambda:record('User',pk=0,is_authenticated=False)),
            UserSourceService=Capability('fixed service receiver',lambda:record('Service',get_user_source_by_uid=w.cap('service_lookup',lookup))),
            UserSourceHandler=Capability('fixed handler receiver',lambda:record('Handler',get_user_source_by_uid=w.cap('handler_lookup',lookup))),
            CoreHandler=Capability('fixed core permission receiver',lambda:record('Core',check_permissions=w.cap('source_permission',check))),
            AuthenticateUserSourceOperationType=record('OperationType',type='authenticate_user_source'))
    elif qualified=='BuilderPreviewAuthentication.authenticate':
        actor=w.named('actor',record('Actor',pk=1,builder_id=i.get('actor_builder',10)))
        def lookup(token):
            if i.get('invalid_actor'):raise SliceFault('BuilderPreviewGrantInvalid')
            return actor
        receiver.fields['get_builder_id']=w.cap('builder_id',lambda req:10)
        def mapped(mapping):
            def translate(fault):
                matches=[v for k,v in mapping.items() if k.name==fault.name]
                if not matches:return fault
                code,status,message=matches[0];f=SliceFault('APIException',message);f.code=code;f.status=status;return f
            return record('MappedContext',enter=lambda:None,exit=lambda:None,translate=translate)
        b.update(map_exceptions=Capability('fixed explicit map without registry overrides',mapped),
            BuilderPreviewSessionInvalid=ErrorType('BuilderPreviewSessionInvalid'),BuilderPreviewGrantInvalid=ErrorType('BuilderPreviewGrantInvalid'),
            ERROR_BUILDER_PREVIEW_SESSION_INVALID=('ERROR_BUILDER_PREVIEW_SESSION_INVALID',401,'The builder preview session is missing, invalid, or expired.'),
            get_builder_preview_cookie_name=Capability('configured preview cookie name',lambda:'preview'),
            BuilderPreviewGrantHandler=Capability('selected preview actor provider',lambda:record('GrantHandler',actor_from_token=w.cap('preview_actor',lookup))))
    elif qualified=='AuthenticateFromUserSessionAuthentication.authenticate':
        session=w.named('session',record('Session',user_id=1,session_hash='normal-session' if i.get('session_hash',True) else '',token_hash='normal-token',expires_at=i.get('expires_at',2000)))
        def lookup(**k):
            if i.get('missing_user'):raise SliceFault('UserDoesNotExist')
            if k!={'id':1}:raise AdmissionError('session identity lookup differs')
            return w.user
        manager=record('Manager',select_related=w.cap('select_profile',lambda *a:record('Query',get=w.cap('session_user',lookup))))
        model=record('UserModel',objects=manager,DoesNotExist=ErrorType('UserDoesNotExist'))
        b.update(extract_user_session_from_request=w.cap('session_decode',lambda req:None if i.get('no_session') else session),
            get_user_model=Capability('fixed selected model',lambda:model),time=record('Time',time=w.cap('clock',lambda:1000)),
            UserHandler=Capability('selected revocation receiver',lambda:record('Handler',refresh_token_hash_is_blacklisted=w.cap('revocation_lookup',lambda token:bool(i.get('revoked',False))))))
    else:raise AdmissionError('unknown Baserow contract')
    return [],b,[receiver,w.request]

def webui_setup(w,qualified):
    i=w.i
    helpers=[]
    b=dict(ENABLE_OTEL=False,WEBUI_AUTH_TRUSTED_EMAIL_HEADER=i.get('trusted_header',''),ENABLE_PUBLIC_ACTIVE_USERS_COUNT=i.get('public_usage',False),
        status=record('Status',HTTP_401_UNAUTHORIZED=401,HTTP_403_FORBIDDEN=403),
        ERROR_MESSAGES=record('Errors',INVALID_TOKEN='source-invalid-token',API_KEY_NOT_ALLOWED='source-api-key-not-allowed',ACCESS_PROHIBITED='source-access-prohibited',UNAUTHORIZED='source-unauthorized'),
        HTTPException=ErrorType('HTTPException'),
        log=record('Logger',error=w.cap('log.error',lambda *a:None)))
    config={'auth.enable_api_keys':i.get('enable_api_keys',True),'user.permissions':{'configured':True},
        'auth.api_key.endpoint_restrictions':i.get('restricted',False),'auth.api_key.allowed_endpoints':i.get('allowed_paths','/api/items')}
    def by_key(key):return None if i.get('missing_user') else w.user
    def by_id(pk):
        if i.get('missing_user'):return None
        return w.user if pk=='u1' else w.other
    def last_active(pk):w.state['active_updates'].append(pk)
    def count():
        if i.get('usage_error'):raise SliceFault('DatabaseError')
        return 4
    b['Users']=record('Users',get_user_by_api_key=w.cap('api_user',by_key,True),get_user_by_id=w.cap('jwt_user',by_id,True),
        update_last_active_by_id=w.cap('active_update',last_active,True),get_active_user_count=w.cap('active_count',count,True))
    b['Config']=record('Config',get_many=w.cap('config_read',lambda *a:dict(config),True))
    b['has_permission']=w.cap('api_permission',lambda *a:bool(i.get('api_permission',True)),True)
    def decode(token):
        if i.get('invalid_token'):raise SliceFault('DecodeError')
        if i.get('no_claim'):return {}
        return {'id':'u2' if token=='cookie-normal' else 'u1'}
    b['decode_token']=w.cap('decode',decode)
    b['is_valid_token']=w.cap('token_current',lambda *a:bool(i.get('token_current',True)),True)
    def schedule(pending):
        if not isinstance(pending,Deferred) or pending.consumed:raise AdmissionError('scheduler requires one fresh owned coroutine')
        name,args,kwargs=getattr(pending,'owned_call',(None,(),{}))
        if name!='active_update' or len(args)!=1 or kwargs:raise AdmissionError('scheduled callback has no declared last-active binding')
        pending.consumed=True;w.state['scheduled_active'].append(args[0])
    b['asyncio']=record('Asyncio',create_task=w.cap('schedule_active',schedule))
    def delete(name):w.state['deleted_cookies'].append(name)
    response=record('Response',delete_cookie=w.cap('delete_cookie',delete))
    if qualified=='get_current_usage':
        b['get_models_in_use']=w.cap('model_usage',lambda:['owned-model'])
        return [],b,[w.user]
    if qualified=='get_current_user_by_api_key':return [],b,[w.request,'sk-owned-normal']
    if qualified=='get_current_user':
        helpers=['get_current_user_by_api_key']
        token=i.get('bearer_token','bearer-normal') if i.get('bearer',True) else None
        auth=None if token is None else record('AuthCredentials',credentials=token)
        return helpers,b,[w.request,response,record('BackgroundTasks'),auth]
    raise AdmissionError('unknown web user profile')

def setup(w,contract):
    repo=contract['repository'];q=contract['function']
    if repo=='TandoorRecipes/recipes':return recipe_setup(w,q)
    if repo=='taigaio/taiga-back':return taiga_setup(w,q,contract['path'])
    if repo=='baserow/baserow':return baserow_setup(w,q)
    if repo=='open-webui/open-webui':return webui_setup(w,q)
    return auth_setup(w,repo,q)
