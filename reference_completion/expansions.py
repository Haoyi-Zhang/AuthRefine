"""Declared raw fixtures and source-bound dependency adapters;no service runtime."""
from copy import deepcopy
import ast,re,uuid
if __package__:
    from .interpreter import Capability,DataRecord,SliceFault,AdmissionError
else:
    from interpreter import Capability,DataRecord,SliceFault,AdmissionError
def rec(kind,**fields):return DataRecord(kind,fields)
def literal(rows,name):
    values=[]
    for row in rows.values():
        for n in ast.parse(row['text']).body:
            if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name:
                try:v=ast.literal_eval(n.value)
                except (ValueError,TypeError):continue
                if v not in values:values.append(v)
    if len(values)!=1:raise AdmissionError('source literal binding is missing or ambiguous: '+name)
    return values[0]
def timepoint(seconds,microsecond=0):
    if type(seconds)is not int or abs(seconds)>10**12 or type(microsecond)is not int or not 0<=microsecond<1000000:raise AdmissionError('UTC timestamp outside declared finite value domain')
    t=rec('TimePoint',seconds=seconds,microsecond=microsecond)
    def replace(**k):
        if set(k)-{'tzinfo','microsecond'}:raise AdmissionError('timestamp replacement outside UTC projection')
        return timepoint(seconds,k.get('microsecond',microsecond))
    t.fields['replace']=Capability('UTC replacement',replace);return t
def observe(w,name,args,kwargs):
    mapping={'user_has_perm':'permission','is_project_admin':'admin','can_user_leave_project':'can_leave','UserProfile__is_jwt_token_valid':'profile_token_valid','set_user_session_data_from_request':'session_setup','set_user_impersonated_from_token':'impersonation_setup','has_permission':'api_permission','is_valid_token':'token_current','get_models_in_use':'model_usage','get_authorization_header':'header','JWTAuthentication__get_header':'header','JWTAuthentication__get_raw_token':'raw_token'}
    if name not in mapping:return
    if name in ('UserProfile__is_jwt_token_valid','JWTAuthentication__get_header','JWTAuthentication__get_raw_token'):args=args[1:]
    w.events.append(dict(call=mapping[name],args=[w.normalize(a) for a in args],kwargs={k:w.normalize(v) for k,v in kwargs.items()}))
def taiga(w,c,b):
    i=w.i;w.user.fields['is_anonymous']=not i.get('authenticated',True)
    raw=i.get('project_policy',{})
    role=list(raw.get('role_permissions',[p for p,k in (('view','permission'),('comment','comment_allowed'),('update','update_allowed')) if i.get(k,False)]))
    admin=raw.get('is_admin',i.get('admin',False));member=raw.get('is_member',True)
    m=rec('Membership',is_admin=admin,role=rec('Role',permissions=role)) if member else None
    def lookup(project):return m
    w.user.fields['cached_membership_for_project']=w.cap('membership_lookup',lookup)
    def project(pk):
        p=w.named('project-'+str(pk),rec('Project',pk=pk,anon_permissions=list(raw.get('anon_permissions',[])),public_permissions=list(raw.get('public_permissions',[]))))
        leave_admin=raw.get('leave_admin',not i.get('can_leave',True))
        owner=raw.get('is_owner',not i.get('can_leave',True));p.fields['owner']=w.user if owner else w.other
        own=rec('Membership',user=w.user,is_admin=leave_admin);other=rec('Membership',user=w.other,is_admin=True)
        rows=[own]+([other] if raw.get('other_active_admin',True) else [])
        def query(rs):
            return rec('MembershipQuery',exclude=w.cap('members.exclude',lambda **k:query([v for v in rs if v.fields['user'] is not k.get('user')])),count=w.cap('members.count',lambda:len(rs)))
        def get(**k):
            if i.get('membership_missing'):raise SliceFault('MembershipDoesNotExist')
            return own
        def filt(**k):return query([v for v in rows if (not k.get('is_admin') or v.fields['is_admin']) and (not k.get('user__is_active') or v.fields['user'].fields['is_active'])])
        p.fields['memberships']=rec('MembershipManager',get=w.cap('members.get',get),filter=w.cap('members.filter',filt))
        p.fields['cached_memberships_for_user']=w.cap('project_membership_lookup',lambda user:m)
        return p
    p1=project(1);w.obj.fields['project']=p1;w.obj.fields['webhook']=rec('Webhook',project=p1)
    if c['function']=='CanLeaveProject.check_permissions':w.obj.kind='Project';w.obj.fields.update(p1.fields)
    def model(*a):return rec('ModelType',instance_kind='Project',objects=rec('Manager',get=w.cap('project.get',lambda **k:project(k['pk']))))
    b['apps']=rec('Apps',get_model=w.cap('project_model',model))
    w.receiver.fields['project_perm']=raw.get('permission_name','view')
    rows=c['batch_constants']['taiga_permission_tables']
    b.update({key:[(s,s) for s in names] for key,names in rows.items()})
    services=b['services']
    for key in ('user_has_perm','is_project_admin','can_user_leave_project'):
        services.fields[key]=Capability('bound source '+key,lambda *a,_key=key,**k:w.machine.run(_key,list(a),k))
def taiga_header(w,c,b):
    i=w.i;q=c['function']
    if q=='BasicAuthentication.authenticate':w.request.fields['headers']['authorization']=i.get('header','');return
    b['api_settings']=rec('Settings',AUTH_HEADER_NAME='HTTP_AUTHORIZATION')
    b['AUTH_HEADER_TYPE_BYTES']={b'Bearer'};b['HTTP_HEADER_ENCODING']='utf-8'
    def failed(*a,**k):return w.error('AuthenticationFailed',*a,**k)
    b['AuthenticationFailed']=w.cap('AuthenticationFailed',failed)
    if i.get('no_header'):w.request.fields['META'].pop('HTTP_AUTHORIZATION',None)
    else:w.request.fields['META']['HTTP_AUTHORIZATION']=i.get('header','Other owned-normal-token' if i.get('no_raw') else 'Bearer owned-normal-token')
    for name in ('get_header','get_raw_token'):
        w.receiver.fields[name]=Capability('bound source '+name,lambda *a,_name=name:w.source('JWTAuthentication.'+_name,[w.receiver,*a]))
def baserow(w,c,b):
    i=w.i;q=c['function'];sources=c['helper_sources']
    if q=='BuilderPreviewAuthentication.authenticate':
        base=literal(sources,'BUILDER_PREVIEW_COOKIE_BASE_NAME');prefix=i.get('cookie_prefix','')
        b['settings']=rec('Settings',FRONTEND_COOKIE_PREFIX=prefix);b['BUILDER_PREVIEW_COOKIE_BASE_NAME']=base
        w.request.fields['COOKIES']={prefix+base:i.get('preview_cookie')};return
    if q!='JSONWebTokenAuthentication.authenticate':return
    w.user.writable=frozenset({'web_socket_id','untrusted_client_session_id','untrusted_client_action_group','remote_addr_ip','impersonated_by_user_id'})
    w.user_context_keys=w.user.writable
    w.request.fields['META'].update(deepcopy(i.get('meta',{})))
    token=w.named('token',dict(i.get('token_claims',dict(iat=i.get('token_iat',2),impersonated_by=i.get('impersonated_by')))));w.token=token
    def base(req):
        if i.get('invalid_token'):raise SliceFault('InvalidToken')
        return None if i.get('no_credentials') else (w.user,token)
    b['super']=Capability('declared JWT source provider',lambda:rec('JWTBase',authenticate=w.cap('jwt_base',base)))
    when=i.get('password_changed_at',1 if i.get('profile_valid',True) else 3)
    profile=rec('Profile',last_password_change=None if when is None else timepoint(when,i.get('password_change_microsecond',0)))
    profile.fields['iat_before_last_password_change']=Capability('source timestamp comparison',lambda stamp:w.source('UserProfile.iat_before_last_password_change',[profile,stamp]))
    profile.fields['is_jwt_token_valid']=Capability('source profile validity',lambda tok:w.source('UserProfile.is_jwt_token_valid',[profile,tok]));w.user.fields['profile']=profile
    b['datetime']=rec('Datetime',utcfromtimestamp=Capability('UTC integer timestamp',lambda stamp:timepoint(stamp)))
    b['timezone']=rec('Timezone',utc=rec('UTC'))
    settings=rec('Settings',CLIENT_SESSION_ID_HEADER='ClientSessionId',CLIENT_UNDO_REDO_ACTION_GROUP_ID_HEADER='ClientUndoRedoActionGroupId',WEBSOCKET_ID_HEADER='WebSocketId',MAX_CLIENT_SESSION_ID_LENGTH=i.get('session_id_limit',256))
    b['settings']=settings
    for key in ('UNTRUSTED_CLIENT_SESSION_ID_USER_ATTR','UNDO_REDO_ACTION_GROUP_ID','IMPERSONATED_BY_CLAIM','IMPERSONATED_BY_USER_ATTR'):b[key]=literal(sources,key)
    def assign(obj,key,value):
        if not isinstance(obj,DataRecord) or key not in obj.writable:raise AdmissionError('setattr outside declared mutable user fields')
        if w.control!='drop_user_context':obj.fields[key]=value
    b['setattr']=Capability('declared user-field mutation',assign)
    def match(pattern,value):
        if type(value)is not str or len(value)>16384 or pattern!='^[0-9a-zA-Z-]+$':raise AdmissionError('regex outside fixed source header predicate')
        return bool(re.match(pattern,value))
    b['re']=rec('Regex',match=Capability('fixed header predicate',match))
    def uid(value,version):
        try:uuid.UUID(value,version=version)
        except ValueError:raise SliceFault('ValueError')
        return None
    b['uuid']=rec('UUIDModule',UUID=Capability('owned UUID validation',uid))
    for key in ('InvalidClientSessionIdAPIException','InvalidUndoRedoActionGroupIdAPIException'):
        # Only the source exception name is part of this boundary observation.
        try:
            from .interpreter import ErrorType
        except ImportError:from interpreter import ErrorType
        b[key]=ErrorType(key)
def webui(w,c,b):
    i=w.i
    if c['function']=='get_current_usage':b['USAGE_POOL']=deepcopy(i.get('usage_pool',{'owned-model':[]}));return
    config={'auth.enable_api_keys':i.get('enable_api_keys',True),'user.permissions':deepcopy(i.get('default_permissions',{'features':{'api_keys':i.get('api_permission',True)}})),'auth.api_key.endpoint_restrictions':i.get('restricted',False),'auth.api_key.allowed_endpoints':i.get('allowed_paths','/api/items')}
    b['Config']=rec('Config',get_many=w.cap('config_read',lambda *a:deepcopy(config),True))
    b['DEFAULT_USER_PERMISSIONS']=deepcopy(i.get('permission_template',{'features':{'api_keys':False}}));b['deepcopy']=Capability('owned plain configuration copy',deepcopy)
    groups=[rec('Group',permissions=deepcopy(v)) for v in i.get('group_permissions',[])]
    b['Groups']=rec('Groups',get_groups_by_member_id=w.cap('group_rows',lambda *a,**k:groups,True))
    if c['function']!='get_current_user':return
    def decode(token):
        if i.get('invalid_token'):raise SliceFault('DecodeError')
        if i.get('no_claim'):return {}
        return deepcopy(i.get('claims',{'id':'u2' if token=='cookie-normal' else 'u1'}))
    b['decode_token']=w.cap('decode',decode)
    auth=rec('AuthRow',session_stamp=i.get('account_stamp',None if i.get('token_current',True) else 'changed'),mfa=rec('MfaRow',secret='owned-secret' if i.get('mfa_secret') else '',reset_required=i.get('mfa_reset',False)))
    conf=rec('MfaConfig',ENABLE_MFA=i.get('mfa_enabled',False),MFA_ALLOW_OAUTH_BYPASS=i.get('mfa_oauth_bypass',False),MFA_ALLOW_TRUSTED_HEADER_BYPASS=i.get('mfa_header_bypass',False))
    def mfa_required(method,config):return w.source('is_mfa_required',[method,config])
    b['_declared_imports']={('open_webui.utils.mfa',0,(('get_auth',None),('get_mfa_config',None),('is_mfa_required',None))):{'get_auth':w.cap('auth_row',lambda uid:auth,True),'get_mfa_config':w.cap('mfa_config',lambda:conf,True),'is_mfa_required':Capability('source MFA policy',mfa_required)}}
    if i.get('redis_enabled'):
        def read(key):
            if i.get('redis_error'):raise SliceFault('RedisError')
            return i.get('token_revoked') if ':token:' in key else i.get('revoked_at')
        w.request.fields['app'].fields['state'].fields['redis']=w.named('redis',rec('Redis',get=w.cap('redis.get',read,True)))
    try:
        from .interpreter import ErrorType
    except ImportError:from interpreter import ErrorType
    b.update(REDIS_KEY_PREFIX='owned',RedisError=ErrorType('RedisError'),revocation_log=rec('Logger',warning=w.cap('revocation_warning',lambda *a:None)))
def install(w,c,helpers,b,args):
    if not c.get('batch_expansion'):return helpers,b,args
    if c['batch_category']=='taiga_policy':
        import hashlib
        row=c['batch_choice_source'];tables={}
        if hashlib.sha256(row['text'].encode()).hexdigest()!=row['sha256'] or row['repository']!=c['repository'] or row['snapshot']!=c['snapshot']:raise ValueError('permission choice source differs')
        for n in ast.parse(row['text']).body:
            if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('ANON_PERMISSIONS','MEMBERS_PERMISSIONS','ADMINS_PERMISSIONS'):
                tables[n.targets[0].id]=[v.elts[0].value for v in n.value.elts]
        if tables!=c['batch_constants']['taiga_permission_tables']:raise ValueError('source permission table binding differs')
    w.receiver=args[0] if c['repository'] not in ('open-webui/open-webui',) else None
    def prepare(name,a,k):
        a=list(a)
        if w.control=='wrong_object' and name=='user_has_perm':a[2]=w.other
        if w.control=='wrong_scope' and name=='has_permission':a[1]='features.other'
        if w.control=='wrong_token' and name=='UserProfile__is_jwt_token_valid':a[1]=w.named('other-token',dict(a[1]))
        return a,k
    b['_prepare_source_call']=Capability('owned wrong-handoff control',prepare)
    b['_observe_source_call']=Capability('source-bound handoff observations',lambda name,a,k:observe(w,name,a,k))
    if c['repository']=='taigaio/taiga-back':
        if c['batch_category']=='taiga_policy':taiga(w,c,b)
        else:taiga_header(w,c,b)
    elif c['repository']=='baserow/baserow':baserow(w,c,b)
    elif c['repository']=='open-webui/open-webui':webui(w,c,b)
    return list(dict.fromkeys([*helpers,*c['batch_helpers']])),b,args
