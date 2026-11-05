"""Typed normal observations and independently specified dependency handoffs."""
import ast,base64,hashlib
def typed_equal(a,b):
    if type(a) is not type(b):return False
    if type(a) is dict:return a.keys()==b.keys() and all(typed_equal(a[k],b[k]) for k in a)
    if type(a) in (list,tuple):return len(a)==len(b) and all(typed_equal(x,y) for x,y in zip(a,b))
    if a is None or type(a) in (str,int,bool):return a==b
    return False
def ref(n):return {'ref':n}
SOURCE_UID='00000000000040008000000000000010'
SOURCE_OPERATION='application.user_source.authenticate'
def source_constants(packet):
    """Read two actual imported literals from attributed passive dependency text."""
    rows=packet.get('binding_sources',[]);trees={}
    for row in rows:
        if hashlib.sha256(row['text'].encode()).hexdigest()!=row['sha256']:raise ValueError('dependency source identity differs')
        trees[row['path']]=ast.parse(row['text'])
    prefix='backend/src/baserow/core/user_sources/'
    constants=trees[prefix+'constants.py'];operations=trees[prefix+'operations.py']
    keys=[n.value.value for n in constants.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='USER_SOURCE_CLAIM' and isinstance(n.value,ast.Constant)]
    classes=[n for n in operations.body if isinstance(n,ast.ClassDef) and n.name=='AuthenticateUserSourceOperationType']
    if len(keys)!=1 or len(classes)!=1:raise ValueError('ambiguous selected source constant')
    labels=[n.value.value for n in classes[0].body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='type' and isinstance(n.value,ast.Constant)]
    if len(labels)!=1 or type(keys[0]) is not str or type(labels[0]) is not str:raise ValueError('source constant is not one literal string')
    result={'USER_SOURCE_CLAIM':keys[0],'AuthenticateUserSourceOperationType.type':labels[0]}
    for c in packet['references']['contracts']:
        if c['function']=='UserSourceJSONWebTokenAuthentication.authenticate' and c.get('source_constants')!=result:raise ValueError('contract constants differ from original definitions')
    return result
def rec(n,**f):return {'record':n,'fields':f}
def obligations(c,i):
    """Arguments that define the selected handoff,not dependency implementation."""
    q=c['function'];repo=c['repository'];r={}
    def put(n,a=(),k=None):r[n]={'args':list(a),'kwargs':{} if k is None else k}
    if repo=='TandoorRecipes/recipes':
        put('active_spaces',k={'active':True});put('group_names',['name'],{'flat':True})
        put('households',['household_id'],{'flat':True})
        put('household.filter',k={'user':ref('user'),'space':rec('Space',pk=2) if not i.get('same_space',True) else rec('Space',pk=1,created_by=ref('user'),no_sharing_limit=i.get('unlimited',False)), 'household__in':[5]})
        put('share.filter',k={'recipe':ref('object'),'uuid':i.get('share'),'abuse_blocked':False})
        put('share.save');put('oauth_scope',[ref('request'),rec('View',kwargs={'pk':1} if i.get('has_pk',True) else {})])
        for n in ('get_owner','get_space','get_shared','shared_rows','space_owner','other_space_owner','related_spaces','query.first','query.exists'):put(n)
    elif repo=='taigaio/taiga-back':
        if q in ('Not.check_permissions','Or.check_permissions','And.check_permissions'):
            for n in range(len(i.get('components',[]))):put('component'+str(n),[ref('request'),rec('View',kwargs={'pk':1} if i.get('has_pk',True) else {}),None if i.get('absent_object') else ref('object')])
        pid=i.get('data',{}).get('project') or 1
        obj=None if i.get('absent_object') else ref('object');project=ref('project-'+str(pid)) if c.get('batch_category')=='taiga_policy' else rec('Project',pk=pid)
        if q=='CommentAndOrUpdatePerm.check_permissions':
            # Permission labels depend on the source-selected comment/update branch.
            d=i.get('data',{});labels=['comment'] if set(d)-{'version'}=={'comment'} and i.get('comment_allowed') else ['comment','update'] if set(d)-{'version'}=={'comment'} else ['update']
            r['permission']=[{'args':[ref('user'),p,project],'kwargs':{}} for p in labels]
            put('project_model',['projects','Project']);put('project.get',k={'pk':i.get('data',{}).get('project')})
        else:put('permission',[ref('user'),i.get('project_policy',{}).get('permission_name','view'),obj])
        put('admin',[ref('user'),(ref('project-1') if c.get('batch_category')=='taiga_policy' else rec('Project',pk=1)) if q.startswith('IsWebhook') else obj]);put('can_leave',[ref('user'),obj])
        if c.get('batch_category')=='taiga_policy':
            put('membership_lookup',[ref('project-'+str(pid))]);put('project_membership_lookup',[ref('user')]);put('members.get',k={'user':ref('user')});put('members.filter',k={'is_admin':True,'user__is_active':True});put('members.exclude',k={'user':ref('user')});put('members.count')
        put('header',[ref('request')]);put('raw_token',['owned-header']);put('validate_token',['owned-normal-token']);put('user_lookup',[ref('token')]);put('csrf',[ref('request')])
        if c.get('batch_category')=='taiga_header' and q=='JWTAuthentication.authenticate':
            header=i.get('header','Other owned-normal-token' if i.get('no_raw') else 'Bearer owned-normal-token')
            put('raw_token',[{'bytes':header.encode().hex()}]);parts=header.split();put('validate_token',[{'bytes':parts[1].encode().hex()}] if len(parts)==2 else [])
        header=i.get('header','').split();parts=('', '')
        if len(header)==2 and header[0].lower()=='basic':
            try:
                s=base64.b64decode(header[1]).decode().partition(':');parts=(s[0],s[2])
            except (ValueError,UnicodeError):pass
        if q.endswith('authenticate_credentials'):parts=('owned-user','owned-password')
        put('credential_lookup',k={'username':parts[0],'password':parts[1]})
    elif repo=='baserow/baserow':
        put('jwt_base',[ref('request')]);put('profile_token_valid',[ref('token')]);put('session_setup',[ref('user'),ref('request')]);put('impersonation_setup',[ref('user'),ref('token')]);put('span_context',[ref('user'),ref('request')]);put('sentry_setup',[ref('user')])
        put('header',[ref('request')]);put('raw_token',['owned-header']);put('source_token',['owned-normal-token'])
        put('service_lookup',[ref('user'),SOURCE_UID],{'for_authentication':True});put('handler_lookup',[SOURCE_UID]);put('source_user',[ref('user_source')],{'user_id':1})
        put('source_permission',[ref('user'),c.get('source_constants',{}).get('AuthenticateUserSourceOperationType.type',SOURCE_OPERATION)],{'workspace':ref('workspace'),'context':ref('user_source')})
        put('source:BuilderPreviewAuthentication.get_builder_id',[ref('request')]);put('preview_actor',[i.get('preview_cookie')])
        put('session_decode',[ref('request')]);put('select_profile',['profile']);put('session_user',k={'id':1});put('revocation_lookup',['normal-session' if i.get('session_hash',True) else 'normal-token']);put('clock')
    elif repo=='horilla/horilla-hr':
        put('jwt',[ref('request')]);put('tenant.filter',k={'employee_id__employee_user_id':1});put('tenant.values_list',['company_id'],{'flat':True});put('tenant.first');put('set_company',[i.get('company')])
        put('candidate.filter',k={'email__iexact':(i.get('username',' One@Example.invalid ') or '').strip().lower()})
        for n in range(len(i.get('password_matches',[False,True]))):put('check_password'+str(n),[i.get('password','owned-password')])
    elif repo=='argilla-io/argilla':
        claims=dict(i['decoded_claims']) if 'decoded_claims' in i else dict(id='u1',**({'scope':['read','write']} if i.get('with_scope',True) else {}))
        put('scheme',[ref('request')]);put('decode',['owned-normal-token']);put('userinfo_construct',[claims]);put('userinfo_pop',['scope',[]])
    elif repo=='langgenius/dify':
        raw=i.get('token',{'known':'dfoa_owned-normal',None:'owned-normal','unknown':'sk-owned-normal'}[i.get('token_type','known')])
        put('classify_token',[raw]);put('token_fingerprint',[raw]);put('digest_bytes',[{'bytes':raw.encode('utf-8').hex()}]);put('digest_hex')
        token=hashlib.sha256(raw.encode('utf-8')).hexdigest();put('rate_limit',[token]);put('resolve',[token])
    elif repo=='open-webui/open-webui':
        token=i.get('bearer_token','bearer-normal') if i.get('bearer',True) else i.get('cookies',{}).get('token')
        if token is None and i.get('middleware_token'):token='middleware-normal'
        uid='u2' if token=='cookie-normal' else 'u1'
        claims=i.get('claims',{'id':uid})
        put('decode',[token]);put('api_user',['sk-owned-normal' if q=='get_current_user_by_api_key' else token]);put('jwt_user',[claims.get('id',uid)]);put('token_current',[claims,ref('redis') if i.get('redis_enabled') else None]);put('active_update',[claims.get('id',uid)])
        permissions=i.get('default_permissions',{'features':{'api_keys':i.get('api_permission',True)}}) if c.get('batch_expansion') else {'configured':True}
        put('api_permission',['u1','features.api_keys',permissions]);put('group_rows',['u1'],{'db':None,'include_inherited':True});put('config_read',['auth.enable_api_keys','user.permissions','auth.api_key.endpoint_restrictions','auth.api_key.allowed_endpoints']);put('active_count');put('model_usage');put('auth_row',[claims.get('id','')]);put('mfa_config')
    return r
def check_handoffs(c,inputs,events):
    specs=obligations(c,inputs);seen={};violations=[]
    for e in events:
        name=e['call']
        if name in ('cache.get','cache.set'):
            seen[name]=seen.get(name,0)+1
            key=e.get('args',[None])[0]
            group=isinstance(key,str) and key.startswith('GROUP_CACHE_')
            correct='GROUP_CACHE_1_1' if group else 'recipe_share_10_'+str(inputs.get('share'))
            if name=='cache.get':wanted={'args':[correct] if group else [correct,False],'kwargs':{'default':None} if group else {}}
            else:
                groups=inputs.get('cached_groups') or (inputs.get('groups',['user']) if inputs.get('active_spaces',1)==1 else [])
                wanted={'args':[correct,groups if group else True],'kwargs':{'timeout':30 if group else 3}}
            actual={'args':e.get('args',[]),'kwargs':e.get('kwargs',{})}
            if not typed_equal(actual,wanted):violations.append({'call':name,'actual':actual,'expected':wanted})
            continue
        if name not in specs:continue
        wanted=specs[name];index=seen.get(name,0);seen[name]=index+1
        if type(wanted) is list:wanted=wanted[index] if index<len(wanted) else None
        actual={'args':e.get('args',[]),'kwargs':e.get('kwargs',{})}
        if wanted is None or not typed_equal(actual,wanted):violations.append({'call':name,'index':index,'actual':actual,'expected':wanted})
    return violations,sorted(seen)
