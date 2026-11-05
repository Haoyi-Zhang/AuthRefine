"""Source-read reference equations, independent of the source interpreter.

These specify finite normal entry contexts, not intended whole-system policies.
All expected observations are constructed here before interpreter execution.
"""
from itertools import product

SAFE={'GET','HEAD','OPTIONS'}
def ref(n):return {'ref':n}
def ret(v):return {'kind':'return','value':v}
def error(n,status=None,code=None):
    d={'kind':'error','name':n}
    if status is not None:d['status']=status
    if code is not None:d['code']=code
    return d
PAIR=ret([ref('user'),ref('token')]);SESSION=ret([ref('user'),None])
ABSTRACT={'PermissionComponent.check_permissions','BaseAuthentication.authenticate'}

def recipe_reference(q,i):
    auth=i.get('authenticated',True);safe=i.get('method','GET') in SAFE
    same=i.get('same_space',True);own=i.get('owner',True) or i.get('orphan',False)
    group_values=i.get('cached_groups') or (i.get('groups',['user']) if i.get('active_spaces',1)==1 else [])
    def group(role):return auth and bool(set(group_values)&({'guest','user','admin'} if role=='guest' else {'user','admin'} if role=='user' else {'admin'}))
    owner=q.split('.')[0];obj=q.endswith('has_object_permission');share=i.get('share')
    state={};calls={};out=None
    def shared():
        valid=bool(i.get('share_cached') or (share=='share-normal' and i.get('share_exists',True) and
            (not(0<i.get('sharing_limit',3)<i.get('share_count',1)) or i.get('unlimited',False))))
        if valid and not i.get('share_cached'):
            state['share_count']=i.get('share_count',1)+1
            state['cache:recipe_share_10_share-normal']=True
            calls['share.save']=1
        else:calls['share.save']=0
        return valid
    if owner in ('CustomIsOwner','CustomIsOwnerReadOnly','CustomIsOwnerDestroyOnly'):
        out=auth and (own if obj else True)
        if owner=='CustomIsOwnerReadOnly':out=out and safe
        if owner=='CustomIsOwnerDestroyOnly':out=out and i.get('method','GET')=='DELETE'
    elif owner=='CustomIsSpaceOwner':out=auth and (i.get('space_owner',True) if obj else True)
    elif owner=='CustomIsShared':out=auth and (i.get('shared',False) if obj else True)
    elif owner=='CustomIsHousehold':
        if obj and auth and i.get('orphan'):return error('AttributeError'),state,calls,[]
        out=auth and (i.get('household',False) if obj else True)
    elif owner in ('CustomIsGuest','CustomIsUser','CustomIsAdmin','CustomUserPermission'):
        out=group({'CustomIsUser':'user','CustomIsAdmin':'admin'}.get(owner,'guest'))
        if owner=='CustomUserPermission' and obj:out=(safe and i.get('has_pk',True) and out and same) or i.get('self_object',False)
    elif owner=='CustomIsShare':out=shared() if obj and share else False if obj else safe and i.get('has_pk',True)
    elif owner=='CustomRecipePermission':
        if not obj:out=(group('guest') and safe or group('user')) or (share and safe and i.get('has_pk',True))
        elif share and shared():out=True
        elif share and not same:return error('Http404'),state,calls,[]
        elif i.get('private',False):out=(i.get('owner',True) or i.get('shared',False)) and same
        else:out=(group('guest') and safe or group('user')) and same
    elif owner=='CustomAiProviderPermission':
        out=(group('user') and safe) or group('admin') or i.get('superuser',False)
        if obj:out=(i.get('global_provider',False) and i.get('superuser',False)) or (not i.get('global_provider',False) and same and (group('admin') or group('user') and safe))
    elif owner=='CustomTokenHasScope':out=i.get('scope_ok',True) if i.get('oauth') else auth;calls['oauth_scope']=int(bool(i.get('oauth')))
    elif owner=='CustomTokenHasReadWriteScope':out=i.get('scope_ok',True) if i.get('oauth') else True;calls['oauth_scope']=int(bool(i.get('oauth')))
    elif owner=='IsReadOnlyDRF':out=safe
    elif owner=='IsCreateDRF':out=i.get('method','GET')=='POST'
    else:raise ValueError(q)
    return ret(out),state,calls,[]

def taiga_reference(q,i):
    c={};order=[]
    if q=='PermissionComponent.check_permissions':out=ret(None)
    elif q=='BaseAuthentication.authenticate':out=error('NotImplementedError')
    elif q=='CanRetrieveUser.check_permissions':out=ret(True if not i.get('private_profiles') else None if i.get('absent_object') else i.get('authenticated',True))
    elif q in ('Not.check_permissions','Or.check_permissions','And.check_permissions'):
        values=i.get('components',[])
        n=1 if q.startswith('Not') else next((j+1 for j,v in enumerate(values) if v==(q.startswith('Or'))),len(values))
        c.update({'component'+str(j):int(j<n) for j in range(len(values))})
        out=ret(not values[0] if q.startswith('Not') else any(values) if q.startswith('Or') else all(values))
    elif q=='HasProjectPerm.check_permissions':out=ret(i.get('permission',False));c['permission']=1
    elif q in ('IsProjectAdmin.check_permissions','IsWebhookProjectAdmin.check_permissions'):out=ret(i.get('admin',False));c['admin']=1
    elif q=='IsObjectOwner.check_permissions':out=ret(not i.get('absent_owner',False) and i.get('owner',True))
    elif q=='CanUseToken.check_permissions':out=ret(not i.get('absent_object',False) and i.get('owner',True))
    elif q=='CanLeaveProject.check_permissions':
        reaches=not i.get('absent_object') and i.get('authenticated',True);c['can_leave']=int(reaches)
        out=ret(False) if not reaches or i.get('membership_missing') else ret(True) if i.get('can_leave',True) else error('PermissionDenied')
    elif q=='CommentAndOrUpdatePerm.check_permissions':
        d=i.get('data',{});keys=set(d)-{'version'}
        out=ret(False if i.get('absent_object') else keys=={'comment'} and i.get('comment_allowed',False) or i.get('update_allowed',False))
        c['permission']=0 if i.get('absent_object') else 1+int(keys=={'comment'} and not i.get('comment_allowed'))
        c['project.get']=int(not i.get('absent_object') and bool(d.get('project')) and d['project']!=1)
    elif q=='JWTAuthentication.authenticate':
        c['validate_token']=int(not(i.get('no_header') or i.get('no_raw')))
        out=ret(None) if not c['validate_token'] else error('InvalidToken') if i.get('invalid_token') else PAIR
    elif q=='BasicAuthentication.authenticate':
        parts=i.get('header','').split()
        out=ret(None) if not parts or parts[0].lower()!='basic' else error('AuthenticationFailed') if len(parts)!=2 or i.get('invalid_encoding') or i.get('missing_user') or not i.get('active',True) else SESSION
    elif q=='BasicAuthentication.authenticate_credentials':out=error('AuthenticationFailed') if i.get('missing_user') or not i.get('active',True) else SESSION
    elif q=='SessionAuthentication.authenticate':
        c['csrf']=int(i.get('active',True));out=ret(None) if not i.get('active',True) else error('PermissionDenied') if i.get('csrf_denied') else SESSION
    else:raise ValueError(q)
    return out,{},c,order

def other_reference(repo,q,i):
    state={};c={};order=[]
    if repo=='horilla/horilla-hr':
        if q=='SwaggerAuthentication.authenticate':
            bearer=i.get('header','').startswith('Bearer ');c['jwt']=int(bearer)
            out=ret(None) if bearer and i.get('jwt_none') and not i.get('jwt_error') else PAIR if bearer and not i.get('jwt_error') else SESSION if i.get('authenticated',True) else ret(None)
        elif q=='RejectBasicAuthentication.authenticate':out=error('AuthenticationFailed') if i.get('header','').startswith('Basic ') else ret(None)
        elif q=='CandidateAuthenticationBackend.authenticate':
            values=i.get('password_matches',[False,True]);j=next((n for n,v in enumerate(values) if v),None)
            reaches=bool((i.get('username',' One@Example.invalid ') or '').strip() and i.get('password','owned-password'))
            out=ret(ref('candidate'+str(j))) if reaches and j is not None else ret(None)
            for n in range(len(values)):c['check_password'+str(n)]=int(reaches and (j is None or n<=j))
            c['candidate.filter']=int(reaches)
        elif q=='TenantScopedJWTAuthentication.authenticate':
            out=error('InvalidToken') if i.get('jwt_error') else ret(None) if i.get('jwt_none') else error('PermissionDenied') if i.get('company') is None and not i.get('superuser') else PAIR
            state['selected_company']=None if i.get('jwt_none') or i.get('jwt_error') else i.get('company')
            c['set_company']=int(not(i.get('jwt_none') or i.get('jwt_error')) and i.get('company') is not None)
        else:raise ValueError(q)
    elif repo=='argilla-io/argilla':
        out=ret(None) if i.get('no_credentials') else error('JWTDecodeError') if i.get('invalid_token') else ret([{'record':'AuthCredentials','fields':{'scopes':['read','write'] if i.get('with_scope',True) else []}},{'id':'u1'}])
        c['decode']=int(not i.get('no_credentials'))
    elif repo=='langgenius/dify':
        valid=i.get('token_type','known')=='known';c['rate_limit']=int(valid);c['resolve']=int(valid and not i.get('rate_limited'))
        out=error('InvalidBearerError') if not valid else error('RateLimitExceeded') if i.get('rate_limited') else error('InvalidBearerError') if i.get('missing_row') else ret({'record':'AuthContext','fields':dict(token_type='known',subject_email='one@example.invalid',subject_issuer='owned-issuer',account_id='a1',client_id='c1',token_id='t1',expires_at=2000)})
        order=['classify_token','token_fingerprint','rate_limit','resolve'] if valid and not i.get('rate_limited') else []
    elif repo=='baserow/baserow':
        if q=='JSONWebTokenAuthentication.authenticate':
            out=error('AuthenticationFailed',code='ERROR_INVALID_ACCESS_TOKEN') if i.get('invalid_token') or not i.get('profile_valid',True) and not i.get('no_credentials') else ret(None) if i.get('no_credentials') else error('DeactivatedUserException') if not i.get('active',True) else PAIR
            order=['session_setup','impersonation_setup','span_context','span.enter','sentry_setup','span.exit'] if out==PAIR else []
            c.update({n:int(out==PAIR) for n in ('session_setup','impersonation_setup','sentry_setup')})
        elif q=='UserSourceJSONWebTokenAuthentication.authenticate':
            early=i.get('no_header') or i.get('no_raw') or i.get('invalid_token') or i.get('missing_claim')
            codes={'UserSourceDoesNotExist':'user_source_does_not_exist','PermissionDenied':'user_source_not_allowed','UserNotInWorkspace':'user_source_not_allowed','ApplicationDoesNotExist':'application_not_found'}
            if early:out=ret(None)
            elif i.get('lookup_error'):out=error('AuthenticationFailed',code=codes[i['lookup_error']])
            elif i.get('missing_user'):out=error('AuthenticationFailed',code='user_not_found')
            elif i.get('permission_error') and not i.get('service_header'):out=error('AuthenticationFailed',code=codes[i['permission_error']])
            else:out=PAIR
            c['service_lookup']=int(not early and bool(i.get('service_header')));c['handler_lookup']=int(not early and not i.get('service_header'))
            c['source_permission']=int(not early and not i.get('lookup_error') and not i.get('missing_user') and not i.get('service_header'))
        elif q=='BuilderPreviewAuthentication.authenticate':
            out=ret([ref('actor'),None]) if i.get('preview_cookie') and not i.get('invalid_actor') and i.get('actor_builder',10)==10 else error('APIException',401,'ERROR_BUILDER_PREVIEW_SESSION_INVALID')
            c['preview_actor']=int(bool(i.get('preview_cookie')))
        elif q=='AuthenticateFromUserSessionAuthentication.authenticate':
            out=error('AuthenticationFailed') if i.get('no_session') or i.get('missing_user') or not i.get('active',True) or i.get('revoked') or bool(i.get('expires_at',2000)) and i.get('expires_at',2000)<1000 else ret([ref('user'),ref('request')])
            c['revocation_lookup']=int(not i.get('no_session') and not i.get('missing_user') and i.get('active',True))
        else:raise ValueError(q)
    elif repo=='open-webui/open-webui':
        api=q=='get_current_user_by_api_key'
        if q=='get_current_usage':
            reaches=i.get('public_usage') or i.get('role','user')=='admin'
            out=error('HTTPException',403) if not reaches else error('HTTPException',500) if i.get('usage_error') else ret({'model_ids':['owned-model'],'user_count':4})
            c['active_count']=int(bool(reaches));return out,state,c,order
        token=i.get('bearer_token','bearer-normal') if i.get('bearer',True) else i.get('cookies',{}).get('token')
        if token is None and i.get('middleware_token'):token='middleware-normal'
        if not api:api=token is not None and token.startswith('sk-')
        if api:
            path=i.get('path','/api/items');allowed=[p.strip() for p in i.get('allowed_paths','/api/items').split(',') if p.strip()]
            permitted=any(path==p or path.startswith(p+'/') for p in allowed)
            code=401 if i.get('missing_user') else 403 if not i.get('enable_api_keys',True) or i.get('role','user')!='admin' and not i.get('api_permission',True) or i.get('restricted') and not permitted else None
            out=error('HTTPException',code) if code else ret(ref('user'));state['active_updates']=[] if code else ['u1'];state['scheduled_active']=[]
            if q=='get_current_user' and not code:state['request_state']={'user':ref('user'),'auth_type':'api_key'}
        elif token is None:out=error('HTTPException',401)
        else:
            identity='other' if token=='cookie-normal' else 'user';uid='u2' if identity=='other' else 'u1'
            trusted=i.get('headers',{}).get(i.get('trusted_header',''),'').lower()
            email='two@example.invalid' if identity=='other' else 'one@example.invalid'
            denied=i.get('invalid_token') or i.get('no_claim') or not i.get('token_current',True) or i.get('missing_user') or (bool(i.get('trusted_header')) and bool(trusted) and trusted!=email)
            out=error('HTTPException',401) if denied else ret(ref(identity));state['active_updates']=[];state['scheduled_active']=[] if denied else [uid]
            if denied:state['deleted_cookies']=[k for k in ('token','oauth_id_token','oauth_session_id') if i.get('cookies',{}).get(k)]
            else:state['request_state']={'user':ref(identity),'auth_type':'jwt','claims':{'id':uid}}
    else:raise ValueError(repo)
    return out,state,c,order

def reference(contract,inputs):
    repo=contract['repository'];q=contract['function']
    return recipe_reference(q,inputs) if repo=='TandoorRecipes/recipes' else taiga_reference(q,inputs) if repo=='taigaio/taiga-back' else other_reference(repo,q,inputs)

def cases(contract):
    repo=contract['repository'];q=contract['function'];out=[{}]
    if repo=='TandoorRecipes/recipes':
        out=[dict(authenticated=a,method=m,owner=o) for a,m,o in product((False,True),('GET','POST','DELETE'),(False,True))]
        out += [dict(groups=[g],method=m,**kw) for g,m,kw in product(('guest','user','admin','outsider'),('GET','POST'),({}, {'active_spaces':2},{'cached_groups':['admin']}))]
        out += [dict(shared=True,owner=False),dict(household=True),dict(space_owner=False),dict(orphan=True,owner=False),dict(self_object=True,method='POST'),dict(has_pk=False)]
        if q.startswith(('CustomIsShare.','CustomRecipePermission.')):
            out += [dict(share=s,share_count=count,private=private,same_space=same,owner=False,groups=[],repeat=2) for s,count,private,same in product(('share-normal','missing'),(1,4),(False,True),(False,True))]
            out += [dict(share='share-normal',share_cached=True,share_count=9),dict(share='share-normal',share_count=9,unlimited=True)]
        if q.startswith('CustomAiProviderPermission.'):
            out += [dict(global_provider=glob,superuser=sup,same_space=same,groups=[]) for glob,sup,same in product((False,True),repeat=3)]
        if q.startswith('CustomToken'):
            out += [dict(oauth=o,authenticated=a,scope_ok=s) for o,a,s in product((False,True),repeat=3)]
    elif repo=='taigaio/taiga-back':
        if q in ABSTRACT:out=[{}]
        elif q.startswith(('Not.','Or.','And.')):out=[dict(components=list(v)) for v in ((True,),(False,),(True,False),(False,True),(False,False),(True,True))]+([] if q.startswith('Not.') else [dict(components=[])])
        elif q=='CommentAndOrUpdatePerm.check_permissions':out=[dict(data=d,comment_allowed=c,update_allowed=u) for d,c,u in product(({}, {'comment':'normal'}, {'comment':'normal','version':1}, {'description':'normal'}, {'project':2,'comment':'normal'}),(False,True),(False,True))]+[dict(absent_object=True)]
        elif q=='CanRetrieveUser.check_permissions':out=[dict(private_profiles=p,authenticated=a,absent_object=o) for p,a,o in product((False,True),repeat=3)]
        elif q=='CanLeaveProject.check_permissions':out=[{},dict(can_leave=False),dict(membership_missing=True),dict(absent_object=True),dict(authenticated=False)]
        elif q=='JWTAuthentication.authenticate':out=[{},dict(no_header=True),dict(no_raw=True),dict(invalid_token=True)]
        elif q=='BasicAuthentication.authenticate':out=[dict(header=h,**k) for h,k in product(('', 'Bearer normal','Basic','Basic a b','Basic b3duZWQtdXNlcjpvd25lZC1wYXNzd29yZA==','Basic /w=='),({}, {'missing_user':True},{'active':False}))];out=[dict(v,invalid_encoding=True) if v['header']=='Basic /w==' else v for v in out]
        elif q=='BasicAuthentication.authenticate_credentials':out=[{},dict(missing_user=True),dict(active=False)]
        elif q=='SessionAuthentication.authenticate':out=[{},dict(active=False),dict(csrf_denied=True)]
        else:out=[{},dict(permission=True,admin=True),dict(owner=False),dict(absent_owner=True),dict(absent_object=True)] if q=='CanUseToken.check_permissions' else [{},dict(permission=True,admin=True),dict(owner=False),dict(absent_owner=True)]
    elif repo=='baserow/baserow':
        if q=='JSONWebTokenAuthentication.authenticate':out=[{},dict(no_credentials=True),dict(invalid_token=True),dict(profile_valid=False),dict(active=False)]
        elif q=='UserSourceJSONWebTokenAuthentication.authenticate':out=[{},dict(service_header=True),dict(no_header=True),dict(no_raw=True),dict(invalid_token=True),dict(missing_claim=True),dict(missing_user=True)]+[dict(lookup_error=e,service_header=h) for e,h in product(('UserSourceDoesNotExist','PermissionDenied','UserNotInWorkspace','ApplicationDoesNotExist'),(False,True))]+[dict(permission_error=e) for e in ('PermissionDenied','UserNotInWorkspace','ApplicationDoesNotExist')]
        elif q=='BuilderPreviewAuthentication.authenticate':out=[{},dict(preview_cookie='owned-preview'),dict(preview_cookie='owned-preview',invalid_actor=True),dict(preview_cookie='owned-preview',actor_builder=11)]
        else:out=[{},dict(no_session=True),dict(missing_user=True),dict(active=False),dict(revoked=True),dict(expires_at=999),dict(expires_at=1000),dict(expires_at=0),dict(session_hash=False)]
    elif repo=='horilla/horilla-hr':
        if q=='SwaggerAuthentication.authenticate':out=[dict(header=h,**k) for h,k in product(('', 'Bearer owned-normal'),({}, {'jwt_none':True},{'jwt_error':True},{'jwt_error':True,'authenticated':False},{'authenticated':False}))]
        elif q=='RejectBasicAuthentication.authenticate':out=[dict(header=h) for h in ('','Basic normal','Bearer normal')]
        elif q=='CandidateAuthenticationBackend.authenticate':out=[dict(password_matches=list(v)) for v in ((),(False,),(True,),(False,True),(True,True))]+[dict(username=''),dict(password='')]
        else:out=[dict(company=c,**k) for c,k in product((None,7),({}, {'superuser':True},{'jwt_none':True},{'jwt_error':True}))]
    elif repo=='argilla-io/argilla':out=[{},dict(no_credentials=True),dict(invalid_token=True),dict(with_scope=False)]
    elif repo=='langgenius/dify':out=[{},dict(token_type=None),dict(token_type='unknown'),dict(rate_limited=True),dict(missing_row=True)]
    elif repo=='open-webui/open-webui':
        if q=='get_current_usage':out=[dict(public_usage=p,role=r,usage_error=e) for p,r,e in product((False,True),('user','admin'),(False,True))]
        else:
            out=[{},dict(missing_user=True),dict(enable_api_keys=False),dict(api_permission=False),dict(role='admin',api_permission=False),dict(restricted=True,path='/api/items/1'),dict(restricted=True,path='/api/other'),dict(restricted=True,allowed_paths='  /api/other, /api/items  ')]
            if q=='get_current_user':out += [dict(bearer=False),dict(bearer=False,middleware_token=True),dict(bearer=False,cookies={'token':'cookie-normal'}),dict(bearer_token='sk-owned-normal'),dict(invalid_token=True,cookies={'token':'cookie-normal','oauth_id_token':'owned-id','oauth_session_id':'owned-session'}),dict(no_claim=True),dict(token_current=False),dict(trusted_header='x-trusted',headers={'x-trusted':'OTHER@example.invalid'}),dict(trusted_header='x-trusted',headers={'x-trusted':'ONE@example.invalid'})]
    # Remove exact duplicate contexts, not outcomes. Stable order is part of freeze.
    import json
    unique={json.dumps(i,sort_keys=True):i for i in out}
    return list(unique.values())

SCOPE={
 'TandoorRecipes/recipes':'Fixed safe methods GET/HEAD/OPTIONS; persisted positive object keys; explicit group rows, cache state, ownership and sharing tables. Selected same-module helpers and fixed superclass bodies are interpreted. OAuth scope backend remains an explicit dependency result. No view dispatch or framework ORM execution.',
 'taigaio/taiga-back':'Declared component list and permission/admin service results; exact principal/object handoff and source short circuit. Authentication primitives are explicit decoded-token, credential-lookup and CSRF inputs. No cryptographic validation, route discovery or Django dispatch.',
 'baserow/baserow':'Declared JWT/session/source providers and exact user/token/source/context forwarding. Preview exception registry has no overrides and builder ID is supplied as 10. Telemetry callbacks are owned serial protocols. Enterprise body is checked locally only; no restricted enterprise source is redistributed.',
 'horilla/horilla-hr':'Declared JWT result, resolved tenant and candidate password outcomes. Tenant selection has observable owned state. No real candidate credentials, tenant queries or signing implementation is executed.',
 'open-webui/open-webui':'Telemetry disabled; explicit decoded claims, revocation lookup, user/config providers and trust-header configuration. Source writes request state; JWT activity is scheduled, API-key activity awaited. No network, Redis, production database or telemetry import is executed.',
 'argilla-io/argilla':'Supplied bearer extraction and decoded claim mapping. Observe scope removal and user-info handoff, not JWT cryptography.',
 'langgenius/dify':'Supplied token classification and resolver row; observe limiter-before-resolver order and exact context fields. Dummy owned token only; no real token, account access or rate-limit service.',
}
