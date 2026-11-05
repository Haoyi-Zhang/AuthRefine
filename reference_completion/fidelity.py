"""Fixed dependency bodies and raw context boundaries,without framework execution."""
import ast,hashlib,re
if __package__:
    from .interpreter import Capability,DataRecord,ErrorType,SliceFault,AdmissionError,source_syntax
    from .expansions import timepoint
else:
    from interpreter import Capability,DataRecord,ErrorType,SliceFault,AdmissionError,source_syntax
    from expansions import timepoint
def record(kind,**fields):return DataRecord(kind,fields)
def validate_dependency(c):
    d=c['oauth_dependency'];req=d['requirement'];lic=d['license']
    if req['repository']!=c['repository'] or req['snapshot']!=c['snapshot'] or hashlib.sha256(req['text'].encode()).hexdigest()!=req['sha256']:raise ValueError('requesting requirement differs')
    if re.findall(r'^django-oauth-toolkit==([^\s]+)$',req['text'],re.M)!=['3.4.1']:raise ValueError('dependency is not the exact required release')
    if d['snapshot']!='db6c4f51a79fd43693de35bcc876168596074fb0' or d['repository']!='django-oauth/django-oauth-toolkit' or hashlib.sha256(lic['text'].encode()).hexdigest()!=lic['sha256']:raise ValueError('dependency release/license differs')
    for h in c['fidelity_helpers']:
        r=c['helper_sources'][h]
        if r['repository']!=d['repository'] or r['snapshot']!=d['snapshot']:raise ValueError('dependency helper provenance differs')
    source=c['helper_sources']['AbstractAccessToken.is_valid']['text'];tree=source_syntax(source)
    classes=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='AccessToken']
    if len(classes)!=1 or [ast.unparse(n) for n in classes[0].bases]!=['AbstractAccessToken']:raise ValueError('token model inheritance differs')
    if any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in ('is_valid','is_expired','allow_scopes') for n in classes[0].body):raise ValueError('token model overrides selected inherited behavior')
def install(w,c,helpers,b,args):
    if c.get('oauth_dependency'):
        validate_dependency(c);i=w.i;receiver=args[0];w.permission_receiver=receiver;receiver.writable=frozenset({'message'})
        if not i.get('required_scopes_missing'):
            scopes=i.get('required_scopes',['owned'])
            if type(scopes)is not list or len(scopes)>32 or any(type(s)is not str or len(s)>256 for s in scopes):raise AdmissionError('required scopes need bounded strings')
            w.view.fields['required_scopes']=list(scopes)
        if i.get('oauth'):
            scope=i.get('oauth_scope','owned read write' if i.get('scope_ok',True) else '')
            if type(scope)is not str or len(scope)>4096:raise AdmissionError('token scope outside declared string domain')
            t=w.request.fields['auth'];stamp=i.get('oauth_expires',2000);t.fields.update(scope=scope,expires=None if stamp is None else timepoint(stamp))
            for name in ('is_valid','is_expired','allow_scopes'):t.fields[name]=Capability('source token '+name,lambda *a,_n=name:w.source('AbstractAccessToken.'+_n,[t,*a]))
        target='TokenHasReadWriteScope.get_scopes' if c['function'].startswith('CustomTokenHasReadWriteScope.') else 'TokenHasScope.get_scopes'
        receiver.fields['get_scopes']=Capability('source required scopes',lambda *a:w.source(target,[receiver,*a]))
        def parent():
            owner,_=w.machine.frames[-1]
            if owner=='TokenHasReadWriteScope':return record('ScopeBase',get_scopes=Capability('source inherited scopes',lambda *a:w.source('TokenHasScope.get_scopes',[receiver,*a])))
            if owner not in ('CustomTokenHasScope','CustomTokenHasReadWriteScope'):raise AdmissionError('scope parent outside fixed hierarchy')
            return record('ScopeBase',has_permission=w.cap('oauth_scope',lambda *a:w.source('TokenHasScope.has_permission',[receiver,*a])))
        b.update(super=Capability('fixed scope inheritance',parent),ImproperlyConfigured=ErrorType('ImproperlyConfigured'),PermissionDenied=record('PermissionDenied',default_detail='You do not have permission to perform this action.'),
            oauth2_settings=record('OAuthSettings',READ_SCOPE=i.get('read_scope','read'),WRITE_SCOPE=i.get('write_scope','write'),ERROR_RESPONSE_WITH_SCOPES=i.get('scope_error_details',False)),timezone=record('UTCClock',now=Capability('declared UTC clock',lambda:timepoint(i.get('oauth_now',1000)))),
            log=record('Logger',debug=w.cap('scope_log',lambda *a:None),warning=w.cap('scope_warning',lambda *a:None)))
    if c.get('source_auth_lookup'):
        i=w.i;w.auth_record.fields['active']=i.get('auth_active',True)
        if not i.get('auth_mfa_present',True):w.auth_record.fields['mfa']=None
        def lookup(uid):
            if i.get('auth_lookup_error'):
                if i['auth_lookup_error'] not in ('SQLAlchemyError','ValidationError'):raise AdmissionError('unbound authentication lookup error')
                raise SliceFault(i['auth_lookup_error'])
            return w.auth_record if i.get('auth_exists',True) and uid in ('u1','u2') else None
        b.update(Auths=record('AuthRows',get_auth_by_id=w.cap('auth_query',lookup,True)),SQLAlchemyError=ErrorType('SQLAlchemyError'),ValidationError=ErrorType('ValidationError'))
        imports=b['_declared_imports'];key=next(iter(imports));imports[key]['get_auth']=w.cap('auth_row',lambda uid:w.source('get_auth',[uid]),True)
    return list(dict.fromkeys([*helpers,*c.get('fidelity_helpers',[])])),b,args
