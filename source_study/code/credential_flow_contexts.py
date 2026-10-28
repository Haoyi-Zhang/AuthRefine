"""Normal owned credentials only;no provider/account key is read or used."""
import hashlib
import hmac
import itertools
import json
import uuid

SECRET='owned-authrefine-normal-context-only-not-a-service-secret'


def token(profile,project,kind):
    if profile=='plain':return (f'Owned{project}{kind}'+('AbCdEf0123456789'*3))[:32]
    # Two actual project candidates share a lookup prefix;only one full MAC
    # agrees. No attack,randomness-quality or deployment claim is made.
    prefix='hcw_' if kind=='w' else 'hcr_'
    secret=('SameLead' if project in (1,2) else 'ThirdLed')+f'{project}{kind}'+('Aa012Bb345Cc678Dd901Ee234')
    return prefix+secret[:28]


def stored(key):
    return key[4:12]+'.'+hmac.new(SECRET.encode(),key.encode(),hashlib.sha256).hexdigest()


def check_code(project):return str(uuid.UUID(int=project))


def fixtures():
    rows=[]
    for profile,mode,keychoice,carrier,method,version in itertools.product(
            ('plain','stored_mac'),('read','write'),('1w','1r','2w','2r','3w','3r','missing'),
            ('header','body','header-first'),('GET','POST'),(1,2,3)):
        key='' if keychoice=='missing' else token(profile,int(keychoice[0]),keychoice[1])
        alternate=token(profile,2 if keychoice.startswith('1') else 1,'w')
        headers={} if carrier=='body' else {'X-Api-Key':key}
        body={} if carrier=='header' else {'api_key':alternate if carrier=='header-first' else key}
        for target in ((1,2,3,99) if mode=='read' else (None,)):
            case=dict(id=f'{profile}-{mode}-{keychoice}-{carrier}-{method}-v{version}-{target}',profile=profile,mode=mode,
                keychoice=keychoice,carrier=carrier,method=method,version=version,target=target,
                request=dict(method=method,headers=headers,body_hex=json.dumps(body,separators=(',',':')).encode().hex(),
                    path_info=f'/api/v{version}/checks/'),code=None if target is None else check_code(target))
            rows.append(case)
    if len(rows)!=1260 or len({r['id'] for r in rows})!=1260:raise ValueError('complete owned normal context domain differs')
    return rows


def expected(case):
    request=case['request'];header=request['headers'].get('X-Api-Key')
    if 'X-Api-Key' in request['headers']:key=header
    elif case['mode']=='write' and case['method']=='POST':key=json.loads(bytes.fromhex(request['body_hex'])).get('api_key','')
    else:key=''
    matched=[(p,k) for p,k in itertools.product((1,2,3),('w','r')) if token(case['profile'],p,k)==key]
    if not matched or (case['mode']=='write' and matched[0][1]!='w'):
        return dict(status=401,project=None,readonly=None,version=None,consumer=None)
    project,kind=matched[0];readonly=kind=='r' if case['mode']=='read' else False
    state=dict(project=project,readonly=readonly,version=case['version'])
    if case['mode']=='write':return dict(status=200,**state,consumer='authorization_boundary_only')
    status=404 if case['target']==99 else 200 if case['target']==project else 403
    return dict(status=status,**state,consumer='serializer_boundary' if status==200 else None)
