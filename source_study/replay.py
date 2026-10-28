"""Portable offline credential-chain replay on owned records only.

No original application modules/services/tests execute. Wheel acquisition is a
separate opt-in command using frozen primary-host identities and no build hooks.
"""
import argparse
import ast
import hashlib
import gzip
import json
import os
from pathlib import Path,PurePosixPath
import subprocess
import sys
import urllib.request
import zipfile
from io import BytesIO

ROOT=Path(__file__).resolve().parent


def data_bytes(p):
    p=Path(p)
    return p.read_bytes() if p.exists() else gzip.decompress(p.with_name(p.name+'.gz').read_bytes())
def read(p):return json.loads(data_bytes(p))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def source_check():
    sys.path.insert(0,str(ROOT/'code'))
    from credential_flow_ir import compile_function
    p=read(ROOT/'data/credential-input.json');binding=p['binding']
    for name in ('credential_flow_ir.py','credential_flow_contexts.py','credential_flow_native.py'):
        path=ROOT/'code'/name;raw=path.read_bytes()
        if name=='credential_flow_ir.py':
            old=b'Development credential-flow interpreter;not a delivery or full-app verifier.'
            current=b'Bounded credential-flow interpreter;not a full-app verifier.'
            if raw.count(current)!=1:raise ValueError('packaged interpreter header differs')
            raw=raw.replace(current,old,1)
        if hashlib.sha256(raw).hexdigest()!=p['code'][name]:raise ValueError('measured closed-interpreter implementation changed')
    for path,h in binding['source_bindings'].items():
        if sha(ROOT/'source/healthchecks'/path)!=h:raise ValueError('original selected source bytes differ')
    trees={k:ast.parse((ROOT/'source/healthchecks'/k).read_bytes()) for k in binding['source_bindings'] if k.endswith('.py')}
    for anchor in binding['source_anchors']:
        nodes=[n for n in ast.walk(trees[anchor['path']]) if isinstance(n,ast.FunctionDef)
            and n.lineno==anchor['first_line'] and n.end_lineno==anchor['last_line']]
        if len(nodes)!=1 or compile_function(nodes[0])!=binding['programs'][anchor['function']]:
            raise ValueError('source to closed-IR body binding differs')
    if binding['declared_framework']!='Django[argon2]==6.1.2':raise ValueError('source framework pin differs')
    from credential_flow_contexts import fixtures,expected
    if fixtures()!=p['owned_inputs']:raise ValueError('fixed normal context domain differs')
    actual=read(ROOT/'data/credential-observations.json')
    for c,o in zip(p['owned_inputs'],actual['rows']):
        if o['id']!=c['id'] or o['expected']!=expected(c) or o['observed']!=expected(c):raise ValueError('independent finite reference differs')
    if len(actual['rows'])!=1260:raise ValueError('incomplete normal observations')
    return p


def framework_check(directory):
    directory=Path(directory).resolve();runtime=read(ROOT/'data/credential-runtime.json')
    checked_dirs=set()
    for rel,h in runtime['unpacked_files'].items():
        parts=PurePosixPath(rel)
        if parts.is_absolute() or '..' in parts.parts or '\\' in rel or ':' in rel:raise ValueError('unsafe frozen framework name')
        parent=directory
        for part in parts.parts[:-1]:
            parent=parent/part
            if parent not in checked_dirs:
                if parent.is_symlink() or not parent.is_dir():raise ValueError('framework directory is not a plain data directory')
                checked_dirs.add(parent)
        p=directory.joinpath(*parts.parts)
        if p.is_symlink() or sha(p)!=h:raise ValueError('frozen framework file differs: '+rel)
    return directory


def prepare(directory,wheel_cache=None):
    directory=Path(directory).resolve();directory.mkdir(parents=True,exist_ok=True)
    runtime=read(ROOT/'data/credential-runtime.json')
    for row in runtime['packages']:
        url=row['wheel_url']
        if not url.startswith('https://files.pythonhosted.org/'):raise ValueError('frozen primary wheel host required')
        cache=None if wheel_cache is None else Path(wheel_cache)/Path(row['wheel_file']).name
        if cache is not None and cache.is_file():data=cache.read_bytes()
        else:
            with urllib.request.urlopen(url,timeout=30) as response:
                if not response.url.startswith('https://files.pythonhosted.org/'):raise ValueError('wheel redirected outside primary host')
                data=response.read(30_000_001)
        if len(data)>30_000_000 or hashlib.sha256(data).hexdigest()!=row['wheel_sha256']:raise ValueError('frozen wheel identity differs')
        with zipfile.ZipFile(BytesIO(data)) as z:
            for entry in z.infolist():
                rel=PurePosixPath(entry.filename)
                if rel.is_absolute() or '..' in rel.parts or '\\' in entry.filename or ':' in entry.filename or (entry.external_attr>>16)&0o170000==0o120000:
                    raise ValueError('unsafe dependency member')
                path=directory.joinpath(*rel.parts).resolve()
                if not path.is_relative_to(directory):raise ValueError('dependency path escaped selected directory')
                if entry.is_dir():path.mkdir(parents=True,exist_ok=True);continue
                if entry.file_size>10_000_000:raise ValueError('dependency member envelope')
                raw=z.read(entry)
                if path.exists() and path.read_bytes()!=raw:raise ValueError('do not overwrite different dependency data')
                path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    framework_check(directory);print(json.dumps(dict(primary_pure_wheels=3,verified_files=len(runtime['unpacked_files']),build_hooks_executed=False)))


def namespace():
    return ['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--cap-drop','ALL',
        '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
        '--proc','/proc','--dev','/dev','--size','67108864','--tmpfs','/tmp']


def child():
    sys.path[:0]=['/owned','/framework']
    from credential_flow_native import measure
    p=read('/inputs.json');print(json.dumps(measure(p['binding'],p['owned_inputs']),separators=(',',':')))


def replay(directory):
    if not sys.platform.startswith('linux') or os.getuid()==0:raise ValueError('non-root Linux,Python>=3.12,bubblewrap and prlimit required')
    if sys.version_info<(3,12):raise ValueError('source-pinned Django requires Python3.12+')
    p=source_check();framework=framework_check(directory)
    probe=("import os,pathlib; p=pathlib.Path; assert os.getuid()!=0; "
        "assert not any(p(x).exists() for x in ('/mnt','/home','/run/WSL')); "
        "assert {l.split(':')[0].strip() for l in p('/proc/net/dev').read_text().splitlines()[2:]}=={'lo'}; "
        "s=dict(l.split(':',1) for l in p('/proc/self/status').read_text().splitlines() if ':' in l); "
        "assert int(s['CapEff'].strip(),16)==0 and s['NoNewPrivs'].strip()=='1'; "
        "assert 'AUTHREFINE_SENTINEL' not in os.environ; print('isolated')")
    safe=dict(PATH='/usr/bin:/bin',LC_ALL='C.UTF-8',HOME='/tmp',TZ='UTC')
    done=subprocess.run(namespace()+['--clearenv','/usr/bin/python3','-I','-c',probe],env={**safe,'AUTHREFINE_SENTINEL':'owned-control'},capture_output=True,text=True,timeout=15)
    if done.returncode or done.stdout!='isolated\n' or done.stderr:raise ValueError('actual namespace controls not observed')
    command=namespace()+['--ro-bind',str(framework),'/framework','--ro-bind',str(ROOT/'data/credential-input.json.gz'),'/inputs.json.gz',
        '--ro-bind',str(Path(__file__).resolve()),'/owned/replay.py']
    for name in ('credential_flow_ir.py','credential_flow_contexts.py','credential_flow_native.py'):
        command+=['--ro-bind',str(ROOT/'code'/name),'/owned/'+name]
    command+=['--clearenv','--setenv','LC_ALL','C.UTF-8','/usr/bin/prlimit','--as=536870912','--cpu=120','--nproc=256',
        '--nofile=128','--fsize=16777216','--','/usr/bin/python3','-I','-S','-B','/owned/replay.py','child']
    done=subprocess.run(command,env=safe,capture_output=True,timeout=150)
    if done.returncode or done.stderr:raise ValueError('isolated owned replay failed: '+done.stderr.decode(errors='replace'))
    actual=json.loads(done.stdout)
    if actual!=read(ROOT/'data/credential-observations.json'):raise ValueError('complete source/native replay differs from retained observations')
    print(json.dumps(dict(full_finite_native_replay=True,**actual['totals'],
        host_home_network_parent_environment_absent=True,source_application_modules_executed=False)))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['check','prepare','replay','child']);parser.add_argument('--framework');parser.add_argument('--wheel-cache')
    args=parser.parse_args()
    if args.mode in ('prepare','replay') and not args.framework:parser.error('--framework is required')
    if args.mode=='prepare':prepare(args.framework,args.wheel_cache)
    elif args.mode=='replay':replay(args.framework)
    elif args.mode=='child':child()
    else:source_check();print(json.dumps(dict(source_functions=10,normal_contexts=1260,source_as_data_only=True)))
