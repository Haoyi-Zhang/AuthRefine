#!/usr/bin/env python3
"""Self-contained release verifier for the trace-refinement artifact.

Quick mode performs immutable-source hashing, JSON/schema hygiene, archive-safety
checks, and the full unit suite.  ``--campaign`` additionally executes the
published deterministic reproduction in a temporary copy so the frozen
baseline is not overwritten.
"""
from __future__ import annotations
import argparse, ast, hashlib, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
VOLATILE={"__pycache__",".pytest_cache",".mypy_cache",".coverage"}

def sha256(p:Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()

def count_tests()->int:
    n=0
    for p in (ROOT/'tests').rglob('*.py'):
        tree=ast.parse(p.read_text(encoding='utf-8'),filename=str(p))
        n+=sum(isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef)) and x.name.startswith('test_') for x in ast.walk(tree))
    return n

def immutable_files():
    roots=[ROOT/'src',ROOT/'tests',ROOT/'external_inputs']
    seen=set()
    for base in roots:
        if base.exists():
            for p in sorted(base.rglob('*')):
                if p.is_file() and not any(x in VOLATILE for x in p.parts) and p.suffix not in {'.pyc','.pyo'}:
                    seen.add(p.resolve()); yield p
    for p in sorted(ROOT.iterdir()):
        if (p.is_file() and p.name not in {'SOURCE-MANIFEST.sha256','FINAL-VERIFICATION.md','RESULT-FILE-INDEX.md'} and p.suffix not in {'.pyc','.pyo'}
                and p.name not in {'.coverage','.coverage.release-audit'} and p.resolve() not in seen):
            yield p

def run(cmd,cwd=ROOT,timeout=900,env=None):
    cp=subprocess.run(cmd,cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout,env=env)
    return {"cmd":cmd,"returncode":cp.returncode,"output_tail":cp.stdout[-12000:]}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--campaign',action='store_true',help='run the full deterministic campaign in a temporary copy')
    ap.add_argument('--json',action='store_true',help='emit machine-readable JSON')
    a=ap.parse_args()
    checks=[]
    # No symlinks or cache/bytecode in the delivered tree.
    links=[str(p.relative_to(ROOT)) for p in ROOT.rglob('*') if p.is_symlink()]
    caches=[str(p.relative_to(ROOT)) for p in ROOT.rglob('*') if p.name in VOLATILE or p.suffix in {'.pyc','.pyo'}]
    checks.append({'name':'archive_hygiene','ok':not links and not caches,'links':links,'cache_entries':caches})
    # Parse every JSON evidence file.
    bad_json=[]; json_files=0
    for p in ROOT.rglob('*.json'):
        json_files+=1
        try: json.loads(p.read_text(encoding='utf-8'))
        except Exception as e: bad_json.append({'file':str(p.relative_to(ROOT)),'error':str(e)})
    checks.append({'name':'json_parse','ok':not bad_json,'files':json_files,'errors':bad_json})
    # Compare immutable source hashes with the release manifest.
    manifest=ROOT/'SOURCE-MANIFEST.sha256'
    actual={str(p.relative_to(ROOT)):sha256(p) for p in immutable_files() if p.name!='SOURCE-MANIFEST.sha256'}
    expected={}
    if manifest.exists():
        for line in manifest.read_text(encoding='utf-8').splitlines():
            if not line.strip(): continue
            digest,name=line.split('  ',1); expected[name]=digest
    checks.append({'name':'source_manifest','ok':bool(expected) and expected==actual,
                   'expected_files':len(expected),'actual_files':len(actual),
                   'missing':sorted(set(expected)-set(actual)),'extra':sorted(set(actual)-set(expected)),
                   'changed':sorted(k for k in set(actual)&set(expected) if actual[k]!=expected[k])})
    # Unit tests in ordinary and optimized mode.
    ordinary=run([sys.executable,'-W','error','-m','unittest','discover','-s','tests'])
    optimized=run([sys.executable,'-OO','-W','error','-m','unittest','discover','-s','tests'])
    checks.append({'name':'unit_tests','ok':ordinary['returncode']==0 and optimized['returncode']==0,
                   'test_methods':count_tests(),'ordinary':ordinary,'optimized':optimized})
    if a.campaign:
        with tempfile.TemporaryDirectory(prefix='trace-refinement-verify-') as td:
            dst=Path(td)/'artifact'; shutil.copytree(ROOT,dst,ignore=shutil.ignore_patterns('__pycache__','*.pyc','.coverage'))
            env=os.environ.copy(); env.update({'PYTHONHASHSEED':'1729','TZ':'UTC','LC_ALL':'C.UTF-8','LANG':'C.UTF-8'})
            campaign=run([sys.executable,'reproduce.py'],cwd=dst,timeout=1200,env=env)
            checks.append({'name':'campaign','ok':campaign['returncode']==0,'run':campaign})
    report={'schema_version':1,'python':sys.version,'root':str(ROOT),'checks':checks,'ok':all(x['ok'] for x in checks)}
    if a.json: print(json.dumps(report,indent=2,ensure_ascii=False))
    else:
        for c in checks: print(('PASS' if c['ok'] else 'FAIL')+'  '+c['name'])
        print('PASS  release' if report['ok'] else 'FAIL  release')
    return 0 if report['ok'] else 1
if __name__=='__main__': raise SystemExit(main())
