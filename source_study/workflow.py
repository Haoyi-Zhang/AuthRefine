"""Source archive -> discovered guards -> supplied contract -> replayable diagnosis.

Application files are parsed as data, never imported or executed. The reusable
profile admits pure returned FastAPI closures and complete JSON observations.
An optional fixed native policy primitive is reconstructed from source literals.
Contracts specify expected results separately from the measured source program.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import configparser
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import time
import zipfile

ROOT=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'code'),str(ROOT.parent/'src')]
from closure_guard_ir import compile_guard, evaluate, Unsupported
from dependency_closure_inventory import Inventory
from finite_observation_diagnosis import diagnose_observations
from inspect_source import validate_archive, summarize

MAX_CONTRACT_BYTES=4_000_000
MAX_CONTEXTS=4096
MODEL={'request_definition':{'r':'sub,obj,act,tenant'},
       'policy_definition':{'p':'sub,obj,act,tenant'},
       'role_definition':{'g':'_,_,_'},
       'policy_effect':{'e':'some(where(p.eft==allow))'},
       'matchers':{'m':'g(r.sub,p.sub,r.tenant)&&r.obj==p.obj&&regexMatch(r.act,p.act)&&r.tenant==p.tenant'}}


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def identity(raw):return hashlib.sha256(raw).hexdigest()


def read_json(path):
    path=Path(path)
    if path.stat().st_size>MAX_CONTRACT_BYTES:
        raise ValueError('contract input exceeds its byte envelope')
    def unique(pairs):
        out={}
        for key,value in pairs:
            if key in out:raise ValueError('duplicate contract key: '+key)
            out[key]=value
        return out
    return json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=unique,
        parse_constant=lambda value:(_ for _ in ()).throw(ValueError('nonfinite JSON literal')))


def _source_member(archive,names,member):
    path=PurePosixPath(member)
    if (path.is_absolute() or '..' in path.parts or '\\' in member or ':' in member
            or member not in names):raise Unsupported('source member is not uniquely bound')
    info=archive.getinfo(names[member])
    if info.file_size>1_048_576 or (info.external_attr>>16)&0o170000==0o120000:
        raise Unsupported('source member exceeds the plain-file envelope')
    return archive.read(info)


def _native_binding(inventory,item,module,member,archive,names,program):
    helper=item['definitions'].get('_get_enforcer')
    if helper is None or item['writes']['_get_enforcer']!=1:
        raise Unsupported('native producer is absent or shadowed')
    calls=[n for n in ast.walk(helper) if isinstance(n,ast.Call)
           and inventory.expression(n.func,module)=='casbin.Enforcer']
    if len(calls)!=1 or calls[0].keywords or len(calls[0].args)!=2:
        raise Unsupported('native constructor is not the supported two-literal source profile')
    directories=[n for n in item['tree'].body if isinstance(n,ast.Assign)
        and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='_SECURITY_DIR']
    if (len(directories)!=1 or item['writes']['_SECURITY_DIR']!=1
            or ast.unparse(directories[0].value)!='Path(__file__).parent'
            or item['bindings'].get('Path')!='pathlib.Path' or item['writes']['Path']!=1
            or item['writes']['casbin']!=1 or item['bindings'].get('casbin')!='casbin'
            or item['writes']['str']):raise Unsupported('native file-directory or primitive origin is unresolved')
    files=[]
    for arg in calls[0].args:
        if not (isinstance(arg,ast.Call) and isinstance(arg.func,ast.Name) and arg.func.id=='str'
                and len(arg.args)==1 and not arg.keywords and isinstance(arg.args[0],ast.BinOp)
                and isinstance(arg.args[0].op,ast.Div) and isinstance(arg.args[0].left,ast.Name)
                and arg.args[0].left.id=='_SECURITY_DIR' and isinstance(arg.args[0].right,ast.Constant)
                and type(arg.args[0].right.value) is str):
            raise Unsupported('native file expression requires a separate source profile')
        name=str(PurePosixPath(member).parent/arg.args[0].right.value)
        raw=_source_member(archive,names,name)
        files.append(dict(member=name,sha256=identity(raw),text=raw.decode('utf-8-sig')))
    parser=configparser.ConfigParser(interpolation=None,delimiters=('=',),strict=True)
    parser.read_string(files[0]['text'])
    actual={s:{k:re.sub(r'\s+','',v) for k,v in parser[s].items()} for s in parser.sections()}
    if parser.defaults() or actual!=MODEL:
        raise Unsupported('native matcher is outside the fixed tenant-role primitive profile')
    rows=[tuple(v.strip() for v in line.split(',')) for line in files[1]['text'].splitlines()
          if line.strip() and not line.lstrip().startswith('#')]
    if (len(rows)>256 or any(not r or r[0] not in ('p','g')
            or len(r)!=(5 if r[0]=='p' else 4) for r in rows)):
        raise Unsupported('native literal policy row envelope differs')
    if any(len(v)>128 for r in rows for v in r):raise Unsupported('native policy token envelope')
    # Only bounded literal/alternation patterns are sent to the trusted engine.
    pattern=r'(?:[A-Za-z0-9_]+(?:\|[A-Za-z0-9_]+)*|\([A-Za-z0-9_]+(?:\|[A-Za-z0-9_]+)*\)|\.\*)'
    if any(not re.fullmatch(pattern,r[3]) and not (r[2]=='*' and r[3]=='*'
            and type(program['captures'].get('obj')) is str and program['captures']['obj']!='*')
            for r in rows if r[0]=='p'):
        raise Unsupported('native action pattern is outside the reviewed literal profile')
    return dict(model=files[0],policy=files[1],rows=rows,
        contract='fixed native instance for this source call; startup, singleton and authentication supplied')


def discover(archive_path):
    path=Path(archive_path);validate_archive(path)
    inventory=Inventory(path);report=inventory.scan();guards=[]
    with zipfile.ZipFile(path) as archive:
        names={n.partition('/')[2]:n for n in archive.namelist() if not n.endswith('/')}
        for binding in report['pure_returned_closure_source_bindings']:
            member=binding['factory_member'];item=next(x for x in inventory.modules.values() if x['path']==member)
            module=next(k for k,v in inventory.modules.items() if v is item)
            row=dict(source_binding=binding,status='unsupported',program=None)
            try:
                if (item['bindings'].get('HTTPException')!='fastapi.HTTPException'
                        or item['writes']['HTTPException']!=1 or any(item['writes'][n] for n in ('any','all'))):
                    raise Unsupported('denial primitive or source builtins are unresolved')
                nodes=[n for n in ast.walk(item['tree']) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))
                    and n.lineno==binding['closure_line'] and n.end_lineno==binding['closure_end_line']]
                if len(nodes)!=1:raise Unsupported('returned closure source identity is ambiguous')
                node=nodes[0]
                reserved={'any','all','HTTPException','_get_enforcer','logger'}
                if (any(n.arg in reserved for n in node.args.args)
                        or reserved.intersection(binding['captures'])
                        or any(isinstance(n,ast.Name) and isinstance(n.ctx,(ast.Store,ast.Del))
                               and n.id in reserved for n in ast.walk(node))):
                    raise Unsupported('closure shadows a modeled primitive')
                constants={}
                for n in ast.walk(node):
                    if isinstance(n,ast.Attribute) and inventory.expression(n,module)=='fastapi.status.HTTP_403_FORBIDDEN':
                        constants[ast.unparse(n)]=403
                row['program']=compile_guard(node,binding['captures'],constants)
                row['capture_values']=row['program']['captures']
                row['source_sha256']=report['source_bindings'][member]
                def operations(value):
                    if isinstance(value,list):
                        if value and isinstance(value[0],str):yield value[0]
                        for v in value:yield from operations(v)
                if 'enforcer' in set(operations(row['program']['statements'])):
                    row['native_binding']=_native_binding(inventory,item,module,member,archive,names,row['program'])
                row['status']='compiled_guard'
            except (Unsupported,SyntaxError,ValueError,KeyError,RecursionError,configparser.Error) as error:
                row['status']='unsupported';row['program']=None;row['reason']=str(error)
            guards.append(row)
    return report,guards


def validate_contract(contract):
    if (not isinstance(contract,dict) or set(contract)!={'profile','entry_contract','cases'}
            or contract['profile']!='returned-guard' or type(contract['entry_contract']) is not str
            or not contract['entry_contract'].strip() or not isinstance(contract['cases'],list)
            or not 1<=len(contract['cases'])<=128):raise ValueError('invalid returned-guard contract')
    seen=set();selectors=set();count=0
    for case in contract['cases']:
        if (not isinstance(case,dict) or set(case)!={'id','select','contexts'}
                or type(case['id']) is not str or not case['id'] or case['id'] in seen):
            raise ValueError('distinct nonempty contract case identifiers required')
        seen.add(case['id']);selection=case['select']
        if (not isinstance(selection,dict) or set(selection)-{'factory','captures','member'}
                or not {'factory','captures'}<=set(selection) or type(selection['factory']) is not str
                or not isinstance(selection['captures'],dict)
                or 'member' in selection and type(selection['member']) is not str):
            raise ValueError('invalid semantic source selector')
        key=canonical(selection)
        if key in selectors:raise ValueError('duplicate source selector; combine its contexts instead')
        selectors.add(key)
        if not isinstance(case['contexts'],list) or not case['contexts']:
            raise ValueError('contract needs complete nonempty normal contexts')
        ids=set()
        for context in case['contexts']:
            count+=1
            if count>MAX_CONTEXTS:raise ValueError('contract context envelope exceeded')
            if (not isinstance(context,dict) or set(context)!={'id','arguments','expected'}
                    or type(context['id']) is not str or not context['id'] or context['id'] in ids
                    or not isinstance(context['arguments'],dict)):raise ValueError('invalid or duplicate normal context')
            ids.add(context['id']);expected=context['expected']
            if (not isinstance(expected,dict) or expected.get('decision') not in ('allow','deny')
                    or set(expected)!=({'decision','returned_value'} if expected['decision']=='allow' else {'decision'})):
                raise ValueError('expected allow requires returned value; deny is an explicit decision')
    canonical(contract)
    return count


def _engine(binding):
    from native_runtime import engine_identity
    from native_casbin import AdmissionError
    try:
        runtime=engine_identity()
        if runtime['profile']!='casbin-1.43.0':raise Unsupported('workflow native profile requires casbin-1.43.0')
        import casbin
        from casbin.persist.adapters import StringAdapter
        model=casbin.Model();model.load_model_from_text(binding['model']['text'])
        engine=casbin.Enforcer(model,StringAdapter(binding['policy']['text']));engine.enable_auto_save(False)
        for kind in ('p','g'):
            if engine.model.model[kind][kind].policy!=[list(r[1:]) for r in binding['rows'] if r[0]==kind]:
                raise Unsupported('native literal policy load differs')
        return engine.enforce,{k:v for k,v in runtime.items() if k!='imported_module'}
    except (ImportError,AdmissionError) as error:
        raise Unsupported('workflow native dependency unavailable: '+str(error)) from error


def check_contract(guards,contract):
    validate_contract(contract);outputs=[];selected=set()
    for case in contract['cases']:
        selector=case['select']
        matching=[(i,g) for i,g in enumerate(guards) if g['status']=='compiled_guard' and g['source_binding']['factory_name']==selector['factory']
            and ('member' not in selector or g['source_binding']['factory_member']==selector['member'])
            and g.get('capture_values')==selector['captures']]
        if not matching:
            outputs.append(dict(id=case['id'],status='source_not_admitted',reason='no compiled source closure matches the contract selector',observations=[]))
            continue
        for index,guard in matching:
            if index in selected:raise ValueError('overlapping selectors would replay the same source binding twice')
            selected.add(index);observed=[];properties=[];native=None;runtime=None
            try:
                if 'native_binding' in guard:native,runtime=_engine(guard['native_binding'])
            except Unsupported as error:
                outputs.append(dict(id=case['id'],status='dependency_missing',reason=str(error),observations=[]));continue
            started=time.perf_counter_ns()
            for context in case['contexts']:
                actual=evaluate(guard['program'],context['arguments'],native)
                expected=context['expected'];valid=actual['decision'] in ('allow','deny')
                agreement=(valid and actual['decision']==expected['decision']
                    and (expected['decision']=='deny' or canonical(actual.get('returned_value'))==canonical(expected['returned_value'])))
                observed.append(dict(id=context['id'],arguments=context['arguments'],expected=expected,
                    observed=actual,agrees=agreement if valid else None))
                if valid:
                    properties.append(dict(id=context['id']+':decision',expected=expected['decision']=='allow',observed=actual['decision']=='allow'))
                    if expected['decision']=='allow':properties.append(dict(id=context['id']+':returned-value',expected=True,
                        observed=actual['decision']=='allow' and canonical(actual.get('returned_value'))==canonical(expected['returned_value'])))
            observed_ns=time.perf_counter_ns()-started
            unknown=sum(o['agrees'] is None for o in observed)
            started=time.perf_counter_ns()
            diagnosis=None if unknown else diagnose_observations(properties)
            diagnosis_ns=time.perf_counter_ns()-started
            status=('inconclusive' if unknown else 'contract_mismatch' if any(not o['agrees'] for o in observed) else 'semantic_agreement')
            outputs.append(dict(id=case['id'],status=status,source_binding=guard['source_binding'],
                source_sha256=guard['source_sha256'],program_identity=identity(canonical(guard['program']).encode()),
                contexts=len(observed),unknown_contexts=unknown,observations=observed,diagnosis=diagnosis,
                source_observation_ns=observed_ns,complete_diagnosis_ns=diagnosis_ns,
                native_runtime=runtime,native_calls=sum(len(o['observed']['native_calls']) for o in observed)))
    complete=all(o['status'] in ('semantic_agreement','contract_mismatch') for o in outputs)
    return dict(status='checked' if complete else 'incomplete',entry_contract=contract['entry_contract'],cases=outputs,
        selected_discovered_bindings=len(selected),unselected_discovered_bindings=len(guards)-len(selected),
        actual_context_executions=sum(o.get('contexts',0) for o in outputs),
        semantic_success_not_inferred_from_links=True,
        comparison_unit='declared returned-guard boundary, reset per complete JSON context; not persistent application state')


def analyze(archive_path,contract=None):
    started=time.perf_counter_ns();source,guards=discover(archive_path);discovery_ns=time.perf_counter_ns()-started
    compiled=sum(g['status']=='compiled_guard' for g in guards)
    if contract is not None:semantics=check_contract(guards,contract)
    else:semantics=None
    stage=('unsupported_source_form' if not source['routes'] else
           'needs_contract' if compiled else 'unsupported_guard_form' if guards else 'structural_only')
    if semantics is not None:stage='contract_checked' if semantics['status']=='checked' else 'contract_incomplete'
    return dict(status=stage,snapshot=source['snapshot'],archive_sha256=source['archive_sha256'],
        source_bindings=source['source_bindings'],structure=summarize(source),guards=guards,
        discovered_closure_bindings=len(guards),compiled_closure_bindings=compiled,
        unsupported_closure_bindings=len(guards)-compiled,semantics=semantics,
        stages_ns=dict(source_discovery_and_compilation=discovery_ns,total=time.perf_counter_ns()-started),
        source_modules_or_tests_executed=False,whole_application_verified=False,model_requests=0)


def batch(archives,contracts=None):
    # This population is the original exposed transfer, not a newly selected cohort.
    original=json.loads(gzip.decompress((ROOT/'data/source-transfer.json.gz').read_bytes()))
    rows=[]
    for entry in original['rows']:
        path=Path(archives)/(str(entry['repository_id'])+'.zip')
        base={k:entry[k] for k in ('repository_id','repository','source_snapshot','archive_sha256','stratum')}
        try:
            if identity(path.read_bytes())!=entry['archive_sha256']:raise ValueError('original source identity differs')
            contract_path=None if contracts is None else Path(contracts)/(str(entry['repository_id'])+'.json')
            contract=read_json(contract_path) if contract_path is not None and contract_path.exists() else None
            result=analyze(path,contract)
            if result['snapshot']!=entry['source_snapshot']:raise ValueError('original snapshot differs')
            rows.append(dict(**base,result=result))
        except (OSError,ValueError,zipfile.BadZipFile,RecursionError) as error:
            rows.append(dict(**base,result=dict(status='invalid_input',reason=str(error))))
    return dict(sources=len(rows),rows=rows,status_counts=dict(Counter(r['result']['status'] for r in rows)),
        all_original_sources_retained=len(rows)==48,
        source_modules_or_tests_executed=False,new_independent_samples=0,model_requests=0)


def suite(framework=None):
    from verify import verify
    from repair_profiles import verify as repair
    result=dict(frozen_family_and_case_recomputation=verify(),executed_repair_consumers=repair())
    if framework is not None:
        from replay import replay
        # Keep the replay's JSON stdout inside this result's own output stream.
        import contextlib,io
        out=io.StringIO()
        with contextlib.redirect_stdout(out):replay(framework)
        result['isolated_native_credential_replay']=json.loads(out.getvalue())
    else:result['isolated_native_credential_replay']='not requested; retained identity-bound native evidence is separate'
    return result


def replay_profiles():
    base=ROOT/'source/returned-guards'
    registry=read_json(base/'bindings.json');outputs=[]
    for item in registry['projects']:
        if not re.fullmatch(r'[0-9]+',item['directory']):raise ValueError('invalid selected source directory')
        directory=(base/item['directory']).resolve()
        if not directory.is_relative_to(base.resolve()):raise ValueError('selected source escaped its root')
        relative=PurePosixPath(item['contract'])
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('invalid contract location')
        contract_path=(ROOT/relative).resolve()
        if not contract_path.is_relative_to(ROOT) or identity(contract_path.read_bytes())!=item['contract_sha256']:
            raise ValueError('bound review contract differs')
        with tempfile.TemporaryDirectory(prefix='authrefine-owned-source-') as tmp:
            path=Path(tmp)/'source.zip'
            with zipfile.ZipFile(path,'w') as archive:
                archive.comment=item['snapshot'].encode('ascii')
                for member,expected in item['files'].items():
                    source=(directory/member).resolve()
                    if not source.is_relative_to(directory) or identity(source.read_bytes())!=expected:
                        raise ValueError('selected original source differs: '+member)
                    archive.writestr('selected-source/'+member,source.read_bytes())
            result=analyze(path,read_json(contract_path))
        outputs.append(dict(repository=item['repository'],snapshot=item['snapshot'],source_scope=item['scope'],result=result))
    return dict(projects=outputs,context_executions=sum(p['result']['semantics']['actual_context_executions'] for p in outputs),
        current_source_compilation_and_diagnosis=True,source_modules_or_tests_executed=False,model_requests=0)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='mode',required=True)
    one=sub.add_parser('source');one.add_argument('archive');one.add_argument('--contract',type=Path)
    many=sub.add_parser('batch');many.add_argument('--archives',required=True,type=Path);many.add_argument('--contracts',type=Path)
    check=sub.add_parser('check');check.add_argument('--framework',type=Path)
    replay=sub.add_parser('replay')
    for item in (one,many,check,replay):item.add_argument('--output',type=Path)
    args=parser.parse_args(argv)
    try:
        if args.output is not None and args.output.exists():raise ValueError('output path must be fresh')
        if args.mode=='source':value=analyze(args.archive,None if args.contract is None else read_json(args.contract))
        elif args.mode=='batch':value=batch(args.archives,args.contracts)
        elif args.mode=='replay':value=replay_profiles()
        else:value=suite(args.framework)
        text=json.dumps(value,indent=2,allow_nan=False)+'\n'
        if args.output:
            with args.output.open('x',encoding='utf-8') as stream:stream.write(text)
        else:print(text,end='')
    except (OSError,ValueError,zipfile.BadZipFile,RecursionError) as error:
        parser.exit(2,'workflow did not complete: '+str(error)+'\n')


if __name__=='__main__':main()
