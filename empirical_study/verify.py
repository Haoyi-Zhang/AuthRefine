"""Offline verification of the fixed-source empirical evidence and source bodies."""
import ast,base64,csv,gzip,hashlib,json,sys
from collections import Counter
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from predicate_runtime import body_identity
from review import verify_review
ROOT=Path(__file__).resolve().parent
def load(name,root=ROOT):
    path=root/'data'/name
    with gzip.open(path,'rb') as f:raw=f.read(64000001)
    if len(raw)>64000000:raise ValueError('data envelope')
    return json.loads(raw)
def exact(a,b):return json.dumps(a,sort_keys=True,separators=(',',':'))==json.dumps(b,sort_keys=True,separators=(',',':'))
def canonical(row,keys):return json.dumps({k:row[k] for k in keys},sort_keys=True,separators=(',',':'))
def verify_evidence_categories(root,population,observations):
    with (root/'data/evidence-classification.csv').open(encoding='utf-8',newline='') as f:
        reader=csv.DictReader(f)
        fields=['project','repository','extended_source_scope','evidence_category','upstream_defect_status']
        if reader.fieldnames!=fields:raise ValueError('evidence classification schema')
        rows=list(reader)
    if [(r['project'],r['repository']) for r in rows]!=[(p['project'],p['repository']) for p in population]:
        raise ValueError('evidence classification project identity')
    expected_extensions={r['project'] for r in observations['extension_coverage']['rows']}
    if any(r['extended_source_scope']!=('yes' if r['project'] in expected_extensions else 'no') for r in rows):
        raise ValueError('evidence classification extension coverage')
    exceptions={'R01':'documentation_scope_difference','R22':'local_contract_mismatch'}
    if any(set(r)!=set(fields) or r['evidence_category']!=exceptions.get(r['project'],'scoped_verification')
           or r['upstream_defect_status']!='not_established' for r in rows):
        raise ValueError('unsubstantiated evidence classification')
    policy=observations['policy_recheck']
    if (policy['upstream_files_changed'] is not False or policy['new_defects_claimed']!=0
            or policy['normal_contract_recheck_passed'] is not True):
        raise ValueError('local mismatch cannot be classified as an upstream repair')
    return dict(Counter(r['evidence_category'] for r in rows))
def verify_evidence_trace(root,inputs,observations):
    trace=json.loads((root/'data/evidence-trace.json').read_text(encoding='utf-8'))
    cases={r['project']:r for r in trace['cases']}
    if len(trace['cases'])!=2 or set(cases)!={'R01','R22'}:
        raise ValueError('evidence trace case set')
    with (root/'data/evidence-classification.csv').open(encoding='utf-8',newline='') as f:
        rows={r['project']:r for r in csv.DictReader(f)}
    for key,case in cases.items():
        if (case['category']!=rows[key]['evidence_category']
                or case['upstream_defect_status']!=rows[key]['upstream_defect_status']):
            raise ValueError('evidence trace classification')
    documentation=cases['R01']
    expected=[r for r in inputs['primary']['cases'] if r['project']=='R01']
    if (documentation['retained_entries']!=[r['id'] for r in expected]
            or [r['function'] for r in expected if r['id']==documentation['documentation_entry']]
            !=['Authenticator.check_allowed']
            or any(r['snapshot'] not in documentation['frozen_source'] for r in expected)):
        raise ValueError('documentation trace source identity')
    local=cases['R22']
    if local['observation_key']!='policy_recheck':
        raise ValueError('local comparison record identity')
    policy=observations[local['observation_key']]
    variants={r['variant']:r for r in policy['variants']}
    original,copy=variants['original'],variants['proposed_repair']
    if (original['normal_contexts']!=local['contexts'] or copy['normal_contexts']!=local['contexts']
            or len(original['mismatches'])!=local['original_mismatches']
            or len(copy['mismatches'])!=local['local_copy_mismatches']
            or local['upstream_files_changed'] is not False or policy['upstream_files_changed'] is not False):
        raise ValueError('local comparison trace counts')
def verify(root=ROOT):
    root=Path(root);manifest=json.loads((root/'manifest.json').read_text(encoding='utf-8'))
    for name,expected in manifest['files'].items():
        p=(root/name).resolve()
        if not p.is_relative_to(root.resolve()) or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise ValueError('file identity:'+name)
    inputs=load('inputs.json.gz',root);observations=load('observations.json.gz',root);sources=load('sources.json.gz',root)
    population=inputs['population'];projects={p['project'] for p in population}
    if len(population)!=40 or len(projects)!=40 or len({p['repository_id'] for p in population})!=40:raise ValueError('population')
    verify_evidence_categories(root,population,observations)
    verify_evidence_trace(root,inputs,observations)
    bysource={(s['project'],s['path']):s for s in sources}
    rawsources={}
    for key,s in bysource.items():
        raw=base64.b64decode(s['content_base64'],validate=True)
        if hashlib.sha256(raw).hexdigest()!=s['sha256']:raise ValueError('original source bytes')
        rawsources[key]=raw
    def capsule(row):
        raw=rawsources[row['project'],row['member']]
        if hashlib.sha256(raw).hexdigest()!=row['source_sha256']:raise ValueError('capsule source file')
        nodes=[n for n in ast.walk(ast.parse(raw)) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.lineno==row['line'] and n.end_lineno==row['end_line']]
        text='\n'.join(raw.decode('utf-8-sig').splitlines()[row['line']-1:row['end_line']])+'\n'
        if len(nodes)!=1 or body_identity(nodes[0].body)!=row['portable_body_sha256'] or text!=row['source']:raise ValueError('original source capsule')
    primary=inputs['primary'];remaining=inputs['delegated'];extensions=inputs['extensions']
    for row in primary['cases']+[r for c in remaining['cases']+extensions['cases'] for r in c['functions']]:capsule(row)
    primary_projects={c['project'] for c in primary['cases']};delegated_projects={c['project'] for c in remaining['cases']}
    if primary_projects&delegated_projects or primary_projects|delegated_projects!=projects:raise ValueError('selected project partition')
    for repeat in observations['primary']:
        if [r['id'] for r in repeat['rows']]!=[c['id'] for c in primary['cases']]:raise ValueError('primary case order')
        for c,row in zip(primary['cases'],repeat['rows']):
            if [s['id'] for s in c['inputs']]!=[s['id'] for s in row['observations']]:raise ValueError('primary input omission')
            for s,v in zip(c['inputs'],row['observations']):
                if not exact(v['native'],v['model']) or not exact(v['native'],s['expected']):raise ValueError('primary observation')
    def check_suite(label,cases,keys):
        runs=observations[label]
        for case in cases:
            selected=[r for r in runs if r['project']==case['project']]
            if {(r['arm'],r['repeat']) for r in selected}!={(a,n) for a in ('native','model') for n in (1,2,3)}:raise ValueError('paired run omission')
            base=None
            for run in selected:
                if [r['id'] for r in run['observations']]!=[r['id'] for r in case['samples']]:raise ValueError('context omission')
                current=[canonical(r,keys) for r in run['observations']]
                if base is None:base=current
                elif current!=base:raise ValueError('paired return/trace/state difference')
                for sample,row in zip(case['samples'],run['observations']):
                    if row['result']['status'] in ('harness_error','unsupported'):raise ValueError('incomplete result')
                    expected=sample.get('expected',sample['fixture'].get('expected_result'))
                    result=row['result'];fixture=sample['fixture']
                    if expected and not all(k in result and exact(result[k],v) for k,v in expected.items()):raise ValueError('functional contract difference')
                    if 'expected' in fixture:
                        value=result.get('value')
                        if case['project']=='R24':value=value.get('authenticated') if isinstance(value,dict) else None
                        if result['status']!='value' or not exact(value,fixture['expected']):raise ValueError('extension normal result')
                    if 'expected_active' in fixture and (result['status']!='value' or not exact(result.get('value',{}).get('active'),fixture['expected_active'])):raise ValueError('source active property result')
                    if 'expected_status' in fixture:
                        status=result.get('status_code',200)
                        if case['project']=='R04' and result['status']=='value':status=result['value']['status_code']
                        if status!=fixture['expected_status']:raise ValueError('extension status')
                    if label=='extensions' and case['project']=='R26':
                        value=dict(username=fixture['username'],password=fixture['password']) if fixture['username'] or fixture['password'] else None
                        if not exact(result,dict(status='value',value=value)):raise ValueError('credential handoff')
                    if label=='extensions' and case['project']=='R31':
                        value=dict(roles=['reader'] if fixture['subject']=='alice' else [],admin=False,allowed=fixture['subject']=='alice' and fixture['action']=='read')
                        if not exact(result,dict(status='value',value=value)):raise ValueError('role-list versus authorization verdict')
    check_suite('delegated',remaining['cases'],('id','result','provider_trace','state'))
    check_suite('extensions',extensions['cases'],('id','result','trace','state'))
    declared=sum(len(c['functions']) for c in extensions['cases'])
    if declared!=sum(len(r['entered']) for r in observations['extension_coverage']['rows']) or any(r['unentered'] for r in observations['extension_coverage']['rows']):raise ValueError('actual function-object entry')
    policy=observations['policy_recheck']
    if not policy['normal_contract_recheck_passed'] or [len(x['mismatches']) for x in policy['variants']]!=[2,0]:raise ValueError('policy-copy repair')
    totals=observations['static_application_paths']
    if totals['baseline']['non_auxiliary_source_path']['declared_routes']!=2212 or totals['guarded']['non_auxiliary_source_path']['all_declared_dependencies_linked']!=1022:raise ValueError('static denominator')
    methods=json.loads((root/'methods.json').read_text(encoding='utf-8'))
    if methods['source_contract_review']['items']!=99 or sum(methods['source_contract_review']['final_categories'].values())!=99 or methods['source_contract_review']['final_response_items']!=115:raise ValueError('structured assessment denominator')
    if methods['source_contract_review']['independent_semantic_gold_claimed'] or methods['source_contract_review']['raw_response_text_or_reviewer_identities_distributed']:raise ValueError('unsupported review provenance claim')
    review=verify_review(root,methods)
    if len(methods['projects'])!=40 or methods['source_execution']['extension_function_bindings']!=declared:raise ValueError('method/source binding count')
    if len(methods['costs']['delegated_batch_wall_ns'])!=6 or methods['costs']['extension_worker_processes']!=60 or len(methods['costs']['static_runs'])!=240:raise ValueError('cost strata')
    followup=methods['repairs'].get('additional_owned_followup_controls',{})
    if followup.get('tests')!=5 or not followup.get('after_all_pass'):raise ValueError('context/keyword follow-up controls')
    anonymous=next(c for c in extensions['cases'] if c['project']=='R24')
    if not any(r['function']=='Anonymous.is_active' for r in anonymous['functions']):raise ValueError('anonymous active source omitted')
    for r in observations['extensions']:
        if r['project']=='R24':
            value=next(x['result'] for x in r['observations'] if x['id']=='R24-F04')
            if not exact(value,dict(status='value',value=dict(authenticated=False,active=False))):raise ValueError('unobserved anonymous active field')
    return dict(projects=40,primary_contexts=sum(len(c['inputs']) for c in primary['cases'])+sum(len(c['samples']) for c in remaining['cases']),
        extension_projects=len(extensions['cases']),extension_contexts=sum(len(c['samples']) for c in extensions['cases']),
        extension_source_functions=declared,all_recorded_observations_consistent=True,
        whole_application_certificate=False,baseline_and_extension_counts_are_not_independent_samples=True,
        completed_source_review_items=review['completed_final_items'])
if __name__=='__main__':print(json.dumps(verify(),indent=2))
