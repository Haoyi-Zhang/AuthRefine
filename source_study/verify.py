"""Recompute fixed-family outputs and case tables from the shipped study data."""
import hashlib
import gzip
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT.parent/'src'),str(ROOT/'code')]
from source_family import diagnose_source_family
from replay import source_check,data_bytes
from complete_profiles import verify as verify_fixed_profiles
from baseline_checks import ordinary_bfs
from checker import reference_step


def read(p):return json.loads(data_bytes(p))


def verify_case_consumer(consumer):
    """Check saved witnesses/counts, not merely the final classification."""
    total=agreeing=0;seen=set()
    for batch in consumer['batches']:
        count=batch['contexts'];ids=batch['source_context_ids']
        if (type(count) is not int or not 1<=count<=16 or type(batch['first_context']) is not int or batch['first_context']!=total
                or len(ids)!=count or len(set(ids))!=count or seen.intersection(ids)):
            raise ValueError('case property identifiers or contiguous denominator differ')
        seen.update(ids)
        p=batch['policy'];m=batch['machine']
        if p['aliases'] or p['state'] or len(m['observations'])!=1 or m['observations']!=[0] or len(m['alphabet'])!=count:
            raise ValueError('case is not the stated complete reset-context encoding')
        result=diagnose_source_family(p,m)
        expected=dict(classification=result['classification'],algorithms_agree=result['algorithms_agree'],
            matching_bindings=result['matching_bindings'],shortest_length=result['profiles'][0]['length'],
            shortest_witness=result['profiles'][0]['trace'],ordinary_BFS=ordinary_bfs(p,m))
        expected=json.loads(json.dumps(expected))
        if any(json.dumps(batch.get(key),sort_keys=True)!=json.dumps(value,sort_keys=True) for key,value in expected.items()):
            raise ValueError('complete case classification/membership/witness/BFS evidence differs')
        for i,request in enumerate(m['alphabet']):
            decision,post=reference_step(p,0,request,{})
            actual,next_state=m['transitions'][0][i]
            agreeing+=decision==actual and post==m['observations'][next_state]
        total+=count
    if (any(type(consumer[k]) is not int for k in ('context_properties','table_batches','agreeing_properties','nonagreeing_properties'))
            or consumer['context_properties']!=total or consumer['table_batches']!=len(consumer['batches'])
            or consumer['agreeing_properties']!=agreeing or consumer['nonagreeing_properties']!=total-agreeing):
        raise ValueError('case aggregate counts disagree with actual complete property cells')
    return total


def verify():
    manifest=read(ROOT/'MANIFEST.json')
    for rel,h in manifest['files'].items():
        p=(ROOT/rel).resolve()
        if not p.is_relative_to(ROOT) or hashlib.sha256(p.read_bytes()).hexdigest()!=h:raise ValueError('study input differs: '+rel)
        if rel.endswith('.json.gz'):json.loads(gzip.decompress(p.read_bytes()))
    source_check()
    family=read(ROOT/'data/credential-family.json');bindings=matching=0
    for c in family['cases']:
        r=diagnose_source_family(c['policy'],c['machine'])
        if json.loads(json.dumps(r))!=c['diagnosis']:raise ValueError('source credential family diagnosis differs')
        bindings+=r['bindings'];matching+=r['matching_bindings']
    idx=read(ROOT/'data/cases/index.json');properties=0;unknown=0
    for row in idx['cases']:
        path=ROOT/'data/cases'/Path(row['file']).name
        if hashlib.sha256(data_bytes(path)).hexdigest()!=row['sha256']:raise ValueError('case index binding differs')
        c=read(path);d=c['existing_checker_consumer']
        if d.get('status')=='unknown':unknown+=1;continue
        properties+=verify_case_consumer(d)
    if bindings!=112 or matching!=8 or unknown!=1 or len(idx['cases'])!=8:raise ValueError('fixed study denominator differs')
    historical=read(ROOT/'data/historical-scope.json')
    if historical['fixed_cases']!=20 or historical['unclassified_cases']:raise ValueError('historical dispositions incomplete')
    fixed=verify_fixed_profiles()
    return dict(source_functions=10,credential_contexts=1260,credential_bindings=bindings,matching_bindings=matching,
        deep_cases=8,conditional_semantic_cases=7,explicit_unknown_cases=unknown,finite_reset_context_properties=properties,
        historical_dispositions=20,independent_gold_accepted=False,full_applications_certified=False,
        all_supplied_family_algorithms_agree=True,complete_case_witnesses_counts_and_BFS_verified=True,
        current_fixed_source_profiles=fixed)


if __name__=='__main__':print(json.dumps(verify(),indent=2))
