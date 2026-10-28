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


def read(p):return json.loads(data_bytes(p))


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
        for b in d['batches']:
            r=diagnose_source_family(b['policy'],b['machine'])
            if r['classification']!=b['classification'] or not r['algorithms_agree']:raise ValueError('finite case consumer differs')
            properties+=b['contexts']
    if bindings!=112 or matching!=8 or unknown!=1 or len(idx['cases'])!=8:raise ValueError('fixed study denominator differs')
    historical=read(ROOT/'data/historical-scope.json')
    if historical['fixed_cases']!=20 or historical['unclassified_cases']:raise ValueError('historical dispositions incomplete')
    return dict(source_functions=10,credential_contexts=1260,credential_bindings=bindings,matching_bindings=matching,
        deep_cases=8,conditional_semantic_cases=7,explicit_unknown_cases=unknown,finite_reset_context_properties=properties,
        historical_dispositions=20,independent_gold_accepted=False,full_applications_certified=False,
        all_supplied_family_algorithms_agree=True)


if __name__=='__main__':print(json.dumps(verify(),indent=2))
