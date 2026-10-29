"""Replay actual owned repair candidates over the unchanged normal contexts."""
import argparse
import gzip
import hashlib
from itertools import product
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'code'),str(ROOT.parent/'src')]
from boundary_repairs import repair_file_store, repair_sync_guard
from persistent_store import compare_store
from source_save_store import compare_repaired_store
from request_outcomes import compare_request_outcomes
from native_runtime import engine_identity
from wire_boundary_profile import bind_sources, message_type, wire_case


class BoundSourceDirectory:
    """Explicit selected source directory, not an original archive-byte claim."""
    def __init__(self,name):
        self.root=ROOT/'source/repair-profiles'/name
        binding=json.loads((self.root.parent/'bindings.json').read_text(encoding='utf-8'))[name]
        self.archive=SimpleNamespace(comment=binding['snapshot'].encode())
        self.files=binding['files']
        for member,expected in self.files.items():
            if hashlib.sha256((self.root/member).read_bytes()).hexdigest()!=expected:
                raise ValueError('bound repair source differs: '+member)
    def read(self,member):
        if member not in self.files:raise ValueError('unbound source request')
        return (self.root/member).read_bytes()


def store_summary(result):
    keys=['accepted','policy','machine','comparison','native_operations','table_cells','descriptor']
    keys += [k for k in ('source_candidate_descriptor','save_effect_from_candidate_source',
        'external_save_toggle_supplied','historical_kernel_timings_not_claimed_as_current_adapter_timings') if k in result]
    return {key:result[key] for key in keys}


def run():
    if engine_identity()['profile']!='casbin-1.43.0':raise ValueError('use the selected isolated native profile')
    source=BoundSourceDirectory('conclave')
    guard=source.read('backend/app/rbac/deps.py')
    model=source.read('backend/app/rbac/model.conf').decode('utf-8-sig')
    original_guard=compare_request_outcomes(guard,model)
    candidate_guard=repair_sync_guard(guard,native_result_protocol='synchronous_boolean')
    repaired_guard=compare_request_outcomes(candidate_guard,model)
    # The actual native consumer confirms the Boolean result on every measured
    # call; source provider construction remains the separately stated entry.
    if (original_guard['cases']!=1176 or repaired_guard['cases']!=1176
            or not original_guard['source_protocol_error_cases'] or not repaired_guard['comparison']['accepted']
            or repaired_guard['different_case_observations']):raise ValueError('guard candidate did not close its contract')
    source=BoundSourceDirectory('conet')
    store=source.read('src/conet/control/policy.py')
    model=source.read('src/conet/control/policy_model.conf').decode()
    rows=[['finance','invoice.verify','invoke'],['marketing','research.find_leads','invoke'],['marketing','invoice.verify','invoke']]
    original_store=compare_store(store,model,rows,initial=3)
    candidate_store=repair_file_store(store)
    repaired_store=compare_repaired_store(candidate_store,model,rows,initial=3)
    if (original_store['table_cells']!=768 or repaired_store['table_cells']!=768
            or original_store['accepted'] or not repaired_store['accepted'] or repaired_store['external_save_toggle_supplied']
            or not repaired_store['save_effect_from_candidate_source']):
        raise ValueError('source-pinned explicit-save candidate did not close its contract')
    source=BoundSourceDirectory('iot')
    descriptor,proto,_,projection=bind_sources(source,with_projection=True)
    cls,runtime=message_type(descriptor,proto)
    chars=((),('',),('operator',),('operator','reviewer'),('','operator',''),('viewer','viewer'))
    descriptions=((),('',),('read pressure',),('first','second'),('','valid'))
    records=[]
    for ch,desc,priority,issuer in product(chars,descriptions,(0,7),('owned-user-a','owned-user-b')):
        before=wire_case(cls,ch,desc,priority,issuer,projection=projection)
        after=wire_case(cls,ch,desc,priority,issuer,projection=projection,boundary_repair=True)
        if after['different_fields']:raise ValueError('schema-aware repeated-field candidate differs')
        records.append(dict(original=before,repaired=after))
    different=sum(bool(r['original']['different_fields']) for r in records)
    if different!=104 or len(records)!=120:raise ValueError('fixed wire denominator changed')
    return dict(scope='Three exposed development source profiles,not new applications or deployment repairs.',
        source_modules_upstream_tests_services_or_exploits_executed=False,
        Conclave=dict(contexts=1176,original=original_guard,repaired=repaired_guard,
            candidate_source=candidate_guard.decode(),original_source_unchanged=True),
        Conet=dict(table_cells=768,original=store_summary(original_store),repaired=store_summary(repaired_store),
            candidate_source=candidate_store.decode(),original_source_unchanged=True),
        IoT=dict(contexts=120,original_different_records=different,repaired_different_records=0,
            native_encode_decode_pairs=240,records=records,original_source_unchanged=True),
        native_profiles=dict(policy='casbin-1.43.0',wire='protobuf-6.32.1'))


def verify():
    actual=json.loads(json.dumps(run()))
    expected=json.loads(gzip.decompress((ROOT/'data/repair-profiles.json.gz').read_bytes()))
    if actual!=expected:raise ValueError('actual repair consumer differs from the recorded candidate evidence')
    return dict(Conclave_contexts=actual['Conclave']['contexts'],
        Conclave_original_different_contexts=actual['Conclave']['original']['different_case_observations'],
        Conclave_repaired_different_contexts=actual['Conclave']['repaired']['different_case_observations'],
        Conet_table_cells=actual['Conet']['table_cells'],Conet_repaired_accepted=actual['Conet']['repaired']['accepted'],
        IoT_contexts=actual['IoT']['contexts'],IoT_original_different_records=actual['IoT']['original_different_records'],
        IoT_repaired_different_records=0,original_source_unchanged=True,source_applications_executed=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--record',type=Path);args=parser.parse_args()
    if args.record:
        value=run()
        if args.record.exists():raise ValueError('record path must be fresh')
        args.record.parent.mkdir(parents=True,exist_ok=True)
        args.record.write_bytes(gzip.compress((json.dumps(value,indent=2)+'\n').encode(),mtime=0))
        print(json.dumps(dict(recorded_profiles=3,Conclave_cases=1176,Conet_cells=768,IoT_cases=120)))
    else:print(json.dumps(verify(),indent=2))
