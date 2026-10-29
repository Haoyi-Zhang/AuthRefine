"""Independent-contract / measured-output consumers for finite reset contexts.

This is a transparent table encoding, NOT a new source compiler, inferred intent,
or a proof about arbitrary source states. Each input is a complete owned normal
context reset before evaluation. The guard-field/property observations enter the
existing checker under one fixed interpretation; request-local output/state
identities are checked in the native evidence readers, not erased by this model.
"""
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parents[1]/'src'))
from baseline_checks import ordinary_bfs
from language import normalize
from source_family import diagnose_source_family


def diagnose_observations(rows):
    if not rows or len({r['id'] for r in rows})!=len(rows):raise ValueError('distinct nonempty complete normal contexts required')
    outputs=[]
    for start in range(0,len(rows),16):
        batch=rows[start:start+16]
        if any(type(r['expected']) is not bool or type(r['observed']) is not bool for r in batch):
            raise ValueError('Boolean observation projection required')
        names={r['id']:f'context-{i:06d}' for i,r in enumerate(batch,start)}
        p=normalize(dict(principals=list(names.values()),resources=['property'],actions=['observe'],roles=[],members=[],state=[],aliases=[],
            rules=[dict(decision='allow',guard=[dict(field='principal',name=names[r['id']],negated=False)],updates=[])
                   for r in batch if r['expected']]))
        values={names[r['id']]:r['observed'] for r in batch}
        domain=[[n,'property','observe'] for n in p['principals']]
        m=dict(state_names=[],alphabet=domain,observations=[0],initial=0,
            transitions=[[['allow' if values[n] else 'deny',0] for n in p['principals']]])
        result=diagnose_source_family(p,m);bfs=ordinary_bfs(p,m)
        equivalent=all(r['expected']==r['observed'] for r in batch)
        if (result['classification']=='all')!=equivalent or bfs['equivalent']!=equivalent:
            raise ValueError('finite observation/checker disagreement')
        outputs.append(dict(first_context=start,contexts=len(batch),source_context_ids=[r['id'] for r in batch],
            policy=p,machine=m,classification=result['classification'],algorithms_agree=result['algorithms_agree'],
            matching_bindings=result['matching_bindings'],shortest_length=result['profiles'][0]['length'],
            shortest_witness=result['profiles'][0]['trace'],ordinary_BFS=bfs))
    return dict(context_properties=len(rows),table_batches=len(outputs),
        agreeing_properties=sum(r['expected']==r['observed'] for r in rows),
        nonagreeing_properties=sum(r['expected']!=r['observed'] for r in rows),batches=outputs,
        mapping='owned complete reset-context identifier -> finite principal; no claim this is the upstream application principal type',
        family='one explicitly stated contract; no ambiguity candidates invented',
        persistent_state='one observation under reset-per-context and immutable guard-field stores',
        extraction_soundness_or_unseen_state_theorem=False)
