"""Replay complete selected source bodies as data, against frozen references."""
import argparse,ast,gzip,hashlib,json
from pathlib import Path
import sys
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
if __package__:
    from .interpreter import Interpreter,program_for,body_dump,declarations,SliceFault,AdmissionError
    from .profiles import World,setup
    from .observations import typed_equal,check_handoffs,source_constants
else:
    from interpreter import Interpreter,program_for,body_dump,declarations,SliceFault,AdmissionError
    from profiles import World,setup
    from observations import typed_equal,check_handoffs,source_constants
def digest(b):return hashlib.sha256(b).hexdigest()
def encoded(d):return json.dumps(d,ensure_ascii=True,sort_keys=True,indent=2).encode()+b'\n'
def load(p):return json.loads(gzip.decompress(Path(p).read_bytes()))
def execute(source,contract,context,control=None):
    if digest(source['text'].encode())!=contract['source_sha256']:raise ValueError('consumed source identity mismatch')
    node=dict(declarations(source['text']))[contract['function']]
    if digest(body_dump(node).encode())!=contract['body_ast_sha256']:raise ValueError('consumed complete body mismatch')
    w=World(context['inputs'],control)
    try:
        helpers,bindings,args=setup(w,contract)
        program,key=program_for(source['text'],contract['function'],helpers)
        if body_dump(program[key])!=body_dump(node):raise ValueError('entry body rewritten')
        if 'helper_bindings' in contract:
            bound={n:digest(body_dump(program[n.replace('.','__')]).encode()) for n in helpers}
            if bound!=contract['helper_bindings']:raise ValueError('complete helper-body binding differs')
        w.machine=Interpreter(program,bindings,control)
        outcomes=[]
        for _ in range(context['inputs'].get('repeat',1)):
            try:outcomes.append(w.outcome(w.machine.run(key,args)))
            except SliceFault as fault:outcomes.append(w.outcome(fault=fault))
        state=w.snapshot();counts={name:sum(e['call']==name for e in w.events) for name in context['call_counts']}
        observed_order=[e['call'] for e in w.events if e['call'] in context['call_order']]
        state_actual={k:state['cache'].get(k[6:]) if k.startswith('cache:') else state.get(k) for k in context['state']}
        # A successful cached second share read does not increment/save twice.
        violations,checked=check_handoffs(contract,context['inputs'],w.events)
        same=all(typed_equal(v,context['expected']) for v in outcomes) and typed_equal(counts,context['call_counts']) and typed_equal(observed_order,context['call_order']) and typed_equal(state_actual,context['state']) and not violations
        return dict(status='agree' if same else 'mismatch',outcomes=outcomes,state=state,checked_state=state_actual,call_counts=counts,call_order=observed_order,events=w.events,argument_violations=violations,argument_operations_checked=checked,complete_helpers=helpers,source_calls=w.machine.function_calls,steps=w.machine.steps if hasattr(w.machine,'steps') else None)
    except AdmissionError as e:return dict(status='unknown',reason=str(e))
    finally:w.close()
def run(packet,control=None):
    rows=[]
    source_constants(packet)
    if len({c['id'] for c in packet['references']['contracts']})!=len(packet['references']['contracts']):raise ValueError('duplicate reference entry IDs')
    for contract in packet['references']['contracts']:
        source=packet['sources'].get(contract['source_key'])
        contexts=[dict(id=c['id'],**execute(source,contract,c,control)) for c in contract['contexts']] if source else []
        status='requires_separate_local_source' if source is None else 'unknown' if not contexts else 'agree' if all(c['status']=='agree' for c in contexts) else 'mismatch' if any(c['status']=='mismatch' for c in contexts) else 'unknown'
        rows.append(dict(id=contract['id'],repository=contract['repository'],path=contract['path'],function=contract['function'],disposition=contract['disposition'],status=status,contexts=contexts))
    return dict(post_exposure_followup=True,source_application_code_executed=False,control=control,
        concrete_agree=sum(r['status']=='agree' and r['disposition']=='concrete_reference' for r in rows),
        abstract_protocol_checked=sum(r['status']=='agree' and r['disposition']=='abstract_protocol' for r in rows),
        unknown=sum(r['status']=='unknown' for r in rows),mismatch=sum(r['status']=='mismatch' for r in rows),
        separate_source_required=sum(r['status']=='requires_separate_local_source' for r in rows),rows=rows)
def main():
    p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,default=HERE/'inputs.json.gz');p.add_argument('--output',type=Path);p.add_argument('--control',choices=['wrong_identity','drop_save','drop_cache','drop_tenant','wrong_object','wrong_token','wrong_scope','wrong_query','wrong_cache_target']);p.add_argument('--external-source',type=Path);p.add_argument('--check',action='store_true');a=p.parse_args()
    packet=load(a.inputs)
    if a.external_source:
        row=next(c for c in packet['references']['contracts'] if c['source_distribution']=='separate_local_source')
        text=a.external_source.read_text(encoding='utf-8');packet['sources'][row['source_key']]={'text':text}
    result=run(packet,a.control)
    if a.output:a.output.write_bytes(encoded(result))
    if a.check:
        recorded=load(HERE/'results.json.gz')
        if a.external_source:
            expected=load(HERE/'external-source-results.json.gz')
            recorded['rows']=[expected if r['id']==expected['id'] else r for r in recorded['rows']]
            recorded['concrete_agree']+=1;recorded['separate_source_required']-=1
        if result!=recorded:raise SystemExit('recorded reconstruction differs')
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}))
    if result['mismatch'] or result['unknown']:raise SystemExit(1)
if __name__=='__main__':main()
