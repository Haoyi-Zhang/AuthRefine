"""One reviewed project in a fresh isolated process; normal fixtures only."""
import json,os,sys,time
from pathlib import Path
sys.path[:0]=['/owned','/deps','/framework']
from delegated_runtime import install,finish,Unknown
from scope_followup_worlds import FollowupWorld
from remaining_worker import observe
def main():
    arm,project=sys.argv[1:];payload=json.loads(Path('/inputs.json').read_text())
    case=next(c for c in payload['cases'] if c['project']==project);rows=[]
    for sample in case['samples']:
        entered=set()
        def profile(frame,event,arg):
            if event=='call' and frame.f_code.co_filename in ('<reviewed-authorization-capsule>','<source-token-class>'):entered.add(frame.f_code.co_name)
        try:
            start=time.perf_counter_ns();w=FollowupWorld(case,sample);install(case['functions'],w,arm)
            sys.setprofile(profile)
            try:
                result=observe(w,w.invoke)
            finally:sys.setprofile(None)
            rows.append(dict(id=sample['id'],result=result,trace=w.trace,state=w.snapshot(),entered=sorted(entered),elapsed_ns=time.perf_counter_ns()-start))
        except (Exception,Unknown) as ex:
            sys.setprofile(None);rows.append(dict(id=sample['id'],result=dict(status='harness_error',exception=type(ex).__name__,diagnostic=str(ex))))
    print(json.dumps(dict(project=project,arm=arm,observations=rows,uid=os.getuid(),python=sys.version,hash_seed=os.environ.get('PYTHONHASHSEED'),hash_seed_probe=hash('reader'),model_calls=0,network_requests=0),separators=(',',':')))
if __name__=='__main__':main()
