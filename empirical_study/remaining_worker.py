"""Run one isolated arm of selected reviewed source/caller capsules."""
import ast,json,sys,time
from pathlib import Path
sys.path[:0]=['/owned','/deps']
from delegated_runtime import install,admit,Unknown,capture_unknowns
from remaining_worlds import World

def observe(world,fn):
    with capture_unknowns() as unresolved:
        try:result=dict(status='value',value=world.pack(fn()))
        except Unknown as ex:result=dict(status='unsupported',reason=str(ex))
        except Exception as ex:
            result=dict(status='source_exception',exception=type(ex).__name__)
            if hasattr(ex,'status_code'):result['status_code']=ex.status_code
            if isinstance(ex,(TypeError,AttributeError,NameError)):result['diagnostic']=str(ex)
    return dict(status='unsupported',reason='; '.join(unresolved)) if unresolved else result

def main():
    mode=sys.argv[1];payload=json.loads(Path('/inputs.json').read_text());rows=[]
    if mode not in ('preflight','native','model'):raise ValueError('arm')
    for case in payload['cases']:
        observations=[]
        for sample in case['samples']:
            try:
                start=time.perf_counter_ns();world=World(case,sample);prepare_ns=time.perf_counter_ns()-start
                for row in case['functions']:admit(row,world.allowed_imports)
                if mode=='preflight':
                    observations.append(dict(id=sample['id'],source_executed=False));continue
                start=time.perf_counter_ns();install(case['functions'],world,mode);install_ns=time.perf_counter_ns()-start
                start=time.perf_counter_ns();result=observe(world,world.invoke);execution_ns=time.perf_counter_ns()-start
                expected=sample['expected'];agree=all(result.get(k)==v for k,v in expected.items())
                observations.append(dict(id=sample['id'],result=result,provider_trace=world.trace,state=world.snapshot(),
                    draft_reference=expected,draft_reference_agree=agree,prepare_ns=prepare_ns,install_ns=install_ns,execution_ns=execution_ns))
            except Unknown as ex:observations.append(dict(id=sample['id'],result=dict(status='unsupported',reason=str(ex)),complete=False))
            except Exception as ex:observations.append(dict(id=sample['id'],result=dict(status='harness_error',exception=type(ex).__name__,message=str(ex)),complete=False))
        rows.append(dict(project=case['project'],entry=case['entry'],provider_boundary=case['provider_boundary'],observations=observations))
    print(json.dumps(dict(mode=mode,rows=rows,source_application_modules_imported=False,network_requests=0,model_requests=0),separators=(',',':')))

if __name__=='__main__':main()
