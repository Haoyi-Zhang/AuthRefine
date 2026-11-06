"""Fresh isolated normal-path replay;dependency preparation is separate and explicit."""
import argparse,json,os,subprocess,sys,tempfile,time
from pathlib import Path
from verify import ROOT,load,verify,exact
CODE=['predicate_runtime.py','delegated_runtime.py','remaining_worlds.py','remaining_worker.py','scope_followup_worlds.py','scope_followup_worker.py']
def base():
    return ['bwrap','--unshare-all','--die-with-parent','--new-session','--cap-drop','ALL','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--size','33554432','--tmpfs','/tmp']
def main():
    p=argparse.ArgumentParser();p.add_argument('--engine-site',type=Path,required=True);p.add_argument('--framework-site',type=Path,required=True);p.add_argument('--healthchecks-django',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--suite',choices=('all','primary','delegated','extensions'),default='all')
    a=p.parse_args()
    if not sys.platform.startswith('linux') or os.getuid()==0:raise ValueError('non-root Linux with bubblewrap required')
    verify();inputs=load('inputs.json.gz');stored=load('observations.json.gz');a.output.mkdir(parents=True,exist_ok=True)
    if any(a.output.iterdir()):raise ValueError('use a new empty output directory')
    count=0
    with tempfile.TemporaryDirectory(prefix='authrefine-normal-') as temp:
        t=Path(temp)
        if a.suite in ('all','primary'):
            path=t/'primary.json';path.write_text(json.dumps(inputs['primary']),encoding='utf-8')
            for repeat in (1,2,3):
                cmd=base()+['--ro-bind',str(path),'/inputs.json','--ro-bind',str(ROOT/'predicate_runtime.py'),'/owned/predicate_runtime.py','--clearenv','prlimit','--as=268435456','--cpu=20','--','/usr/bin/python3','-I','-S','-B','/owned/predicate_runtime.py','/inputs.json']
                r=subprocess.run(cmd,capture_output=True,timeout=45,env={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8'})
                if r.returncode or r.stderr:raise ValueError(r.stderr.decode(errors='replace'))
                actual=json.loads(r.stdout);old=stored['primary'][repeat-1]
                if not exact([x['observations'] for x in actual['rows']],[x['observations'] for x in old['rows']]):raise ValueError('pure-predicate scientific difference')
                filename=f'primary-{repeat}.json';(a.output/filename).write_text(json.dumps(actual,indent=2)+'\n',encoding='utf-8');count+=1
                print(json.dumps(dict(file=filename,scientific_observations_agree=True)),flush=True)
        for label in ('delegated','extensions'):
            if a.suite not in ('all',label):continue
            path=t/(label+'.json');path.write_text(json.dumps(inputs[label]),encoding='utf-8')
            cases=inputs[label]['cases']
            for repeat in (1,2,3):
                for project in ([None] if label=='delegated' else [c['project'] for c in cases]):
                    for arm in (['native','model'] if repeat%2 else ['model','native']):
                        cmd=base()+['--ro-bind',str(path),'/inputs.json']
                        for n in CODE:cmd+=['--ro-bind',str(ROOT/n),'/owned/'+n]
                        cmd+=['--ro-bind',str(a.framework_site.resolve()),'/framework']
                        if project=='R04':cmd+=['--ro-bind',str(a.healthchecks_django.resolve()),'/framework/django']
                        for n in ('casbin','simpleeval.py','sqlalchemy','typing_extensions.py'):
                            q=a.engine_site/n
                            if q.exists():cmd+=['--ro-bind',str(q.resolve()),'/deps/'+n]
                        worker='remaining_worker.py' if label=='delegated' else 'scope_followup_worker.py'
                        cmd+=['--clearenv','--setenv','LC_ALL','C.UTF-8','--setenv','PYTHONHASHSEED','0','prlimit','--as=805306368','--cpu=45','--nproc=128','--nofile=128','--','/usr/bin/python3','-S','-B','/owned/'+worker,arm]
                        if project:cmd.append(project)
                        start=time.perf_counter_ns();r=subprocess.run(cmd,capture_output=True,timeout=60,env={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8'})
                        if r.returncode or r.stderr:raise ValueError(r.stderr.decode(errors='replace'))
                        actual=json.loads(r.stdout);filename=f'{label}-{project or "all"}-{arm}-{repeat}.json'
                        (a.output/filename).write_text(json.dumps(dict(wall_ns=time.perf_counter_ns()-start,output=actual),indent=2)+'\n',encoding='utf-8')
                        rows=actual['rows'] if label=='delegated' else [dict(project=project,observations=actual['observations'])]
                        for row in rows:
                            old=next(x for x in stored[label] if x['project']==row['project'] and x['arm']==arm and x['repeat']==repeat)
                            keys=('id','result','provider_trace','state') if label=='delegated' else ('id','result','trace','state')
                            normal=lambda rs:[{k:x[k] for k in keys} for x in rs]
                            if not exact(normal(row['observations']),normal(old['observations'])):raise ValueError('fresh scientific observation differs:'+filename)
                        count+=1;print(json.dumps(dict(file=filename,scientific_observations_agree=True)),flush=True)
    print(json.dumps(dict(fresh_isolated_runs=count,model_requests=0,scope='selected source bodies and declared providers;not whole applications')))
if __name__=='__main__':main()
