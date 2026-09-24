
import sys,unittest,json,collections,traceback
counts=collections.Counter(); files=collections.Counter()
def prof(frame,event,arg):
    if event=='call':
        name=frame.f_code.co_name.lower(); fn=frame.f_code.co_filename
        if any(x in name for x in ('quotient','partition','observation','minimi')):
            counts[name]+=1;files[fn]+=1
    return prof
sys.setprofile(prof)
suite=unittest.defaultTestLoader.discover('tests')
r=unittest.TextTestRunner(verbosity=0).run(suite)
sys.setprofile(None)
print('PROFILE_JSON='+json.dumps({'ok':r.wasSuccessful(),'testsRun':r.testsRun,'function_calls':dict(counts),'files':dict(files)},sort_keys=True))
raise SystemExit(0 if r.wasSuccessful() else 1)
