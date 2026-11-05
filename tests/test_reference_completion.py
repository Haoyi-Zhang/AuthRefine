"""Owned normal-data checks for the explicit post-exposure contracts."""
import ast,copy,gzip,hashlib,json
from pathlib import Path
import sys,unittest
ART=Path(__file__).resolve().parents[1]
HERE=ART/'reference_completion' if (ART/'reference_completion').exists() else Path(__file__).resolve().parent
if (HERE/'inputs.json.gz').exists():
    sys.path.insert(0,str(HERE.parent))
    from reference_completion.replay import execute,load,run
    from reference_completion.interpreter import (AdmissionError,Capability,DataRecord,Interpreter,SliceFault,body_dump,program_for,declarations)
    from reference_completion.contracts import reference
else:
    sys.path.insert(0,str(HERE))
    from replay import execute,load,run
    from interpreter import (AdmissionError,Capability,DataRecord,Interpreter,SliceFault,body_dump,program_for,declarations)
    from contracts import reference

class ContractCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.data=load(HERE/('inputs.json.gz' if (HERE/'inputs.json.gz').exists() else 'public-inputs.json.gz'))
    def contract(self,q,repo=None):return next(r for r in self.data['references']['contracts'] if r['function']==q and (repo is None or r['repository']==repo))
    def execute(self,q,inputs,control=None,repo=None):
        c=self.contract(q,repo);context=next(v for v in c['contexts'] if v['inputs']==inputs)
        return execute(self.data['sources'][c['source_key']],c,context,control)
    def test_original_sixty_are_distinct_entry_bindings(self):
        rows=self.data['references']['contracts'];self.assertEqual(len(rows),60)
        self.assertEqual(len({(r['repository'],r['path'],r['function']) for r in rows}),60)
        self.assertEqual(sum(r['disposition']=='abstract_protocol' for r in rows),2)
        self.assertTrue(all(not r['reference_is_intent_gold'] for r in rows))
    def test_reference_equations_reconstruct_every_expected_context(self):
        for c in self.data['references']['contracts']:
            for v in c['contexts']:
                actual=reference(c,v['inputs']);expected=(v['expected'],v['state'],v['call_counts'],v['call_order'])
                if c['id']=='boundary-35' and v['id']=='normal-040':actual=({'kind':'error','name':'AttributeError'},*actual[1:])
                self.assertEqual(actual,expected)
    def test_public_packet_does_not_redistribute_enterprise_source(self):
        self.assertEqual(len(self.data['sources']),19)
        self.assertFalse(any(':enterprise/' in key for key in self.data['sources']))
        self.assertEqual(sum(r['source_distribution']=='separate_local_source' for r in self.data['references']['contracts']),1)
    def test_every_source_and_complete_body_identity(self):
        for c in self.data['references']['contracts']:
            if c['source_key'] not in self.data['sources']:continue
            source=self.data['sources'][c['source_key']]['text'];self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),c['source_sha256'])
            n=dict(declarations(source))[c['function']];self.assertEqual(hashlib.sha256(body_dump(n).encode()).hexdigest(),c['body_ast_sha256'])
    def test_tenant_write_is_observed_not_only_return_value(self):
        q='TenantScopedJWTAuthentication.authenticate';i={'company':7}
        self.assertEqual(self.execute(q,i)['status'],'agree');bad=self.execute(q,i,'drop_tenant')
        self.assertEqual(bad['status'],'mismatch');self.assertEqual(bad['state']['selected_company'],None)
    def test_persisted_share_readback_detects_dropped_save(self):
        q='CustomIsShare.has_object_permission';c=self.contract(q)
        i=next(v['inputs'] for v in c['contexts'] if v['inputs'].get('share')=='share-normal' and v['inputs'].get('share_count')==1 and v['inputs'].get('repeat')==2)
        self.assertEqual(self.execute(q,i)['status'],'agree')
        self.assertEqual(self.execute(q,i,'drop_save')['status'],'mismatch')
    def test_repeated_share_detects_cache_loss(self):
        q='CustomIsShare.has_object_permission';c=self.contract(q)
        i=next(v['inputs'] for v in c['contexts'] if v['inputs'].get('share')=='share-normal' and v['inputs'].get('share_count')==1 and v['inputs'].get('repeat')==2)
        result=self.execute(q,i,'drop_cache');self.assertEqual(result['status'],'mismatch');self.assertEqual(result['call_counts']['share.save'],2)
    def test_wrong_object_identity_is_not_a_matching_policy(self):
        inputs={'authenticated':True,'method':'GET','owner':True}
        self.assertEqual(self.execute('CustomIsOwner.has_object_permission',inputs)['status'],'agree')
        self.assertEqual(self.execute('CustomIsOwner.has_object_permission',inputs,'wrong_identity')['status'],'mismatch')
    def test_scheduled_and_awaited_activity_are_distinct(self):
        jwt=self.execute('get_current_user',{});api=self.execute('get_current_user_by_api_key',{})
        self.assertEqual(jwt['state']['scheduled_active'],['u1']);self.assertEqual(jwt['state']['active_updates'],[])
        self.assertEqual(api['state']['scheduled_active'],[]);self.assertEqual(api['state']['active_updates'],['u1'])
    def test_concrete_source_error_not_dropped_as_unknown(self):
        result=self.execute('CustomIsHousehold.has_object_permission',{'orphan':True,'owner':False})
        self.assertEqual(result['outcomes'],[{'kind':'error','name':'AttributeError'}]);self.assertEqual(result['status'],'agree')
    def test_preview_error_mapping_retains_actual_status_and_code(self):
        result=self.execute('BuilderPreviewAuthentication.authenticate',{})
        self.assertEqual(result['outcomes'],[{'kind':'error','name':'APIException','status':401,'code':'ERROR_BUILDER_PREVIEW_SESSION_INVALID'}])
    def test_source_exception_handler_cannot_swallow_unknown(self):
        text='def f():\n try:\n  return dependency.missing\n except Exception:\n  return True\n'
        program,key=program_for(text,'f');m=Interpreter(program,{'dependency':DataRecord('External',{})})
        with self.assertRaises(AdmissionError):m.run(key,[])
    def test_reached_import_never_executes(self):
        program,key=program_for('def f():\n import os\n return True\n','f')
        with self.assertRaises(AdmissionError):Interpreter(program,{}).run(key,[])
    def test_host_attributes_never_exposed(self):
        program,key=program_for('def f(x):\n return x.__class__\n','f')
        with self.assertRaises(AdmissionError):Interpreter(program,{}).run(key,[object()])
    def test_budget_exhaustion_is_not_a_source_denial(self):
        program,key=program_for('def f():\n return f()\n','f')
        with self.assertRaises(AdmissionError):Interpreter(program,{}).run(key,[])
    def test_source_tampering_rejected_before_interpretation(self):
        c=self.contract('CustomIsOwner.has_permission');source=copy.deepcopy(self.data['sources'][c['source_key']]);source['text']+='\n'
        with self.assertRaises(ValueError):execute(source,c,c['contexts'][0])
    def test_default_replay_reports_missing_source_instead_of_passing(self):
        subset=copy.deepcopy(self.data);row=next(c for c in subset['references']['contracts'] if c['source_distribution']=='separate_local_source')
        subset['references']['contracts']=[row];result=run(subset)
        self.assertEqual(result['concrete_agree'],0);self.assertEqual(result['separate_source_required'],1)
    def test_no_effect_after_source_denial(self):
        c=self.contract('TenantScopedJWTAuthentication.authenticate');v=next(v for v in c['contexts'] if v['inputs']=={'company':None})
        result=execute(self.data['sources'][c['source_key']],c,v)
        self.assertEqual(result['status'],'agree');self.assertEqual(result['call_counts']['set_company'],0)
if __name__=='__main__':unittest.main()
