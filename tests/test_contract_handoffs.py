"""Exact parameter,source-helper and typed-observation controls on owned data."""
import copy,sys,unittest
from pathlib import Path
ART=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ART))
from reference_completion.replay import execute,load,run
from reference_completion.contracts import reference
from reference_completion.observations import typed_equal,source_constants
from reference_completion.profiles import World
from reference_completion.interpreter import AdmissionError,program_for
class ContractHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.packet=load(ART/'reference_completion/inputs.json.gz')
    def selected(self,q,inputs,control=None):
        c=next(c for c in self.packet['references']['contracts'] if c['function']==q)
        v=next(v for v in c['contexts'] if v['inputs']==inputs)
        return execute(self.packet['sources'][c['source_key']],c,v,control)
    def detected(self,q,i,control,operation):
        self.assertEqual(self.selected(q,i)['status'],'agree')
        bad=self.selected(q,i,control);self.assertEqual(bad['status'],'mismatch')
        self.assertIn(operation,[v['call'] for v in bad['argument_violations']])
    def test_wrong_object_not_hidden_by_same_return_and_count(self):self.detected('HasProjectPerm.check_permissions',{'permission':True,'admin':True},'wrong_object','permission')
    def test_wrong_token_not_hidden_by_same_authentication_result(self):self.detected('JSONWebTokenAuthentication.authenticate',{},'wrong_token','profile_token_valid')
    def test_wrong_permission_name_is_observed(self):self.detected('get_current_user_by_api_key',{},'wrong_scope','api_permission')
    def test_wrong_query_target_not_hidden_by_same_exists_result(self):self.detected('CustomIsHousehold.has_object_permission',{'household':True},'wrong_query','household.filter')
    def test_wrong_cache_scope_not_hidden_by_same_group_result(self):self.detected('CustomIsGuest.has_permission',{'groups':['user'],'method':'GET'},'wrong_cache_target','cache.get')
    def test_boolean_integer_not_the_same_observation(self):
        self.assertFalse(typed_equal({'value':True},{'value':1}));self.assertFalse(typed_equal({'value':False},{'value':0}))
    def test_tuple_and_list_not_the_same_observation(self):
        w=World({})
        try:self.assertFalse(typed_equal(w.normalize((1,2)),w.normalize([1,2])))
        finally:w.close()
    def test_imported_literals_are_read_from_original_definitions(self):
        self.assertEqual(source_constants(self.packet),{'USER_SOURCE_CLAIM':'user_source_uid','AuthenticateUserSourceOperationType.type':'application.user_source.authenticate'})
    def test_representative_imported_literal_cannot_replace_source_definition(self):
        p=copy.deepcopy(self.packet)
        c=next(c for c in p['references']['contracts'] if c['function']=='UserSourceJSONWebTokenAuthentication.authenticate')
        c['source_constants']['USER_SOURCE_CLAIM']='user_source'
        with self.assertRaises(ValueError):source_constants(p)
    def test_preview_id_comes_from_actual_route_helper(self):
        v=self.selected('BuilderPreviewAuthentication.authenticate',{'preview_cookie':'owned-preview','parser_context':{'kwargs':{'builder_id':'42'}},'actor_builder':42})
        self.assertEqual(v['status'],'agree');self.assertEqual(v['source_calls']['BuilderPreviewAuthentication__get_builder_id'],1)
    def test_preview_missing_route_is_mapped_source_error(self):
        for p in (None,{}, {'kwargs':{}},{'kwargs':{'builder_id':'not-a-number'}}):
            v=self.selected('BuilderPreviewAuthentication.authenticate',{'preview_cookie':'owned-preview','parser_context':p})
            self.assertEqual(v['status'],'agree');self.assertEqual(v['outcomes'][0],{'kind':'error','name':'APIException','status':401,'code':'ERROR_BUILDER_PREVIEW_SESSION_INVALID'})
            self.assertEqual(v['call_counts']['preview_actor'],0)
    def test_superuser_company_is_resolved_by_source_not_supplied_result(self):
        v=self.selected('TenantScopedJWTAuthentication.authenticate',{'company':7,'superuser':True})
        self.assertEqual(v['status'],'agree');self.assertIsNone(v['state']['selected_company']);self.assertEqual(v['call_counts']['tenant.filter'],0)
    def test_company_query_failure_is_fail_closed_source_behavior(self):
        v=self.selected('TenantScopedJWTAuthentication.authenticate',{'company':7,'tenant_query_error':True})
        self.assertEqual(v['status'],'agree');self.assertEqual(v['outcomes'],[{'kind':'error','name':'PermissionDenied'}]);self.assertIsNone(v['state']['selected_company'])
    def test_company_helper_reads_correct_user_and_column(self):
        v=self.selected('TenantScopedJWTAuthentication.authenticate',{'company':7});self.assertEqual(v['status'],'agree')
        self.assertIn('tenant.filter',v['argument_operations_checked']);self.assertIn('tenant.values_list',v['argument_operations_checked']);self.assertEqual(v['source_calls']['resolve_company_id'],1)
    def test_unknown_query_is_not_swallowed_as_fail_closed_success(self):
        c=next(c for c in self.packet['references']['contracts'] if c['function']=='TenantScopedJWTAuthentication.authenticate');v=copy.deepcopy(c['contexts'][0]);v['inputs']={'company':7,'unknown_tenant_dependency':True}
        result=execute(self.packet['sources'][c['source_key']],c,v);self.assertEqual(result['status'],'unknown')
    def test_empty_contexts_cannot_complete_a_contract(self):
        p=copy.deepcopy(self.packet);p['references']['contracts']=p['references']['contracts'][:1];p['references']['contracts'][0]['contexts']=[]
        self.assertEqual(run(p)['unknown'],1);self.assertEqual(run(p)['concrete_agree'],0)
    def test_duplicate_entries_are_not_double_counted(self):
        p=copy.deepcopy(self.packet);p['references']['contracts']=[p['references']['contracts'][0]]*2
        with self.assertRaises(ValueError):run(p)
    def test_duplicate_source_definition_rejected(self):
        with self.assertRaises(AdmissionError):program_for('def f():\n return True\ndef f():\n return False\n','f')
    def test_rebound_method_rejected(self):
        with self.assertRaises(AdmissionError):program_for('class C:\n def f(self):\n  return True\n f=None\n','C.f')
    def test_unbound_from_import_never_loads_host_module(self):
        from reference_completion.interpreter import Interpreter
        p,key=program_for('def f():\n from pathlib import Path\n return True\n','f')
        with self.assertRaises(AdmissionError):Interpreter(p,{}).run(key,[])
    def test_helper_identity_tampering_rejected(self):
        c=copy.deepcopy(next(c for c in self.packet['references']['contracts'] if c['function']=='BuilderPreviewAuthentication.authenticate'))
        c['helper_bindings']['BuilderPreviewAuthentication.get_builder_id']='0'*64
        with self.assertRaises(ValueError):execute(self.packet['sources'][c['source_key']],c,c['contexts'][0])
    def test_cached_admission_does_not_share_mutable_execution_bodies(self):
        import ast
        text='def f():\n return True\n';p,key=program_for(text,'f');p[key].body=[ast.Return(value=ast.Constant(False))]
        from reference_completion.interpreter import Interpreter
        fresh,key=program_for(text,'f');self.assertIs(Interpreter(fresh,{}).run(key,[]),True)
if __name__=='__main__':unittest.main()
