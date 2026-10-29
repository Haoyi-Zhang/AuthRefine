from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"source_study/code"))
from copy import deepcopy
import ast
import unittest
from pretix_event_profile import source,programs,functions,PERMISSION,TOKEN,contexts,observe,reference,run,ProfileInterpreter
from native_casbin import AdmissionError


class PretixProfileControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=source();cls.compiled=programs(cls.raw)
    def test_complete_context_domain_and_source_consumers(self):
        value=run();self.assertEqual(value['contexts'],288);self.assertEqual(value['actual_SELECTs'],288)
        self.assertEqual(value['differences'],0);self.assertFalse(value['authentication_or_plugin_registry_certified'])
    def test_original_source_bodies_not_validation_substitutions_execute(self):
        wanted=[functions(self.raw,PERMISSION,'EventPermission',('has_permission',)),
            functions(self.raw,TOKEN,'TeamAPIToken',('get_event_permission_set','has_event_permission'))]
        for actual,nodes in zip(self.compiled,wanted):
            for name,node in nodes.items():
                self.assertEqual([ast.dump(n,include_attributes=False) for n in actual[name].body],
                    [ast.dump(n,include_attributes=False) for n in node.body])
    def test_other_authentication_and_unvalidated_token_remain_unknown(self):
        for key,value in [('authenticated',True),('token_kind','OAuthAccessToken'),('token_kind','Device'),
                ('validated_active_token',False),('resolved_view_contract','dynamic')]:
            c=deepcopy(contexts()[0]);c[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(AdmissionError):observe(c,self.compiled)
    def test_missing_event_retains_source_write_and_early_return(self):
        c=next(c for c in contexts() if c['query']=='missing');got,meta=observe(c,self.compiled)
        self.assertEqual(got,dict(allow=False,event=None,organizer=None,permissions=None));self.assertEqual(meta['actual_SELECTs'],1)
    def test_identity_handoff_matches_owned_sqlite_result(self):
        for query in ('own-a','own-b','other'):
            c=next(c for c in contexts() if c['query']==query and c['all_events']);got,meta=observe(c,self.compiled)
            self.assertTrue(meta['exact_event_identity']);self.assertEqual(got,reference(c))
    def test_wrong_owned_access_handoff_is_observably_rejected_by_reference(self):
        c=next(c for c in contexts() if c['query']=='other' and c['method']=='GET')
        got,_=observe(c,self.compiled,omit_owner_contract=True)
        self.assertNotEqual(got,reference(c));self.assertTrue(got['allow']);self.assertFalse(reference(c)['allow'])
    def test_malformed_or_cross_organizer_relations_not_silently_admitted(self):
        for key,value in [('limited_events',[3]),('limited_events',[1,1]),('permissions',['unknown']),('all_events',1)]:
            c=deepcopy(contexts()[0]);c[key]=value
            with self.subTest(key=key),self.assertRaises(AdmissionError):observe(c,self.compiled)
    def test_complete_permission_set_is_transferred_without_copying_an_expected_decision(self):
        c=next(c for c in contexts() if c['query']=='own-a' and c['all_events'] and c['method']=='POST' and c['permissions']==['event.items:read'])
        got,_=observe(c,self.compiled);self.assertFalse(got['allow']);self.assertEqual(got['organizer'],1)
        self.assertEqual(got['permissions'],['event.items:read'])


if __name__=='__main__':unittest.main()
