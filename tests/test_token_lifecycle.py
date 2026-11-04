"""Owned lifecycle boundary controls and honest classification denominators."""
import ast
import gzip
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'adaptation_study'))
import token_lifecycle as t
import study
import owner_insert as owner
from effect_slice import DataRecord,SliceFault
from native_casbin import AdmissionError


class TokenLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled,cls.queries,cls.constants,cls.identity=t.programs()
    def observe(self,expiry,active=True,present=True,header='Token owned-token'):
        store=t.Store(1,active,expiry,present)
        try:
            return t.step(store,self.compiled,self.queries,self.constants,header,t.NOW)
        finally:
            store.close()
    def test_entire_original_authentication_renewal_and_expiry_bodies_are_retained(self):
        case,raw=t.source()
        for name,node in self.compiled.items():
            path=t.MODELS if name=='get_default_expiry' else t.DEPENDENCIES
            original=next(n for n in ast.parse(raw[path]).body if isinstance(n,ast.FunctionDef) and n.name==name)
            self.assertEqual([ast.dump(n) for n in node.body],[ast.dump(n) for n in original.body])
    def test_exact_expiry_boundary_accepts_and_renews(self):
        row=self.observe(t.NOW)
        self.assertEqual(row['state'],'authenticated')
        self.assertEqual(row['credential_effects'],dict(lookups=1,saves=1,deletes=0))
    def test_expired_is_deleted_and_next_lookup_is_missing(self):
        store=t.Store(1,True,t.NOW-timedelta(seconds=1))
        try:
            a=t.step(store,self.compiled,self.queries,self.constants,'Token owned-token',t.NOW)
            b=t.step(store,self.compiled,self.queries,self.constants,'Token owned-token',t.NOW+timedelta(seconds=1))
            self.assertEqual([a['state'],b['state']],['rejected','rejected'])
            self.assertEqual(a['credential_effects']['deletes'],1)
            self.assertEqual(b['credential_effects']['deletes'],0)
            self.assertEqual(len(b['credential_state']),1)
        finally:
            store.close()
    def test_inactive_precedes_expiry_delete_and_never_reaches_query(self):
        row=self.observe(t.NOW-timedelta(seconds=1),active=False)
        self.assertEqual(row['state'],'rejected')
        self.assertEqual(row['credential_effects'],dict(lookups=1,saves=0,deletes=0))
        self.assertEqual(row['query_observations'],[])
    def test_strict_sixty_second_refresh_threshold(self):
        for gap,writes in ((59,0),(60,0),(61,1)):
            with self.subTest(gap=gap):
                row=self.observe(t.NOW+timedelta(days=30,seconds=-gap))
                self.assertEqual(row['credential_effects']['saves'],writes)
    def test_no_expiry_has_no_credential_write(self):
        row=self.observe(None)
        self.assertEqual(row['state'],'authenticated')
        self.assertEqual(row['credential_effects'],dict(lookups=1,saves=0,deletes=0))
    def test_missing_second_field_is_source_error_not_normal_denial(self):
        row=self.observe(None,header='Token')
        self.assertEqual(row['state'],'malformed_source_error')
        self.assertEqual(row['credential_effects'],dict(lookups=0,saves=0,deletes=0))
    def test_original_selected_body_does_not_validate_first_header_field(self):
        self.assertEqual(self.observe(None,header='Bearer owned-token')['state'],'authenticated')
    def test_utc_input_and_unbound_time_operations_fail_closed(self):
        store=t.Store()
        try:
            with self.assertRaises(AdmissionError):
                store.authenticate(self.compiled,self.constants,'Token owned-token',object())
        finally:
            store.close()
        machine=t.TimeInterpreter({},DataRecord('Owned',{}),{})
        with self.assertRaises(AdmissionError):
            machine.value(ast.parse('x-y',mode='eval').body,{'x':object(),'y':object()})
    def test_complete_reset_and_sequential_consumer(self):
        report=t.run()
        self.assertEqual(report['entry_observations'],72)
        self.assertEqual(report['state_counts'],dict(authenticated=24,rejected=30,malformed_source_error=18))
        self.assertEqual(report['connected_query_observations'],288)
        self.assertEqual((report['credential_saves'],report['expired_token_deletes'],report['sequential_steps']),(8,4,14))
        self.assertFalse(report['original_application_modules_executed'])
    def test_five_fault_controls_detect_real_state_or_identity_differences(self):
        for control in ('omit_save','omit_delete','wrong_user','disable_refresh','eager_refresh'):
            with self.subTest(control=control),self.assertRaises(t.LifecycleMismatch):
                t.run(control)
    def test_setup_and_unknown_errors_are_not_successful_controls(self):
        for error in (ValueError('setup'),AdmissionError('unknown')):
            with patch.object(sys,'argv',['token_lifecycle.py','--control','omit_save']),patch.object(t,'run',side_effect=error):
                with self.assertRaises(type(error)):
                    t.main()


class CaseClassificationTests(unittest.TestCase):
    def book(self):
        return json.loads((ROOT/'adaptation_study/casebook.json').read_text(encoding='utf-8'))
    def test_source_scope_modes_and_lifecycle_are_distinct_denominators(self):
        value=study.audit_casebook(self.book())
        self.assertEqual(value['case_scope_counts']['source_lookup_with_native_primitive'],3)
        self.assertEqual(value['case_scope_percentages']['source_lookup_with_native_primitive'],37.5)
        self.assertEqual(value['case_scope_counts']['selected_business_write_and_native_readback'],2)
        self.assertEqual(sum(value['handling_counts'].values()),40)
        self.assertEqual(value['credential_lifecycle_scope_counts']['source_expiry_delete_refresh_executed'],1)
    def test_fabricated_scope_counts_or_percentages_are_rejected(self):
        for field in ('case_scope_counts','case_scope_percentages'):
            book=self.book()
            book[field]['supplied_identity_context']=6
            with self.assertRaises(ValueError):
                study.audit_casebook(book)
    def test_axis_annotations_are_not_eight_independent_handling_samples(self):
        book=self.book()
        book['handling_percentage_denominator']=8
        with self.assertRaises(ValueError):
            study.audit_casebook(book)
    def test_misnamed_original_function_with_same_text_hash_is_rejected(self):
        book=self.book()
        book['cases'][0]['source_anchors'][0]['function']='invented_function'
        with self.assertRaises(ValueError):
            study.audit_casebook(book)
    def test_source_snapshot_identity_is_not_arbitrary(self):
        book=self.book()
        book['cases'][0]['snapshot']='not-the-selected-source'
        with self.assertRaises(ValueError):
            study.audit_casebook(book)


class OwnerInsertTests(unittest.TestCase):
    def test_complete_owner_source_bodies_survive_admission(self):
        compiled,_=owner.programs()
        book=json.loads(gzip.decompress((ROOT/'adaptation_study/sources.json.gz').read_bytes()))
        case=next(r for r in book['rows'] if r['repository_id']==7705569)
        for name,cls,path in (('has_permission','RoutinePermission','wger/manager/api/permissions.py'),
                              ('perform_create','RoutineViewSet','wger/manager/api/views.py')):
            text=next(m['text'] for m in case['modules'] if m['path']==path)
            c=next(n for n in ast.parse(text).body if isinstance(n,ast.ClassDef) and n.name==cls)
            fn=next(n for n in c.body if isinstance(n,ast.FunctionDef) and n.name==name)
            self.assertEqual([ast.dump(n) for n in compiled[name].body],[ast.dump(n) for n in fn.body])
    def test_exact_owner_insert_and_rejected_principals(self):
        value=owner.run()
        self.assertEqual((value['contexts'],value['successful_inserts'],value['stopped_before_insert']),(16,8,8))
        self.assertTrue(all(r['observed_rows']==r['expected_rows'] for r in value['rows']))
        self.assertFalse(value['original_application_modules_executed'])
    def test_client_owner_wrong_request_and_missing_insert_are_detected(self):
        for control in ('client_owner','wrong_request','omit_insert'):
            with self.subTest(control=control),self.assertRaises(owner.OwnerMismatch):
                owner.run(control)
    def test_other_primitive_errors_are_not_successful_fault_detection(self):
        with patch.object(sys,'argv',['owner_insert.py','--control','omit_insert']),patch.object(owner,'run',side_effect=AdmissionError('unsupported')):
            with self.assertRaises(AdmissionError):
                owner.main()


if __name__=='__main__':
    unittest.main()
