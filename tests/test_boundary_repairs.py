import ast
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from boundary_repairs import repair_file_store, repair_sync_guard, repeated_string_values
from native_casbin import AdmissionError
from persistent_store import compare_store, extract_store
from source_save_store import compare_repaired_store, extract_repaired_store
from request_outcomes import compare_request_outcomes
from test_persistent_store import SOURCE as STORE, MODEL, ROWS
from test_request_outcomes import SOURCE as GUARD, model


class BoundaryRepairTests(unittest.TestCase):
    def test_actual_persistent_candidate_is_admitted_and_compared_without_control_flag(self):
        candidate=repair_file_store(STORE)
        result=compare_repaired_store(candidate,MODEL,ROWS,initial=1)
        self.assertTrue(result['accepted'])
        self.assertFalse(result['external_save_toggle_supplied'])
        self.assertTrue(result['save_effect_from_candidate_source'])
        self.assertGreater(result['native_operations']['owned_save_policy'],0)
        self.assertTrue(all(result['source_candidate_descriptor']['source_mutation_effects'][op]['persist_after_success'] for op in ('add','remove')))

    def test_mutation_only_without_source_save_still_fails(self):
        self.assertFalse(compare_store(STORE,MODEL,ROWS[:1])['accepted'])
        candidate=repair_file_store(STORE).replace(b'.save_policy()',b'.save_policy(False)')
        with self.assertRaises(AdmissionError):extract_repaired_store(candidate)

    def test_wrong_save_condition_is_not_silently_accepted(self):
        candidate=repair_file_store(STORE).replace(b' is True:',b' is False:')
        with self.assertRaises(AdmissionError):extract_repaired_store(candidate)

    def test_return_and_query_semantics_are_not_repaired_by_changing_the_reference(self):
        candidate=repair_sync_guard(GUARD,native_result_protocol='synchronous_boolean')
        self.assertTrue(compare_request_outcomes(candidate,model())['comparison']['accepted'])
        changed=candidate.replace(b'enforcer.enforce(uid, dom, obj, act)',b"enforcer.enforce(uid, 't2', obj, act)")
        self.assertFalse(compare_request_outcomes(changed,model())['comparison']['accepted'])

    def test_await_removal_requires_the_declared_provider_contract(self):
        for protocol in ('awaitable_boolean','unknown',None):
            with self.assertRaises(AdmissionError):repair_sync_guard(GUARD,native_result_protocol=protocol)
        with self.assertRaises(AdmissionError):
            repair_sync_guard(GUARD.replace(b'await enforcer.enforce',b'enforcer.enforce'),native_result_protocol='synchronous_boolean')

    def test_only_the_selected_await_changes(self):
        candidate=repair_sync_guard(GUARD,native_result_protocol='synchronous_boolean')
        before=ast.parse(GUARD);after=ast.parse(candidate)
        class Expected(ast.NodeTransformer):
            def visit_Await(self,node):return node.value
        self.assertEqual(ast.dump(Expected().visit(before)),ast.dump(after))

    def test_repeated_values_preserve_gaps_order_duplicates_and_scalar_independence(self):
        source={'roles_0':'viewer','roles_2':'viewer','roles_3':'operator'}
        result=repeated_string_values(source,'roles')
        self.assertEqual(result,['viewer','viewer','operator'])
        self.assertEqual(list(source),['roles_0','roles_2','roles_3'])
        self.assertEqual(repeated_string_values([],'roles'),[])

    def test_invalid_repeated_source_mappings_are_not_guessed(self):
        for source in ({'other_0':'x'},{'roles_01':'x'},{'roles_2':'x','roles_1':'y'}, {'roles_0':1}, {'roles_-1':'x'}):
            with self.subTest(source=source),self.assertRaises(AdmissionError):repeated_string_values(source,'roles')
        with self.assertRaises(AdmissionError):repeated_string_values(['x']*257,'roles')


if __name__=='__main__':unittest.main()
