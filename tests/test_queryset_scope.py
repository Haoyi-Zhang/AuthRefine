"""Owned selected-query controls; no original application code executes."""
import ast
import gzip
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'adaptation_study'))
import queryset_scope as q
from effect_slice import DataRecord
from native_casbin import AdmissionError


class QuerysetScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled, cls.identity = q.programs()

    def test_complete_original_bodies_are_preserved(self):
        source = json.loads(gzip.decompress((ROOT / 'adaptation_study/sources.json.gz').read_bytes()))
        case = next(r for r in source['rows'] if r['repository_id'] == 7705569)
        text = next(m['text'] for m in case['modules'] if m['path'] == self.identity['path'])
        tree = ast.parse(text)
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'RoutineViewSet')
        for name, scope in [('get_queryset', cls.body), ('request_user_or_trainer_q', tree.body)]:
            original = next(n for n in scope if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertEqual([ast.dump(n) for n in original.body], [ast.dump(n) for n in self.compiled[name].body])

    def test_current_owned_sql_rows_and_exact_context_denominators(self):
        result = q.run()
        self.assertEqual((result['contexts'], result['schema_view_empty'], result['selected_scope_queries']), (36, 12, 24))
        self.assertFalse(result['original_application_modules_executed'])
        self.assertTrue(all(r['observed_rows'] == r['expected_rows'] and r['unchanged_store'] for r in result['rows']))

    def test_trainer_extends_scope_without_hiding_public_or_own_rows(self):
        result = q.observe(self.compiled, 1, 2, False)
        self.assertEqual([r[0] for r in result['observed_rows']], [1, 2, 4, 5, 6])
        self.assertEqual(result['source_helper_calls'], 1)

    def test_absent_zero_and_none_session_do_not_grant_another_owner(self):
        for value in ('missing', None, 0, False):
            with self.subTest(value=value):
                row = q.observe(self.compiled, 1, value, 'missing')
                self.assertEqual([r[0] for r in row['observed_rows']], [1, 4, 5, 6])

    def test_schema_view_short_circuits_all_identity_and_query_primitives(self):
        row = q.observe(self.compiled, 1, 'not-an-admitted-trainer', True)
        self.assertEqual(row['primitive_calls'], [['none']])
        self.assertEqual(row['source_helper_calls'], 0)

    def test_unadmitted_trainer_identity_is_not_a_successful_query(self):
        for value in ('not-an-admitted-trainer', True, -1, 101):
            with self.subTest(value=value), self.assertRaises(AdmissionError):
                q.observe(self.compiled, 1, value, False)

    def test_four_owned_faults_have_actual_observation_differences(self):
        for control in ('omit_trainer', 'omit_public', 'wrong_owner', 'ignore_fake_view'):
            with self.subTest(control=control), self.assertRaises(q.QueryMismatch):
                q.run(control)

    def test_setup_and_admission_errors_are_not_successful_controls(self):
        for error in (ValueError('setup'), AdmissionError('unknown')):
            with patch.object(sys, 'argv', ['queryset_scope.py', '--control', 'omit_trainer']), patch.object(q, 'run', side_effect=error):
                with self.assertRaises(type(error)):
                    q.main()

    def test_unbound_predicate_operations_do_not_call_host_protocols(self):
        machine = q.QueryInterpreter({}, DataRecord('Owned', {}), {})
        with self.assertRaises(AdmissionError):
            machine.value(ast.parse('a | b', mode='eval').body, {'a': object(), 'b': object()})
        for predicate in (['user_id', True], ['is_public', 1], ['user_id', '1'], ['arbitrary', 1]):
            with self.subTest(predicate=predicate), self.assertRaises(AdmissionError):
                q.sql(predicate)


if __name__ == '__main__':
    unittest.main()
