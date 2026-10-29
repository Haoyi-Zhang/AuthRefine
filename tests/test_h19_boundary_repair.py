from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "source_study/code"))
from secret_metadata_profile import CASE, observe
from effect_slice import DataRecord
from native_casbin import AdmissionError
from secret_field_boundary import complete_secret_exclusions
from h19_boundary_repair import run, exhaustive_boundary_law


def descriptor(name, secret):
    return DataRecord('Column', {'_meta': DataRecord('column_meta', {'name': name, 'secret': secret})})


def given_table(columns):
    return DataRecord('Table', {'_meta': DataRecord('table_meta', {'columns': columns})})


class H19BoundaryRepairTests(unittest.TestCase):
    def test_all_source_contexts_close_without_changing_the_original_pair(self):
        result = run()
        self.assertEqual(result['contexts'], 18)
        self.assertEqual(result['original_after_nonagreeing_properties'], 18)
        self.assertEqual(result['repaired_nonagreeing_properties'], 0)
        self.assertTrue(all(not r['remaining_different_observers'] for r in result['rows']))
        self.assertTrue(result['query_observations_and_explicit_inclusion_preserved'])

    def test_full_metadata_and_prior_exclusion_mask_product(self):
        self.assertEqual(exhaustive_boundary_law(), 1024)

    def test_is_field_generic_preserves_prior_exclusions_and_object_identity(self):
        public = descriptor('ordinary', False)
        secret = descriptor('private_note', True)
        given = [public]
        table = given_table([public, secret])
        actual = complete_secret_exclusions(table, given)
        self.assertEqual(given, [public])
        self.assertIs(actual[0], public)
        self.assertIs(actual[1], secret)
        self.assertEqual(complete_secret_exclusions(table, actual), actual)

    def test_not_a_hardcoded_token_filter(self):
        ordinary_token = descriptor('token', False)
        private_other = descriptor('private_other', True)
        actual = complete_secret_exclusions(given_table([ordinary_token, private_other]), [])
        self.assertEqual(actual, [private_other])

    def test_wrong_table_identity_stops_admission_instead_of_being_dropped(self):
        own = descriptor('private', True)
        foreign = descriptor('private', True)
        with self.assertRaises(AdmissionError):
            complete_secret_exclusions(given_table([own]), [foreign])

    def test_incomplete_or_ambiguous_metadata_stops_admission(self):
        for secret in (None, 0, 1, 'true'):
            with self.assertRaises(AdmissionError):
                complete_secret_exclusions(given_table([descriptor('private', secret)]), [])
        repeated = descriptor('private', True)
        for columns in ([repeated, repeated], [descriptor('same', True), descriptor('same', False)]):
            with self.assertRaises(AdmissionError):
                complete_secret_exclusions(given_table(columns), [])

    def test_disabling_repair_restores_the_mismatch(self):
        crud = (CASE/'after/piccolo_api/crud/endpoints.py').read_bytes()
        source = (CASE/'after/piccolo_api/session_auth/tables.py').read_bytes()
        self.assertIn('token', observe(crud, source, None, None)['filter_fields'])
        self.assertNotIn('token', observe(crud, source, None, None, filter_boundary_repair=True)['filter_fields'])

    def test_source_output_regression_not_hidden_by_filter_repair(self):
        crud = (CASE/'after/piccolo_api/crud/endpoints.py').read_bytes()
        source = (CASE/'after/piccolo_api/session_auth/tables.py').read_bytes()
        mutant = crud.replace(b'exclude_secrets=self.exclude_secrets,', b'exclude_secrets=False,')
        self.assertNotEqual(mutant, crud)
        observed = observe(mutant, source, ('token',), True, filter_boundary_repair=True)
        self.assertEqual(observed['query_fields'], ['token'])
        self.assertNotIn('token', observed['filter_fields'])


if __name__ == '__main__':
    unittest.main()
