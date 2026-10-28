from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from tenant_query import compare_query_filter, extract_query_filter

SOURCE = b'def tenant_filtered(stmt, model, principal):\n    return stmt.where(model.tenant_id == principal.tenant_id)\n'


class TenantQueryTests(unittest.TestCase):
    def test_actual_sql_preserves_tenant_scope_and_existing_predicates(self):
        result = compare_query_filter(SOURCE)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["native_select_executions"], 12)
        self.assertFalse(result["application_database_or_all_query_sites_verified"])

    def test_missing_filter_and_tautology_controls_are_detected(self):
        for source in (SOURCE.replace(b'stmt.where(model.tenant_id == principal.tenant_id)', b'stmt'),
                       SOURCE.replace(b'principal.tenant_id', b'model.tenant_id')):
            self.assertFalse(compare_query_filter(source)["accepted"])

    def test_unrelated_calls_or_fields_are_not_executed_or_guessed(self):
        for source in (SOURCE.replace(b'stmt.where', b'unknown.where'),
                       SOURCE.replace(b'principal.tenant_id', b'principal.other_field'),
                       SOURCE.replace(b'model.tenant_id == principal.tenant_id', b'unreviewed_call()')):
            with self.assertRaises(AdmissionError):
                extract_query_filter(source)

    def test_top_level_module_effects_are_not_run(self):
        result = compare_query_filter(b'raise RuntimeError("never import this")\n' + SOURCE)
        self.assertTrue(result["accepted"])


if __name__ == "__main__":
    unittest.main()
