from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from source_contracts import extract_contract, replay_contract

ROOT = Path(__file__).resolve().parents[1]
MODEL = (ROOT / "external_inputs/casbin/rbac_model.conf").read_text(encoding="utf-8")
SOURCE = b'''
ROWS = [("p", "p", ["editor", "records", "read"]), ("g", "g", ["alice", "editor"])]
class TestAdapter:
    def test_remove(self):
        e = self.get_enforcer(conf_file=MODEL, policies=ROWS)
        adapter = e.get_adapter()
        assert e.enforce("alice", "records", "read") is True
        changed = adapter.remove_policy(sec="g", ptype="g", rule=("alice", "editor"))
        assert changed is True
        assert e.enforce("alice", "records", "read") is True
        e.load_policy()
        assert e.enforce("alice", "records", "read") is False
'''


class SourceContractTests(unittest.TestCase):
    def extract(self, source=SOURCE):
        return extract_contract(source, "TestAdapter.test_remove", ["MODEL"])

    def test_source_expectations_are_replayed_without_import(self):
        report = replay_contract(self.extract(), MODEL)
        self.assertTrue(report["accepted"])
        self.assertEqual(report["assertions_checked"], 4)
        self.assertEqual(report["native_enforce_calls"], 3)
        self.assertEqual(report["native_reload_calls"], 1)
        self.assertFalse(report["database_adapter_verified"])

    def test_wrong_literal_assertion_is_not_converted_to_passing_native_output(self):
        report = replay_contract(self.extract(SOURCE.replace(b'is False', b'is True')), MODEL)
        self.assertFalse(report["accepted"])
        self.assertFalse(report["trace"][-1]["matches"])

    def test_source_import_or_top_level_calls_are_never_executed(self):
        source = b'raise RuntimeError("this module must not run")\n' + SOURCE
        self.assertTrue(replay_contract(self.extract(source), MODEL)["accepted"])

    def test_unknown_producer_helper_and_rebinding_are_rejected(self):
        for old, new in [(b'adapter.remove_policy', b'adapter.remove_filtered_policy'),
                         (b'changed = adapter', b'e = adapter'),
                         (b'e.load_policy()', b'e = self.get_enforcer(conf_file=MODEL, policies=ROWS)')]:
            with self.assertRaises(AdmissionError):
                self.extract(SOURCE.replace(old, new))

    def test_decorated_parameterized_conditional_or_nonlinear_tests_are_rejected(self):
        for source in [SOURCE.replace(b'    def test_remove', b'    @fixture\n    def test_remove'),
                       SOURCE.replace(b'def test_remove(self)', b'def test_remove(self, other)'),
                       SOURCE.replace(b'        e.load_policy()', b'        if False:\n            dangerous()')]:
            with self.assertRaises(AdmissionError):
                self.extract(source)

    def test_nonliteral_rows_requests_and_unknown_model_binding_are_rejected(self):
        with self.assertRaises(AdmissionError):
            self.extract(SOURCE.replace(b'ROWS = [("p", "p", ["editor", "records", "read"]), ("g", "g", ["alice", "editor"])]', b'ROWS = load_rows()'))
        with self.assertRaises(AdmissionError):
            self.extract(SOURCE.replace(b'e.enforce("alice"', b'e.enforce(other'))
        with self.assertRaises(AdmissionError):
            extract_contract(SOURCE, "TestAdapter.test_remove", ["OTHER_MODEL"])

    def test_ambiguous_source_table_and_nonboolean_assertion_are_rejected(self):
        with self.assertRaises(AdmissionError):
            self.extract(b'ROWS = []\n' + SOURCE)
        with self.assertRaises(AdmissionError):
            self.extract(SOURCE.replace(b'is True', b'== True'))

    def test_empty_or_assertion_free_replay_cannot_pass(self):
        contract = self.extract()
        contract["operations"] = [{"operation": "reload"}]
        with self.assertRaises(AdmissionError):
            replay_contract(contract, MODEL)

    def test_async_redefinition_does_not_leave_a_stale_sync_contract(self):
        with self.assertRaises(AdmissionError):
            self.extract(SOURCE + b'\n    async def test_remove(self):\n        pass\n')


if __name__ == "__main__":
    unittest.main()
