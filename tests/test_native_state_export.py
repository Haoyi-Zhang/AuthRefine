import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from checker import verify_reachable
from native_casbin import AdmissionError, _engine, admit_configuration
from native_state_export import export_policy_store, observe_store, policy_store_specification

ROOT = Path(__file__).resolve().parents[1]
MODEL = (ROOT / "external_inputs/casbin/basic_model.conf").read_text(encoding="utf-8")
ROWS = [["alice", "data1", "read"], ["bob", "data2", "write"]]


class NativeStateExportTests(unittest.TestCase):
    def test_native_updates_and_authorization_match_independent_specification(self):
        result = export_policy_store(MODEL, ROWS)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["native_operations"], 32)
        self.assertEqual(result["comparison"]["states_discovered"], 4)
        self.assertFalse(result["application_project"])

    def test_initial_state_is_preserved(self):
        self.assertTrue(export_policy_store(MODEL, ROWS, initial=2)["accepted"])

    def test_consumption_after_add_and_remove_is_real_native_behavior(self):
        result = export_policy_store(MODEL, ROWS)
        machine = result["machine"]
        state = machine["initial"]
        actual = []
        for action in ("authorize", "add", "authorize", "remove", "authorize"):
            index = machine["alphabet"].index(["api", "permission_0", action])
            decision, state = machine["transitions"][state][index]
            actual.append(decision)
        self.assertEqual(actual, ["deny", "allow", "allow", "allow", "deny"])
        self.assertEqual(state, 0)

    def test_owned_lost_update_control_is_detected(self):
        result = export_policy_store(MODEL, ROWS)
        machine = copy.deepcopy(result["machine"])
        index = machine["alphabet"].index(["api", "permission_0", "add"])
        machine["transitions"][0][index] = ["allow", 0]
        comparison = verify_reachable(result["policy"], machine)
        self.assertFalse(comparison["accepted"])
        self.assertEqual(comparison["length"], 1)
        self.assertNotEqual(comparison["trace"][-1]["source"], comparison["trace"][-1]["target"])

    def test_unknown_native_row_cannot_be_hidden_by_decoder(self):
        engine = _engine(admit_configuration(MODEL, "p, outsider, data9, read"))
        with self.assertRaises(AdmissionError):
            observe_store(engine, ROWS)

    def test_duplicate_and_oversized_universes_are_rejected(self):
        with self.assertRaises(AdmissionError):
            policy_store_specification([ROWS[0], ROWS[0]])
        with self.assertRaises(AdmissionError):
            policy_store_specification([["u", f"r{i}", "a"] for i in range(8)])

    def test_store_values_do_not_inject_additional_policy_fields(self):
        with self.assertRaises(AdmissionError):
            export_policy_store(MODEL, [["alice, administrator", "data1", "read"]])


if __name__ == "__main__":
    unittest.main()
