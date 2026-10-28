from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from checker import verify_reachable
from native_casbin import AdmissionError
from persistent_store import compare_store, extract_store, persistent_specification

MODEL = (Path(__file__).resolve().parents[1] / "external_inputs/casbin/basic_model.conf").read_text(encoding="utf-8")
SOURCE = b'''import casbin
import os
_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'policy_model.conf')
class PolicyEngine:
    def __init__(self, secret_key, policy_path=None):
        self._secret_key = secret_key
        self._enforcer = casbin.Enforcer(_MODEL_PATH, policy_path) if policy_path else casbin.Enforcer(_MODEL_PATH)
        self._enforcer.enable_auto_save(True)
    async def authorize(self, subject, skill_id, action):
        try:
            return self._enforcer.enforce(subject, skill_id, action)
        except Exception:
            logger.exception('authorize failed for (%s, %s, %s)', subject, skill_id, action)
            raise
    def add_policy_rule(self, subject, skill_id, action):
        return self._enforcer.add_policy(subject, skill_id, action)
    def remove_policy_rule(self, subject, skill_id, action):
        return self._enforcer.remove_policy(subject, skill_id, action)
'''
ROWS = [["finance", "invoice", "invoke"], ["marketing", "leads", "invoke"]]


def replay(machine, labels):
    state = machine["initial"]
    results = []
    for resource, action in labels:
        i = machine["alphabet"].index(["api", resource, action])
        decision, state = machine["transitions"][state][i]
        results.append(decision)
    return results, state


class PersistentStoreTests(unittest.TestCase):
    def test_current_instance_set_behavior_agrees(self):
        result = compare_store(SOURCE, MODEL, ROWS, initial=1, persistence=False)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["table_cells"], 24)
        self.assertEqual(result["native_operations"]["enforce"], 8)
        self.assertFalse(result["application_or_upstream_tests_executed"])

    def test_file_autosave_does_not_satisfy_persistent_set_contract(self):
        result = compare_store(SOURCE, MODEL, ROWS[:1])
        self.assertFalse(result["accepted"])
        self.assertEqual(result["comparison"]["length"], 1)
        self.assertEqual(result["table_cells"], 16)
        self.assertEqual(replay(result["machine"], [("permission_0", "add"), ("permission_0", "authorize"),
            ("permission_0", "restart"), ("permission_0", "authorize")])[0], ["allow", "allow", "allow", "deny"])

    def test_successful_revocation_is_lost_at_fresh_reload_without_save(self):
        result = compare_store(SOURCE, MODEL, ROWS[:1], initial=1)
        self.assertEqual(replay(result["machine"], [("permission_0", "remove"), ("permission_0", "authorize"),
            ("permission_0", "restart"), ("permission_0", "authorize")])[0], ["allow", "deny", "allow", "allow"])

    def test_owned_explicit_save_control_meets_same_persistence_contract(self):
        result = compare_store(SOURCE, MODEL, ROWS, initial=1, owned_explicit_save=True)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["table_cells"], 128)
        self.assertGreater(result["native_operations"]["owned_save_policy"], 0)
        self.assertFalse(result["deployment_or_security_finding_confirmed"])

    def test_duplicate_add_and_missing_remove_leave_both_states_unchanged(self):
        result = compare_store(SOURCE, MODEL, ROWS[:1], initial=1, owned_explicit_save=True)
        self.assertEqual(replay(result["machine"], [("permission_0", "add")]), (["deny"], 3))
        self.assertEqual(replay(result["machine"], [("permission_0", "remove"), ("permission_0", "remove")]), (["allow", "deny"], 0))

    def test_independent_specification_copies_disk_on_restart(self):
        p = persistent_specification(ROWS)
        restart = next(rule for rule in p["rules"] if rule["guard"] == [{"field": "action", "name": "restart", "negated": False}])
        self.assertEqual(restart["updates"], [{"name": "memory_0", "from": "disk_0", "negated": False},
                                              {"name": "memory_1", "from": "disk_1", "negated": False}])

    def test_native_calls_are_bound_in_source_parameter_order(self):
        source = SOURCE.replace(b"add_policy(subject, skill_id, action)", b"add_policy(skill_id, subject, action)")
        self.assertEqual(extract_store(source)["methods"]["add"]["argument_positions"], [1, 0, 2])
        with self.assertRaises(AdmissionError):
            compare_store(source, MODEL, ROWS[:1])  # unknown produced row cannot be hidden

    def test_async_await_changes_are_not_silently_erased(self):
        with self.assertRaises(AdmissionError):
            extract_store(SOURCE.replace(b"return self._enforcer.enforce", b"return await self._enforcer.enforce"))

    def test_model_native_import_and_autosave_changes_are_not_guessed(self):
        for old, new in ((b"import casbin", b"import other as casbin"), (b"policy_model.conf", b"other.conf"),
                         (b"enable_auto_save(True)", b"enable_auto_save(False)")):
            with self.subTest(old=old), self.assertRaises(AdmissionError):
                extract_store(SOURCE.replace(old, new))

    def test_rebound_class_method_or_exception_cannot_be_accepted(self):
        for tail in (b"\nPolicyEngine = object\n", b"\nException = RuntimeError\n",
                     b"\n    if True:\n        authorize = False\n"):
            with self.subTest(tail=tail), self.assertRaises(AdmissionError):
                extract_store(SOURCE + tail)

    def test_source_side_effects_and_upstream_functions_never_execute(self):
        descriptor = extract_store(b"raise RuntimeError('do not run source')\n" + SOURCE)
        self.assertFalse(descriptor["source_module_executed"])
        self.assertTrue(descriptor["methods"]["authorize"]["async_function"])

    def test_errors_and_work_envelopes_remain_not_passes(self):
        for source in (b"def", b"x" * 1_048_577):
            with self.subTest(source=source[:10]), self.assertRaises(AdmissionError):
                extract_store(source)
        with self.assertRaises(AdmissionError):
            compare_store(SOURCE, MODEL, [["u", "r" + str(i), "a"] for i in range(4)])
        with self.assertRaises(AdmissionError):
            compare_store(SOURCE, MODEL, [["u,evil", "r", "a"]])


if __name__ == "__main__":
    unittest.main()
