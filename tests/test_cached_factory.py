import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cached_factory import NativeFileFactory, extract_cached_factory, export_cached_component
from native_casbin import AdmissionError, _schema
from protocol_check import verify_protocol

SOURCE = b'''
import casbin
from functools import lru_cache
from . import get_auth_config
@lru_cache(maxsize=1)
def get_enforcer():
    config = get_auth_config()
    model_path = _get_config_path(config.rbac.model_path)
    policy_path = _get_config_path(config.rbac.policy_path)
    enforcer = casbin.Enforcer(model_path, policy_path)
    return enforcer
def reload_enforcer():
    get_enforcer.cache_clear()
def check_permission(role, resource, action):
    enforcer = get_enforcer()
    return enforcer.enforce(role, resource, action)
'''
MODEL = "\n".join("[" + section + "]\n" + "\n".join(k + " = " + v for k, v in values.items())
                  for section, values in _schema("rbac").items())
ROW = ["p", "viewer", "records", "read"]
ROWS = [["g", "admin", "viewer"], ROW]


class CachedFactoryTests(unittest.TestCase):
    def test_source_descriptor_binds_order_and_cache_invalidation(self):
        descriptor = extract_cached_factory(SOURCE)
        self.assertEqual(descriptor["consumer_event_order"], ["acquire", "authorize"])
        self.assertFalse(descriptor["source_module_executed"])

    def test_different_consumer_order_or_reload_target_is_not_assumed(self):
        for source in (SOURCE.replace(b'get_enforcer.cache_clear()', b'other.cache_clear()'),
                       SOURCE.replace(b'instance =', b'other =').replace(b'maxsize=1', b'maxsize=2'),
                       SOURCE.replace(b'enforce(role, resource, action)', b'enforce(action, resource, role)')):
            with self.assertRaises(AdmissionError):
                extract_cached_factory(source)

    def test_actual_file_adapter_and_lru_cache_preserve_old_policy_until_clear(self):
        factory = NativeFileFactory(extract_cached_factory(SOURCE), MODEL, ROWS)
        try:
            factory.acquire()
            self.assertTrue(factory.sink(["viewer", "records", "read"]))
            factory.replace(ROWS[:1])
            factory.acquire()
            self.assertTrue(factory.sink(["viewer", "records", "read"]))
            self.assertEqual(factory.engine_constructions, 1)
            factory.clear()
            factory.acquire()
            self.assertFalse(factory.sink(["viewer", "records", "read"]))
            self.assertEqual(factory.engine_constructions, 2)
        finally:
            factory.close()

    def test_denied_outer_call_can_load_internal_cache(self):
        factory = NativeFileFactory(extract_cached_factory(SOURCE), MODEL, ROWS[:1])
        try:
            self.assertEqual(factory.factory.cache_info().currsize, 0)
            factory.acquire()
            self.assertFalse(factory.sink(["viewer", "records", "read"]))
            self.assertEqual(factory.factory.cache_info().currsize, 1)
        finally:
            factory.close()

    def test_component_machine_matches_contract_under_source_caller_protocol(self):
        result = export_cached_component(extract_cached_factory(SOURCE), MODEL, ROWS, ROW, ["viewer", "records", "read"])
        self.assertTrue(result["accepted"])
        self.assertEqual(len(result["machine"]["observations"]), 6)
        self.assertEqual(result["counts"]["native_sink_calls"], 4)
        self.assertFalse(result["unconditional_external_api_refinement"])

    def test_immediate_visibility_hypothesis_has_a_real_native_component_counterexample(self):
        result = export_cached_component(extract_cached_factory(SOURCE), MODEL, ROWS, ROW, ["viewer", "records", "read"])
        policy = copy.deepcopy(result["policy"])
        for rule in policy["rules"]:
            if any(g.get("name") == "authorize" for g in rule["guard"]):
                for guard in rule["guard"]:
                    if guard.get("name") == "cache_permission":
                        guard["name"] = "file_permission"
        comparison = verify_protocol(policy, result["machine"], result["protocol"])
        self.assertFalse(comparison["accepted"])
        self.assertEqual(comparison["length"], 5)

    def test_owned_lost_clear_control_is_detected(self):
        result = export_cached_component(extract_cached_factory(SOURCE), MODEL, ROWS, ROW, ["viewer", "records", "read"])
        machine = copy.deepcopy(result["machine"])
        clear = machine["alphabet"].index(["api", "factory", "clear"])
        for state, observation in enumerate(machine["observations"]):
            machine["transitions"][state][clear] = ["allow", state]
        outcome = verify_protocol(result["policy"], machine, result["protocol"])
        self.assertFalse(outcome["accepted"])

    def test_unselected_alternative_grant_is_not_silently_dropped(self):
        with self.assertRaises(AdmissionError):
            export_cached_component(extract_cached_factory(SOURCE), MODEL,
                                    ROWS + [["p", "admin", "records", "read"]], ROW, ["admin", "records", "read"])


if __name__ == "__main__":
    unittest.main()
