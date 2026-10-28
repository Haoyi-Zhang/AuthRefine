from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from yaml_policy import MATCHER, parse_yaml, reference_rows, configuration, compare_yaml_policy
from test_policy_slice import PROGRAM

ROOT = Path(__file__).resolve().parents[1]
MODEL = (ROOT / "external_inputs/casbin/rbac_model.conf").read_text(encoding="utf-8")
MODEL = MODEL.replace("g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act", MATCHER)
DATA = {"roles": {"admin": {"permissions": [{"resource": "*", "actions": ["*"]}]}},
        "user_roles": {"admin_user": ["admin"]}, "group_roles": {"/admins": ["admin"]},
        "rules": [{"condition": {"mcp_server": "prod", "tool_name_pattern": ".*delete.*"}, "action": "deny", "priority": 100},
                  {"condition": {"user": "anonymous"}, "action": "allow"}], "default_policy": "deny"}
CONTEXTS = [{"user": "admin_user", "groups": []}, {"user": "anonymous", "groups": []}, {"user": "outside", "groups": ["/admins"]}]
DOMAIN = {"resources": ["mcp:prod:delete_item", "mcp:dev:read"], "actions": ["read", "write"]}


class YamlPolicyTests(unittest.TestCase):
    def compare(self, source=PROGRAM, initial="# empty", data=DATA):
        return compare_yaml_policy(source, MODEL, initial, deepcopy(data), CONTEXTS, DOMAIN)

    def test_source_producer_store_persistence_and_consumers_agree(self):
        result = self.compare()
        self.assertTrue(result["accepted"])
        self.assertEqual(result["expected_rows"], result["persisted_rows"])
        self.assertFalse(result["whole_application_verified"])

    def test_owned_priority_inversion_changes_composed_but_not_config_inputs(self):
        result = self.compare(PROGRAM.replace(b'reverse=True', b'reverse=False'))
        self.assertFalse(result["accepted"])
        self.assertTrue(result["producer_rows_agree"])

    def test_owned_missing_clear_leaves_a_stale_permission(self):
        stale = "p, stale_role, mcp:dev:read, read\ng, outside, stale_role"
        context = [{"user": "outside", "groups": []}]
        source = PROGRAM.replace(b'  self.enforcer.clear_policy()', b'  pass')
        result = compare_yaml_policy(source, MODEL, stale, DATA, context, DOMAIN)
        self.assertFalse(result["accepted"])
        self.assertFalse(result["producer_rows_agree"])
        self.assertFalse(result["contexts"][0]["comparison"]["accepted"])

    def test_owned_native_argument_swap_is_not_normalized_away(self):
        result = self.compare(PROGRAM.replace(b'add_policy(role, permission.get("resource", "*"), verb)', b'add_policy(permission.get("resource", "*"), role, verb)'))
        self.assertFalse(result["accepted"])
        self.assertFalse(result["producer_rows_agree"])

    def test_ignored_policy_metadata_and_condition_keys_are_reported(self):
        data = deepcopy(DATA)
        data["rules"][1]["condition"]["tool_permissions"] = ["write"]
        data["rules"][1]["metadata"] = {"rate_limit": "10/minute"}
        result = self.compare(data=data)
        self.assertTrue(result["accepted"])
        fields = result["ignored_input_fields_not_certified_as_enforced"][0]
        self.assertEqual(fields["condition_keys"], ["tool_permissions"])
        self.assertEqual(fields["metadata_keys"], ["rate_limit"])

    def test_regex_argument_order_is_not_reinterpreted_as_a_glob(self):
        data = {"roles": {"reader": {"permissions": [{"resource": "mcp:dev:*", "actions": ["read"]}]}}, "user_roles": {"u": ["reader"]}}
        result = compare_yaml_policy(PROGRAM, MODEL, "# empty", data, [{"user": "u", "groups": []}], {"resources": ["mcp:dev:item"], "actions": ["read"]})
        self.assertTrue(result["accepted"])
        self.assertFalse(result["cells"][0]["allow"])

    def test_native_matcher_or_effect_change_is_not_assumed(self):
        with self.assertRaises(AdmissionError):
            configuration(MODEL.replace("regexMatch(p.obj, r.obj)", "regexMatch(r.obj, p.obj)"), "# empty")

    def test_supplied_data_is_not_mutated(self):
        before = deepcopy(DATA)
        compare_yaml_policy(PROGRAM, MODEL, "# empty", DATA, CONTEXTS, DOMAIN)
        self.assertEqual(DATA, before)

    def test_aliases_and_custom_yaml_tags_do_not_enter_the_plain_data_contract(self):
        for text in ("roles: &r {}\nuser_roles: *r", "!!python/object:Owned {}"):
            with self.assertRaises(AdmissionError):
                parse_yaml(text)

    def test_unbounded_native_request_regex_is_not_run(self):
        with self.assertRaises(AdmissionError):
            compare_yaml_policy(PROGRAM, MODEL, "# empty", DATA, CONTEXTS, {"resources": ["(a+)+"], "actions": ["read"]})

    def test_valid_yaml_and_duplicate_native_rows_have_explicit_meaning(self):
        self.assertEqual(parse_yaml("roles: {}\nrules: []\ndefault_policy: deny"), {"roles": {}, "rules": [], "default_policy": "deny"})
        data = {"user_roles": {"u": ["reader", "reader"]}}
        self.assertEqual(reference_rows(data), [["g", "u", "reader"]])

    def test_malformed_metadata_or_rule_names_cannot_crash_after_comparison(self):
        for fields in ({"metadata": None}, {"metadata": ["not", "a", "map"]},
                       {"metadata": {1: "not a string key"}}, {"name": 12}):
            data = deepcopy(DATA)
            data["rules"][0].update(fields)
            with self.assertRaises(AdmissionError):
                self.compare(data=data)

    def test_yaml_work_limit_is_inconclusive_not_a_pass(self):
        text = "rules: [" + ",".join("{}" for _ in range(10001)) + "]"
        with self.assertRaises(AdmissionError) as error:
            parse_yaml(text)
        self.assertEqual(error.exception.status, "inconclusive")


if __name__ == "__main__":
    unittest.main()
