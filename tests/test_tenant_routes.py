from itertools import product
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from checker import reference_step
from finite_routes import path_matches
from native_casbin import AdmissionError
from tenant_routes import SCHEMA, abstract_request, action_set, compare_tenant_routes, path_partition

MODEL = "\n".join("[" + section + "]\n" + "\n".join(key + " = " + value for key, value in fields.items())
                  for section, fields in SCHEMA.items())
POLICY = "p, operator, /tasks*, ^(GET|POST)$, tenant_match\np, root, /api/*, ^GET$, any\ng, operator, operator\ng, root, root"


class TenantRouteTests(unittest.TestCase):
    def test_five_field_native_matrix_agrees(self):
        result = compare_tenant_routes(MODEL, POLICY)
        self.assertTrue(result["accepted"])
        self.assertFalse(result["resource_tenant_origin_verified"])

    def test_same_different_tenant_relation_is_not_ignored(self):
        result = compare_tenant_routes(MODEL, POLICY)
        for tenant, target, expected in [(1, 1, "allow"), (1, 2, "deny"), (55, 55, "allow"), (55, 88, "deny")]:
            request = abstract_request(result, "operator", tenant, "/tasks/one", "POST", target)
            self.assertEqual(reference_step(result["policy"], 0, request, {})[0], expected)

    def test_anchor_and_outside_role_classes_are_preserved(self):
        result = compare_tenant_routes(MODEL, POLICY)
        for role, method in [("operator", "POSTX"), ("unknown", "GET")]:
            request = abstract_request(result, role, 1, "/tasks", method, 1)
            self.assertEqual(reference_step(result["policy"], 0, request, {})[0], "deny")

    def test_unsafe_or_unmodeled_action_regex_is_rejected(self):
        for pattern in ("POST", "^(GET|.*)$", "^GET|POST$", "^(GET|GET)$"):
            with self.assertRaises(AdmissionError):
                action_set(pattern)

    def test_exhaustive_small_path_language_is_covered_by_signature_partition(self):
        patterns = ["/a*", "/ab*", "/ab", "/b"]
        partition = path_partition(patterns)
        signatures = {tuple(path_matches(path, p) for p in patterns) for path in partition["representatives"]}
        for length in range(5):
            for characters in product("ab~", repeat=length):
                path = "/" + "".join(characters)
                self.assertIn(tuple(path_matches(path, p) for p in patterns), signatures)

    def test_custom_schema_default_or_scope_is_not_guessed(self):
        for model, policy in [(MODEL.replace("keyMatch(", "keyMatch2("), POLICY),
                              (MODEL, POLICY.replace("tenant_match", "project_match")),
                              ("[DEFAULT]\nunknown=x\n" + MODEL, POLICY)]:
            with self.assertRaises(AdmissionError):
                compare_tenant_routes(model, policy)

    def test_boolean_tenant_is_not_silently_coerced_to_integer(self):
        report = compare_tenant_routes(MODEL, POLICY)
        with self.assertRaises(AdmissionError):
            abstract_request(report, "operator", True, "/tasks", "GET", 1)


if __name__ == "__main__":
    unittest.main()
