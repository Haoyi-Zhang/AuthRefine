from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from finite_routes import compare_finite_routes, path_matches
from native_casbin import AdmissionError, EXTRA_MATCHERS, compare_native

BASE = """[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = MATCHER
"""


class FiniteRouteTests(unittest.TestCase):
    def test_two_whitelisted_middleware_schemas(self):
        domain = {"principals": ["alice", "bob", "visitor"],
                  "resources": ["/data", "/data/", "/data/x", "/outside"], "actions": ["GET", "POST"]}
        text = "p, reader, /data/*, GET\np, *, /data, *\ng, alice, reader"
        for name, matcher in EXTRA_MATCHERS.items():
            with self.subTest(name=name):
                result = compare_finite_routes(BASE.replace("MATCHER", matcher), text, domain)
                self.assertTrue(result["accepted"])
                self.assertEqual(result["native_enforce_calls"], 24)
                self.assertFalse(result["unlisted_url_equivalence_claimed"])

    def test_wildcard_is_not_accepted_as_equality_outside_name_proof(self):
        with self.assertRaises(AdmissionError):
            compare_native(BASE.replace("MATCHER", EXTRA_MATCHERS["rbac_wildcards"]), "p, *, /data, *")

    def test_empty_wildcard_policy_denies_all_declared_requests(self):
        result = compare_finite_routes(BASE.replace("MATCHER", EXTRA_MATCHERS["rbac_wildcards"]), "",
                                       {"principals": ["u"], "resources": ["/"], "actions": ["GET"]})
        self.assertTrue(result["accepted"])
        self.assertEqual(result["machine"]["transitions"], [[["deny", 0]]])

    def test_unreviewed_path_function_is_rejected(self):
        model = BASE.replace("MATCHER", EXTRA_MATCHERS["rbac_path_wildcards"].replace("keyMatch(", "keyMatch2("))
        with self.assertRaises(AdmissionError):
            compare_finite_routes(model, "", {"principals": ["u"], "resources": ["/"], "actions": ["GET"]})

    def test_keymatch_boundary_and_first_star_semantics(self):
        self.assertTrue(path_matches("/data", "/data*"))
        self.assertFalse(path_matches("/dat", "/data*"))
        self.assertTrue(path_matches("/data/a", "/data/*/ignored"))
        self.assertFalse(path_matches("/outside", "/data/*"))

    def test_domain_duplicates_do_not_inflate_evaluation(self):
        with self.assertRaises(AdmissionError):
            compare_finite_routes(BASE.replace("MATCHER", EXTRA_MATCHERS["rbac_wildcards"]), "",
                                  {"principals": ["u", "u"], "resources": ["/"], "actions": ["GET"]})


if __name__ == "__main__":
    unittest.main()
