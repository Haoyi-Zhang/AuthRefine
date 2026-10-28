from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from rest_policy import rest_schema, compare_rest_policy, segment_match, extract_rest_consumer


def model(override="owner"):
    return "\n".join("[" + section + "]\n" + "\n".join(k + " = " + v for k, v in fields.items()) for section, fields in rest_schema(override).items())

ROWS = [["g", "alice", "reader"], ["p", "reader", "/records/:id", "GET"], ["p", "editor", "/records/*", "*"]]
DOMAIN = {"principals": ["alice", "owner", "outsider"],
          "resources": ["/records", "/records/", "/records/11", "/records/11/more", "/outside"],
          "actions": ["GET", "GETX", "POST"]}
CONSUMER = b'''
import os
import casbin
from django.conf import settings
from rest_framework.permissions import BasePermission
from apps.pgo_permission.utils.adapter import Adapter
def verify_permission(*args):
    adapter = Adapter()
    model_conf_file = os.path.join(settings.BASE_DIR, "config", "prem_model.conf")
    e = casbin.Enforcer(model_conf_file, adapter=adapter)
    return e.enforce(*args)
class ApiRBACPermission(BasePermission):
    def has_permission(self, request, view):
        path = request.META["PATH_INFO"]
        username = request.user.username
        method = request.method
        return verify_permission(username, path, method)
'''


class RestPolicyTests(unittest.TestCase):
    def test_native_schema_and_independent_segment_interpretation(self):
        result = compare_rest_policy(model(), ROWS, DOMAIN)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["native_enforce_calls"], 45)
        self.assertFalse(result["unlisted_paths_or_application_verified"])

    def test_source_consumer_binds_request_order_and_policy_location(self):
        descriptor = extract_rest_consumer(CONSUMER)
        self.assertEqual(descriptor["model_path"], "config/prem_model.conf")
        self.assertFalse(descriptor["source_module_or_http_server_executed"])

    def test_changed_request_order_or_source_adapter_rejected(self):
        for altered in (CONSUMER.replace(b'verify_permission(username, path, method)', b'verify_permission(path, username, method)'),
                        CONSUMER.replace(b'"prem_model.conf"', b'"other.conf"'),
                        CONSUMER.replace(b'from apps.pgo_permission.utils.adapter import Adapter', b'from other import Adapter'),
                        CONSUMER + b'\nif other_condition:\n verify_permission = other_function\n'):
            with self.assertRaises(AdmissionError):
                extract_rest_consumer(altered)

    def test_observed_omitted_or_swapped_membership_is_not_a_clean_comparison(self):
        changed = [["g", "reader", "alice"], *ROWS[1:]]
        self.assertFalse(compare_rest_policy(model(), changed, DOMAIN, ROWS)["accepted"])

    def test_override_is_source_literal_not_hardcoded_admin(self):
        domain = {**DOMAIN, "principals": ["admin", "owner"]}
        result = compare_rest_policy(model("owner"), ROWS, domain)
        observed = dict((tuple(request), edge[0]) for request, edge in zip(result["machine"]["alphabet"], result["machine"]["transitions"][0]))
        self.assertEqual(observed[("owner", "/outside", "POST")], "allow")
        self.assertEqual(observed[("admin", "/outside", "POST")], "deny")

    def test_rest_slash_and_nonempty_parameter_boundaries(self):
        self.assertFalse(segment_match("/x", "/x/*"))
        self.assertTrue(segment_match("/x/", "/x/*"))
        self.assertFalse(segment_match("/x/", "/x/:id"))
        self.assertFalse(segment_match("/x/a/b", "/x/:id"))
        self.assertTrue(segment_match("/x/a/b", "/x/:id/*"))

    def test_nonliteral_regex_or_new_model_function_is_not_guessed(self):
        for changed_model, rows in ((model().replace("keyMatch2", "customMatcher"), ROWS),
                                    (model(), [["p", "reader", "/x/.*", "GET"]]),
                                    (model(), [["p", "reader", "/x/*", "^GET$"]])):
            with self.assertRaises(AdmissionError):
                compare_rest_policy(changed_model, rows, DOMAIN)

    def test_empty_policy_and_bad_domains_do_not_pass(self):
        for rows, domain in (([["g", "alice", "reader"]], DOMAIN),
                             (ROWS, {**DOMAIN, "actions": []}), (ROWS, {**DOMAIN, "principals": ["alice", "alice"]})):
            with self.assertRaises(AdmissionError):
                compare_rest_policy(model(), rows, domain)

    def test_segment_reference_exhaustive_small_language_against_native_primitive(self):
        from itertools import product
        from casbin.util import key_match2
        patterns = ["/", "/*", "/x", "/x/*", "/:id", "/:id/x", "/x/:id", "/:first/:second", "/x/:id/*"]
        paths = {"/"}
        for length in (1, 2, 3):
            paths.update("/" + "/".join(parts) for parts in product(("", "x", "y"), repeat=length))
        for path in paths:
            for pattern in patterns:
                self.assertEqual(segment_match(path, pattern), key_match2(path, pattern), (path, pattern))


if __name__ == "__main__":
    unittest.main()
