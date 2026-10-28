from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from frontend_scan import discover, scan_request_frontends
from native_casbin import AdmissionError, _schema

def model_text():
    return "\n".join("[" + section + "]\n" + "\n".join(key + " = " + value for key, value in fields.items())
                     for section, fields in _schema("rbac_path_wildcards").items())

SOURCE = b'''
from starlette.requests import Request
from starlette.authentication import BaseUser
class Decoder:
    def check(self, scope, receive):
        user = scope["user"]
        assert isinstance(user, BaseUser)
        name = user.display_name if user.is_authenticated else "anonymous"
        request = Request(scope, receive)
        return self.enforcer.enforce(name, request.url.path, request.method)
'''
DOMAIN = {"principals": ["alice", "anonymous"], "resources": ["/records", "/outside"], "actions": ["GET"]}
POLICY = "p, alice, /records, GET"


class FrontendScanTests(unittest.TestCase):
    def test_scan_does_not_need_a_manually_selected_function(self):
        result = scan_request_frontends(SOURCE, model_text(), POLICY, DOMAIN)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["candidate_functions"], 1)
        self.assertEqual(result["native_request_contexts"], 8)
        self.assertFalse(result["whole_application_verified"])

    def test_unsupported_functions_are_not_silently_omitted(self):
        source = SOURCE + b'\n    def opaque(self, value):\n        return self.enforcer.enforce(value)\n'
        result = scan_request_frontends(source, model_text(), POLICY, DOMAIN)
        self.assertIsNone(result["accepted"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["functions_with_comparisons"], 1)
        self.assertEqual(result["unsupported_or_inconclusive_functions"], 1)

    def test_detected_mismatch_survives_other_unsupported_functions(self):
        source = SOURCE.replace(b'return self.enforcer.enforce(name, request.url.path, request.method)',
                                b'return not self.enforcer.enforce(name, request.url.path, request.method)')
        source += b'\n    def opaque(self, value):\n        return self.enforcer.enforce(value)\n'
        result = scan_request_frontends(source, model_text(), POLICY, DOMAIN)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["functions_with_mismatches"], 1)

    def test_nested_function_does_not_double_count_its_parent(self):
        found = discover(b'def outer():\n    def inner(x):\n        return engine.enforce(x)\n    return inner\n')
        self.assertEqual([item["function"] for item in found], ["outer.inner"])

    def test_conditional_definition_is_retained_as_an_unsupported_candidate(self):
        source = b'if feature:\n    def check(x):\n        return engine.enforce(x)\n'
        self.assertEqual([item["function"] for item in discover(source)], ["check"])
        result = scan_request_frontends(source, model_text(), POLICY, DOMAIN)
        self.assertIsNone(result["accepted"])
        self.assertEqual(result["unsupported_or_inconclusive_functions"], 1)

    def test_empty_scan_cannot_be_reported_as_all_clear(self):
        result = scan_request_frontends(b'def unrelated():\n    return True\n', model_text(), POLICY, DOMAIN)
        self.assertIsNone(result["accepted"])
        self.assertEqual(result["status"], "unsupported")

    def test_aggregate_work_limit_is_checked(self):
        with self.assertRaises(AdmissionError):
            scan_request_frontends(SOURCE, model_text(), POLICY,
                                   {"principals": ["u"] * 100, "resources": ["r"] * 100, "actions": ["a"] * 100})


if __name__ == "__main__":
    unittest.main()
