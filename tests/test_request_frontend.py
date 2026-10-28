from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError, EXTRA_MATCHERS, _engine, admit_configuration
from request_frontend import compare_request_frontend, evaluate_frontend, extract_frontend

SOURCE = '''from starlette.requests import Request
from starlette.authentication import BaseUser
class Gate:
    def check(self, scope, receive):
        req = Request(scope, receive)
        if "user" not in scope:
            raise RuntimeError("user observation required")
        assert isinstance(req.user, BaseUser)
        actor = req.user.display_name if req.user.is_authenticated else "anonymous"
        return self.enforcer.enforce(actor, req.url.path, req.method)
'''
MODEL = '''[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = ''' + EXTRA_MATCHERS["rbac_wildcards"]
POLICY = "p, reader, /data, GET\ng, alice, reader"
DOMAIN = {"principals": ["alice", "anonymous", "bob"], "resources": ["/data", "/outside"], "actions": ["GET", "POST"]}


class RequestFrontendTests(unittest.TestCase):
    def test_native_request_decoding_matches_the_supplied_identity_contract(self):
        result = compare_request_frontend(SOURCE, "Gate.check", MODEL, POLICY, DOMAIN)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["native_request_contexts"], 24)
        self.assertFalse(result["authentication_producer_verified"])
        self.assertFalse(result["outer_dispatch_and_all_entry_points_verified"])

    def test_owned_identity_field_change_is_detected(self):
        changed = SOURCE.replace('req.user.display_name if req.user.is_authenticated else "anonymous"', '"alice"')
        self.assertFalse(compare_request_frontend(changed, "Gate.check", MODEL, POLICY, DOMAIN)["accepted"])

    def test_missing_user_is_rejected_not_an_authorization_pass(self):
        function = extract_frontend(SOURCE, "Gate.check")
        engine = _engine(admit_configuration(MODEL, POLICY))
        with self.assertRaises(AdmissionError) as ctx:
            evaluate_frontend(function, {"type": "http"}, engine)
        self.assertEqual(ctx.exception.status, "input_rejected")

    def test_unknown_call_in_an_unreached_branch_is_not_dropped(self):
        changed = SOURCE.replace('raise RuntimeError("user observation required")', 'raise custom_exception()')
        with self.assertRaises(AdmissionError):
            extract_frontend(changed, "Gate.check")

    def test_trusted_import_rebinding_is_not_ignored(self):
        changed = SOURCE + "\nRequest = something_else\n"
        with self.assertRaises(AdmissionError):
            extract_frontend(changed, "Gate.check")

    def test_unsupported_side_effecting_assignment_is_rejected(self):
        changed = SOURCE.replace('actor = req.user.display_name', 'self.cached_actor = req.user.display_name')
        with self.assertRaises(AdmissionError):
            extract_frontend(changed, "Gate.check")

    def test_native_url_normalization_is_not_assumed_to_preserve_raw_path(self):
        # Owned boundary control, not a reported application vulnerability.
        domain = {**DOMAIN, "resources": ["/data?draft"]}
        result = compare_request_frontend(SOURCE, "Gate.check", MODEL,
                                           POLICY.replace("/data,", "/data?draft,"), domain)
        self.assertFalse(result["accepted"])

    def test_invalid_primitive_arity_is_rejected_before_branch_execution(self):
        changed = SOURCE.replace('RuntimeError("user observation required")', 'RuntimeError()')
        with self.assertRaises(AdmissionError):
            extract_frontend(changed, "Gate.check")

    def test_function_definition_cannot_rebind_request_class(self):
        with self.assertRaises(AdmissionError):
            extract_frontend(SOURCE + "\ndef Request(*args):\n    return None\n", "Gate.check")

    def test_native_receiver_rebinding_cannot_produce_a_false_pass(self):
        changed = SOURCE.replace("        req = Request(scope, receive)",
                                 "        self = scope\n        req = Request(scope, receive)")
        with self.assertRaises(AdmissionError):
            compare_request_frontend(changed, "Gate.check", MODEL, POLICY, DOMAIN)

    def test_chained_exception_is_not_silently_reinterpreted(self):
        changed = SOURCE.replace('raise RuntimeError("user observation required")',
                                 'raise RuntimeError("user observation required") from unknown_cause')
        with self.assertRaises(AdmissionError):
            extract_frontend(changed, "Gate.check")


if __name__ == "__main__":
    unittest.main()
