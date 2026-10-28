from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from effect_slice import Capability, DataRecord, EffectInterpreter, extract_effect_program
from native_casbin import AdmissionError, _schema
from request_outcomes import compare_request_outcomes, outcome, reference_outcome, source_outcome


SOURCE = b'''from fastapi import HTTPException
from app.rbac.enforcer import SYSTEM_DOMAIN, get_enforcer
from app.observability.audit import audit
def _get_auth_user(request):
    user = getattr(request.state, "auth_user", None)
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user
async def _check_permission(request, obj, act):
    user = _get_auth_user(request)
    uid = str(user.get("uid") or user.get("user_id") or "")
    dom = user.get("domain", "")
    system_role = user.get("system_role", user.get("role", ""))
    if system_role in ("system_owner", "system_admin", "admin"):
        if dom == SYSTEM_DOMAIN or obj.startswith("system:"):
            return user
    if not uid or not dom:
        audit("denied", "failure", {"sub": uid})
        raise HTTPException(status_code=403, detail="missing context")
    enforcer = get_enforcer()
    allowed = await enforcer.enforce(uid, dom, obj, act)
    if not allowed:
        audit("denied", "failure", {"sub": uid}, username=user.get("username", ""))
        raise HTTPException(status_code=403, detail="not allowed")
    return user
'''
CONTROL = SOURCE.replace(b"await enforcer.enforce", b"enforcer.enforce")


def model():
    schema = _schema("rbac_with_domains")
    schema["matchers"]["m"] = 'g(r.sub, p.sub, r.dom) && r.dom == p.dom && (r.obj == p.obj || p.obj == "*") && (r.act == p.act || p.act == "*")'
    return "\n\n".join("[" + section + "]\n" + "\n".join(key + " = " + value for key, value in fields.items()) for section, fields in schema.items())


class RequestOutcomesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_result = compare_request_outcomes(SOURCE, model())
        cls.control_result = compare_request_outcomes(CONTROL, model())

    def test_selected_await_errors_are_not_ordinary_denials(self):
        self.assertFalse(self.source_result["comparison"]["accepted"])
        self.assertGreater(self.source_result["source_protocol_error_cases"], 0)
        self.assertEqual(self.source_result["source_protocol_error_cases"], self.source_result["different_case_observations"])

    def test_owned_direct_boolean_consumer_control_agrees(self):
        self.assertTrue(self.control_result["comparison"]["accepted"])
        self.assertEqual(self.control_result["different_case_observations"], 0)

    def test_complete_declared_context_denominator_and_native_work(self):
        self.assertEqual(self.source_result["cases"], 1176)
        self.assertEqual(self.source_result["counts"]["native"], self.source_result["source_protocol_error_cases"])
        self.assertFalse(self.source_result["whole_application_verified"])

    def test_identity_failures_are_distinct(self):
        self.assertEqual(reference_outcome(None, "board", "read"), outcome(fault="HTTP401"))
        self.assertEqual(reference_outcome({"uid": "", "domain": "t1"}, "board", "read"), outcome(fault="HTTP403", audit=True))

    def test_provider_error_precedes_consumer_and_does_not_become_denial(self):
        user = {"uid": "alice", "domain": "t1"}
        self.assertEqual(reference_outcome(user, "board", "read", False), outcome(fault="ProviderError"))

    def test_wrong_domain_control_is_detected_after_protocol_repair(self):
        source = CONTROL.replace(b"enforcer.enforce(uid, dom, obj, act)", b"enforcer.enforce(uid, 't2', obj, act)")
        self.assertFalse(compare_request_outcomes(source, model())["comparison"]["accepted"])

    def test_overwide_bypass_control_is_detected(self):
        source = CONTROL.replace(b'obj.startswith("system:")', b'obj.startswith("")')
        self.assertFalse(compare_request_outcomes(source, model())["comparison"]["accepted"])

    def test_rebound_source_function_is_not_a_clean_pass(self):
        with self.assertRaises(AdmissionError):
            compare_request_outcomes(CONTROL + b"_check_permission = other\n", model())

    def test_model_change_requires_a_new_contract(self):
        with self.assertRaises(AdmissionError):
            compare_request_outcomes(SOURCE, model().replace('r.dom == p.dom', 'true'))


if __name__ == "__main__":
    unittest.main()
