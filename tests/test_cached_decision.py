"""Owned cache/result/error fixtures; no application or integration tests run."""
from pathlib import Path
import sys
import unittest
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cached_decision import CachedDecisionEvaluation, REFERENCE_POLICY, compare_cached_decision
from effect_slice import SliceFault
from native_casbin import AdmissionError

MODEL = (Path(__file__).resolve().parents[1] / "external_inputs/casbin/rbac_model.conf").read_text(encoding="utf-8")
SOURCE = b'''from src.core.result import Success
from src.domain.enums import AuditAction
CACHE_PREFIX = 'authz'
CACHE_TTL_SECONDS = 300
class CasbinAdapter:
    async def check_permission(self, user_id, resource, action):
        cache_key = f'{CACHE_PREFIX}:{user_id}:{resource}:{action}'
        cache_result = await self._cache.get(cache_key)
        if isinstance(cache_result, Success) and cache_result.value is not None:
            allowed = cache_result.value == '1'
            self._logger.debug('hit')
            return allowed
        user_str = str(user_id)
        try:
            allowed = self._enforcer.enforce(user_str, resource, action)
        except Exception as e:
            self._logger.error('check error', error=e)
            allowed = False
        await self._cache.set(cache_key, '1' if allowed else '0', ttl=CACHE_TTL_SECONDS)
        audit_action = AuditAction.ACCESS_GRANTED if allowed else AuditAction.ACCESS_DENIED
        await self._audit.record(action=audit_action, user_id=user_id, context={'allowed': allowed})
        self._logger.info('check')
        return allowed
'''


class CachedDecisionTests(unittest.TestCase):
    def instance(self, mode, **kwargs):
        policy = REFERENCE_POLICY + '\ng, ' + str(UUID(int=1)) + ', readonly'
        return CachedDecisionEvaluation(SOURCE, MODEL, policy, mode, **kwargs)

    def test_complete_declared_domain_agrees_but_all_audited_claim_does_not(self):
        result = compare_cached_decision(SOURCE, MODEL, REFERENCE_POLICY)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["comparison"]["cases"], 360)
        self.assertFalse(result["all_checks_audited_contract"]["accepted"])
        self.assertEqual(result["cache_hit_cases_without_audit"], 216)
        self.assertEqual(result["counts"], {"native_attempts": 144, "actual_native_enforce": 72})

    def test_allow_cache_hit_avoids_native_and_audit_even_with_owned_native_fault(self):
        instance = self.instance("allow", native_fault=True)
        self.assertTrue(instance.call(UUID(int=1), "users", "manage"))
        self.assertEqual(instance.events, ["cache_get", "log_debug"])
        self.assertEqual(instance.counts["actual_native_enforce"], 0)
        self.assertEqual(instance.writes, [])

    def test_zero_or_other_cache_payload_is_false_not_truthy_success(self):
        for mode in ("deny", "other"):
            instance = self.instance(mode)
            with self.subTest(mode=mode):
                self.assertFalse(instance.call(UUID(int=1), "accounts", "read"))
                self.assertEqual(instance.counts["native_attempts"], 0)

    def test_miss_and_failure_result_fall_back_to_actual_native_async_enforcer(self):
        for mode in ("miss", "failure"):
            instance = self.instance(mode)
            with self.subTest(mode=mode):
                self.assertTrue(instance.call(UUID(int=1), "accounts", "read"))
                self.assertEqual(type(instance.engine).__name__, "AsyncEnforcer")
                self.assertEqual(instance.writes, [{"key": f'authz:{UUID(int=1)}:accounts:read', "value": "1", "ttl": 300}])
                self.assertIn("audit", instance.events)

    def test_owned_native_fault_fails_closed_and_records_error_effect(self):
        instance = self.instance("miss", native_fault=True)
        self.assertFalse(instance.call(UUID(int=1), "accounts", "read"))
        self.assertEqual(instance.counts["native_attempts"], 1)
        self.assertEqual(instance.counts["actual_native_enforce"], 0)
        self.assertIn("log_error", instance.events)
        self.assertEqual(instance.writes[0]["value"], "0")

    def test_cache_read_error_is_not_caught_as_native_denial(self):
        instance = self.instance("miss", provider_fault="cache_get")
        with self.assertRaises(SliceFault) as raised:
            instance.call(UUID(int=1), "accounts", "read")
        self.assertEqual(raised.exception.name, "CacheError")
        self.assertEqual(instance.events, ["cache_get"])

    def test_audit_error_preserves_earlier_cache_write_and_does_not_return_allow(self):
        instance = self.instance("miss", provider_fault="audit")
        with self.assertRaises(SliceFault) as raised:
            instance.call(UUID(int=1), "accounts", "read")
        self.assertEqual(raised.exception.name, "AuditError")
        self.assertEqual(instance.writes[0]["value"], "1")
        self.assertNotIn("log_info", instance.events)

    def test_cache_decode_or_fail_open_source_controls_are_detected(self):
        for old, new in ((b"cache_result.value == '1'", b"cache_result.value == '0'"),
                         (b"allowed = False", b"allowed = True")):
            with self.subTest(old=old):
                self.assertFalse(compare_cached_decision(SOURCE.replace(old, new), MODEL, REFERENCE_POLICY)["accepted"])

    def test_namespace_and_ttl_controls_are_observed(self):
        for old, new in ((b"CACHE_TTL_SECONDS = 300", b"CACHE_TTL_SECONDS = 30"), (b"CACHE_PREFIX = 'authz'", b"CACHE_PREFIX = 'other'")):
            with self.subTest(old=old):
                self.assertFalse(compare_cached_decision(SOURCE.replace(old, new), MODEL, REFERENCE_POLICY)["accepted"])

    def test_conditional_global_rebinding_is_unsupported(self):
        with self.assertRaises(AdmissionError):
            self_source = SOURCE + b"\nif True:\n    CACHE_TTL_SECONDS = 0\n"
            CachedDecisionEvaluation(self_source, MODEL, REFERENCE_POLICY, "miss")

    def test_losing_cache_await_is_unsupported_without_eager_provider_execution(self):
        source = SOURCE.replace(b"await self._cache.get(cache_key)", b"self._cache.get(cache_key)")
        instance = CachedDecisionEvaluation(source, MODEL, REFERENCE_POLICY, "miss")
        with self.assertRaises(AdmissionError):
            instance.call(UUID(int=1), "accounts", "read")
        self.assertEqual(instance.events, [])

    def test_awaited_boolean_is_caught_as_error_not_an_ordinary_allow(self):
        source = SOURCE.replace(b"self._enforcer.enforce(user_str, resource, action)", b"await self._enforcer.enforce(user_str, resource, action)")
        policy = REFERENCE_POLICY + '\ng, ' + str(UUID(int=1)) + ', readonly'
        instance = CachedDecisionEvaluation(source, MODEL, policy, "miss")
        # Python's explicit except-Exception branch catches the TypeError;
        # retain its error/log/write effects and detect the changed contract.
        self.assertFalse(instance.call(UUID(int=1), "accounts", "read"))
        self.assertEqual(instance.counts["actual_native_enforce"], 1)
        self.assertIn("log_error", instance.events)
        self.assertEqual(instance.writes[0]["value"], "0")
        self.assertFalse(compare_cached_decision(source, MODEL, REFERENCE_POLICY)["accepted"])

    def test_independent_expected_matrix_is_not_silently_applied_to_other_policy(self):
        with self.assertRaises(AdmissionError):
            compare_cached_decision(SOURCE, MODEL, REFERENCE_POLICY.replace("accounts", "different"))


if __name__ == "__main__":
    unittest.main()
