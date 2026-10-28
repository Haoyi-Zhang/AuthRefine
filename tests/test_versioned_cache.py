"""Owned fixtures for admitted cache semantics, not an upstream application test."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from effect_slice import SliceFault
from native_casbin import AdmissionError
from versioned_cache import VersionedEvaluation, compare_versioned_cache

MODEL = '''[request_definition]
r = subjects, obj, act
[policy_definition]
p = sub, obj, act, eft
[policy_effect]
e = some(where (p_eft == allow)) && !some(where (p_eft == deny))
[matchers]
m = subjectMatch(r.subjects, p.sub) && r.obj == p.obj && r.act == p.act
'''
SOURCE = b'''import casbin
from app.entities.auth import AuthContext, PermissionSnapshot
def _subject_match(subjects, policy_subject):
    return policy_subject in subjects
class AuthorizationService:
    async def authorize(self, auth, resource, action):
        cache = await self._get_cache()
        subjects = self._subjects(auth)
        return bool(cache.enforcer.enforce(subjects, resource, action))
    async def require(self, auth, resource, action):
        if not await self.authorize(auth, resource, action):
            raise AuthorizationError('permission denied')
    async def _get_cache(self):
        try:
            version = await self.repository.current_version()
            cache = self._cache_state.cache
            if cache is not None and cache.version == version:
                return cache
            async with self._cache_state.reload_lock:
                version = await self.repository.current_version()
                cache = self._cache_state.cache
                if cache is not None and cache.version == version:
                    return cache
                policies = tuple(await self.repository.list_active())
                enforcer = casbin.Enforcer(str(self.model_path))
                enforcer.add_function('subjectMatch', _subject_match)
                for policy in policies:
                    enforcer.add_policy(policy.subject, policy.resource, policy.action, policy.effect)
                cache = _PolicyCache(version, enforcer, policies)
                self._cache_state.cache = cache
                return cache
        except Exception as exc:
            raise AuthorizationUnavailableError('backend unavailable') from exc
    @staticmethod
    def _subjects(auth):
        return (f'user:{auth.user_id}', *(f'role:{role}' for role in sorted(auth.roles)))
    async def build_snapshot(self, auth):
        cache = await self._get_cache()
        subjects = frozenset(self._subjects(auth))
        applicable = tuple(policy for policy in cache.policies if policy.subject in subjects)
        async def allowed_values(prefix, action):
            resources = {policy.resource for policy in applicable if policy.resource.startswith(prefix) and policy.action == action}
            values = {resource.removeprefix(prefix) for resource in resources if await self.authorize(auth, resource, action)}
            return frozenset(values)
        return PermissionSnapshot(policy_version=cache.version,
            allowed_metrics=await allowed_values('metric:', 'read'),
            allowed_tables=await allowed_values('table:', 'read'),
            allowed_columns=await allowed_values('column:', 'read'),
            allowed_department_ids=await allowed_values('row:department:', 'read'),
            sql_fallback_allowed=await self.authorize(auth, 'api:sql-fallback', 'execute'))
'''
EPOCHS = [{"version": 7, "rows": [["role:reader", "metric:sales", "read", "allow"],
    ["role:blocked", "metric:sales", "read", "deny"], ["user:alice", "table:orders", "read", "allow"]]},
          {"version": 8, "rows": [["role:reader", "metric:sales", "read", "deny"], ["role:reader", "table:returns", "read", "allow"]]}]
REQUESTS = [["metric:sales", "read"], ["table:orders", "read"], ["table:returns", "read"]]


class VersionedCacheTests(unittest.TestCase):
    def test_cold_warm_and_changed_epochs_match_native_and_snapshot_contract(self):
        result = compare_versioned_cache(SOURCE, MODEL, EPOCHS, REQUESTS)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["authorization"]["cases"], 96)
        self.assertEqual(result["snapshots"]["cases"], 32)
        self.assertTrue(all(row["policy_reads"] == 2 and row["native_constructions"] == 2 for row in result["counts_by_identity"]))
        self.assertFalse(result["mysql_isolation_or_concurrent_snapshot_consistency_verified"])

    def test_deny_overrides_allow_for_a_tuple_subject(self):
        instance = VersionedEvaluation(SOURCE, MODEL, EPOCHS)
        self.assertTrue(instance.call("authorize", "alice", ["reader"], "metric:sales", "read"))
        self.assertFalse(instance.call("authorize", "alice", ["reader", "blocked"], "metric:sales", "read"))

    def test_snapshot_uses_exact_prefixes_and_denial_filter(self):
        instance = VersionedEvaluation(SOURCE, MODEL, EPOCHS)
        value = instance.call("build_snapshot", "alice", ["reader", "blocked"])
        self.assertEqual(value.fields["allowed_metrics"], frozenset())
        self.assertEqual(value.fields["allowed_tables"], frozenset({"orders"}))
        self.assertEqual(value.fields["policy_version"], 7)

    def test_reused_cache_load_is_not_recounted_as_another_source_application(self):
        instance = VersionedEvaluation(SOURCE, MODEL, EPOCHS)
        for _ in range(4):
            instance.call("authorize", "alice", ["reader"], "metric:sales", "read")
        self.assertEqual(instance.counts["policy_reads"], 1)
        instance.epoch = 1
        self.assertFalse(instance.call("authorize", "alice", ["reader"], "metric:sales", "read"))
        self.assertEqual(instance.counts["policy_reads"], 2)

    def test_role_prefix_and_version_comparison_faults_are_detected(self):
        for before, after in ((b"f'role:{role}'", b"f'roles:{role}'"), (b"cache.version == version", b"cache.version != version")):
            with self.subTest(before=before):
                self.assertFalse(compare_versioned_cache(SOURCE.replace(before, after), MODEL, EPOCHS, REQUESTS)["accepted"])

    def test_snapshot_field_fault_can_fail_even_when_authorization_matches(self):
        changed = SOURCE.replace(b"allowed_values('table:', 'read')", b"allowed_values('metric:', 'read')")
        result = compare_versioned_cache(changed, MODEL, EPOCHS, REQUESTS)
        self.assertTrue(result["authorization"]["accepted"])
        self.assertFalse(result["snapshots"]["accepted"])

    def test_provider_errors_remain_unavailable_not_ordinary_denial(self):
        for fault in ("version", "policies"):
            instance = VersionedEvaluation(SOURCE, MODEL, EPOCHS)
            instance.fault = fault
            with self.subTest(fault=fault), self.assertRaises(SliceFault) as raised:
                instance.call("authorize", "alice", ["reader"], "metric:sales", "read")
            self.assertEqual(raised.exception.name, "AuthorizationUnavailableError")

    def test_require_denial_is_distinct_from_provider_failure(self):
        instance = VersionedEvaluation(SOURCE, MODEL, EPOCHS)
        with self.assertRaises(SliceFault) as raised:
            instance.call("require", "bob", [], "metric:sales", "read")
        self.assertEqual(raised.exception.name, "AuthorizationError")

    def test_empty_epoch_still_builds_an_empty_denying_snapshot(self):
        result = compare_versioned_cache(SOURCE, MODEL, [{"version": 1, "rows": []}], REQUESTS)
        self.assertTrue(result["accepted"])

    def test_unknown_native_model_or_package_binding_is_not_guessed(self):
        for source, model in ((SOURCE.replace(b"import casbin", b"import unrelated as casbin"), MODEL),
                              (SOURCE, MODEL.replace("subjectMatch", "anotherMatch"))):
            with self.subTest(model=model), self.assertRaises(AdmissionError):
                VersionedEvaluation(source, model, EPOCHS)

    def test_duplicate_epochs_boolean_versions_and_injected_policy_fields_rejected(self):
        for epochs in ([EPOCHS[0], EPOCHS[0]], [{"version": True, "rows": []}], [{"version": 1, "rows": [["*", "metric:x", "read", "allow"]]}]):
            with self.subTest(epochs=epochs), self.assertRaises(AdmissionError):
                VersionedEvaluation(SOURCE, MODEL, epochs)

    def test_missing_await_does_not_execute_provider_early(self):
        changed = SOURCE.replace(b"version = await self.repository.current_version()", b"version = self.repository.current_version()")
        instance = VersionedEvaluation(changed, MODEL, EPOCHS)
        with self.assertRaises(AdmissionError):
            instance.call("authorize", "alice", ["reader"], "metric:sales", "read")
        self.assertEqual(instance.counts["version_reads"], 0)


if __name__ == "__main__":
    unittest.main()
