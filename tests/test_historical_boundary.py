from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from historical_boundary import compare_session_filter, compare_sync_permissions, observe_permissions, reference_permissions
from native_casbin import AdmissionError
from observation_protocol import compare_observations, encode_observation

SESSION = b'''class SessionFetcher:
 def _build_sessions_api_data(self, sessions):
  session_blocks = []
  for session_ in sessions:
   if not session_.can_access(self.user):
    continue
   can_manage = self.user is not None and session_.can_manage(self.user)
   session_access_list = None
   serialized_session = self._serialize_session(session_)
   if self.user and session_.can_manage(self.user):
    session_access_list = self._serialize_access_list(session_)
   session_blocks.extend(self._serialize_session_block(b, serialized_session, session_access_list, can_manage) for b in session_.blocks)
  return session_blocks
'''

PERMISSION = b'''import inspect
from inspect import iscoroutinefunction
from functools import cached_property
from strawberry.exceptions import PermissionReturnedAwaitableInSyncContextError
class PermissionExtension:
 def resolve(self, next_, source, info, **kwargs):
  for permission in self.permissions:
   has_permission = permission.has_permission(source, info, **kwargs)
   if inspect.isawaitable(has_permission):
    if inspect.iscoroutine(has_permission):
     has_permission.close()
    raise PermissionReturnedAwaitableInSyncContextError(permission)
   if not has_permission:
    return self._on_unauthorized(permission)
  return next_(source, info, **kwargs)
 @cached_property
 def supports_sync(self):
  async_permissions = [True for permission in self.permissions if iscoroutinefunction(permission.has_permission)]
  return len(async_permissions) == 0
'''
OLD_PERMISSION = PERMISSION.replace(b'''   has_permission = permission.has_permission(source, info, **kwargs)
   if inspect.isawaitable(has_permission):
    if inspect.iscoroutine(has_permission):
     has_permission.close()
    raise PermissionReturnedAwaitableInSyncContextError(permission)
   if not has_permission:''', b'''   if not permission.has_permission(source, info, **kwargs):''')


class HistoricalBoundaryTests(unittest.TestCase):
    def test_session_filter_matches_all_supplied_visibility_vectors(self):
        result = compare_session_filter(SESSION)
        self.assertTrue(result["result"]["accepted"])
        self.assertEqual(result["result"]["cases"], 216)
        self.assertFalse(result["result"]["whole_application_verified"])

    def test_missing_and_inverted_session_filters_are_distinguished(self):
        for source in (SESSION.replace(b'   if not session_.can_access(self.user):\n    continue\n', b''),
                       SESSION.replace(b'if not session_.can_access', b'if session_.can_access')):
            result = compare_session_filter(source)
            self.assertFalse(result["result"]["accepted"])
            self.assertEqual(result["result"]["first_counterexample"]["length"], 1)

    def test_empty_blocks_do_not_turn_a_nonreturned_session_into_a_response_leak(self):
        old = SESSION.replace(b'   if not session_.can_access(self.user):\n    continue\n', b'')
        result = compare_session_filter(old, sessions=1)
        empty = [row for row in result["contexts"] if row["given_access_and_block_counts"] == ((False, 0),)][0]
        self.assertEqual(empty["expected_visible_slots"], empty["source_projected_visible_slots"])

    def test_filter_relocated_after_metadata_consumer_is_not_assumed_to_dominate(self):
        guard = b'   if not session_.can_access(self.user):\n    continue\n'
        source = SESSION.replace(guard, b'').replace(b'   serialized_session = self._serialize_session(session_)\n', b'   serialized_session = self._serialize_session(session_)\n' + guard)
        with self.assertRaises(AdmissionError):
            compare_session_filter(source)

    def test_wrong_access_principal_or_serializer_handoff_is_unsupported(self):
        for source in (SESSION.replace(b'can_access(self.user)', b'can_access(other_user)'),
                       SESSION.replace(b'self._serialize_session(session_)', b'self._serialize_session(other_session)')):
            with self.assertRaises(AdmissionError):
                compare_session_filter(source)

    def test_modified_output_loop_is_not_silently_discarded(self):
        with self.assertRaises(AdmissionError):
            compare_session_filter(SESSION.replace(b'  return session_blocks', b'  return []'))

    def test_patched_permission_shape_matches_independent_first_failure_contract(self):
        result = compare_sync_permissions(PERMISSION)
        self.assertTrue(result["result"]["accepted"])
        self.assertEqual(result["result"]["cases"], 57)

    def test_old_truth_test_does_not_resolve_coroutine_false_before_grant(self):
        result = compare_sync_permissions(OLD_PERMISSION)
        self.assertFalse(result["result"]["accepted"])
        index = result["given_return_records"].index(["coroutine_false"])
        self.assertEqual(result["source_projected_observations"][index]["decision"], "allow")
        self.assertTrue(result["reference_observations"][index]["flags"]["async_context_error"])

    def test_ordinary_boolean_permissions_are_not_called_vulnerable(self):
        result = compare_sync_permissions(OLD_PERMISSION)
        for tokens, left, right in zip(result["given_return_records"], result["reference_observations"], result["source_projected_observations"]):
            if all(token in ("boolean_false", "boolean_true") for token in tokens):
                self.assertEqual(left, right)

    def test_custom_falsy_awaitable_is_not_assumed_truthy(self):
        before = observe_permissions(["custom_falsy_awaitable"], "truth_test")
        after = reference_permissions(["custom_falsy_awaitable"])
        self.assertEqual(before["decision"], "deny")
        self.assertEqual(after["decision"], "deny")
        self.assertFalse(before["flags"]["async_context_error"])
        self.assertTrue(after["flags"]["async_context_error"])

    def test_prior_boolean_denial_short_circuits_a_later_awaitable(self):
        self.assertEqual(observe_permissions(["boolean_false", "coroutine_false"], "truth_test"),
                         reference_permissions(["boolean_false", "coroutine_false"]))

    def test_future_is_rejected_but_not_closed_as_a_coroutine(self):
        result = observe_permissions(["future_false"], "reject_awaitable")
        self.assertTrue(result["flags"]["async_context_error"])
        self.assertFalse(result["flags"]["coroutine_close_called"])

    def test_wrong_inspection_import_or_modified_sync_property_is_unadmitted(self):
        for source in (PERMISSION.replace(b'import inspect', b'import other as inspect'),
                       PERMISSION.replace(b'@cached_property', b'@other_decorator')):
            with self.assertRaises(AdmissionError):
                compare_sync_permissions(source)

    def test_class_rebinding_is_not_projected_as_the_old_method(self):
        for source in (SESSION + b'\n _build_sessions_api_data = other\n', PERMISSION + b'\n resolve = other\n'):
            with self.assertRaises(AdmissionError):
                compare_session_filter(source) if b'SessionFetcher' in source else compare_sync_permissions(source)

    def test_module_side_effects_are_not_executed(self):
        self.assertTrue(compare_sync_permissions(PERMISSION + b'\nraise RuntimeError("never execute source")\n')["result"]["accepted"])

    def test_observation_checker_preserves_error_even_when_both_decisions_deny(self):
        reference = [{"decision": "deny", "flags": {"error": True}}]
        observed = [{"decision": "deny", "flags": {"error": False}}]
        self.assertFalse(compare_observations(reference, observed, "owned scope")["accepted"])

    def test_later_observation_chunk_cannot_be_lost(self):
        reference = [{"decision": "deny", "flags": {"error": False}} for _ in range(33)]
        observed = [{"decision": "deny", "flags": {"error": False}} for _ in range(32)] + [{"decision": "allow", "flags": {"error": False}}]
        result = compare_observations(reference, observed, "owned scope")
        self.assertFalse(result["accepted"])
        self.assertEqual([part["comparison"]["accepted"] for part in result["all_parts"]], [True, True, False])

    def test_domain_decision_is_an_observed_bit_not_the_meta_event_acknowledgment(self):
        reference = [{"decision": "deny", "flags": {"error": False}}]
        observed = [{"decision": "allow", "flags": {"error": False}}]
        result = compare_observations(reference, observed, "owned scope")
        self.assertFalse(result["accepted"])
        self.assertTrue(all(edge[0] == "allow" for edge in result["all_parts"][0]["machine"]["transitions"][0]))
        self.assertIn("result_allowed", result["all_parts"][0]["machine"]["state_names"])

    def test_observation_schema_and_reserved_decision_field_are_checked(self):
        for flags in ({"result_allowed": False}, {1: False}, {"error": 1}, {"a" + str(i): False for i in range(7)}):
            with self.assertRaises(AdmissionError):
                compare_observations([{"decision": "deny", "flags": flags}], [{"decision": "deny", "flags": flags}], "owned scope")

    def test_unknown_return_record_and_unbounded_families_are_not_passes(self):
        with self.assertRaises(AdmissionError):
            observe_permissions(["unknown"], "truth_test")
        with self.assertRaises(AdmissionError):
            compare_sync_permissions(PERMISSION, maximum_permissions=3)
        with self.assertRaises(AdmissionError):
            compare_session_filter(SESSION, sessions=4)


if __name__ == "__main__":
    unittest.main()
