from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from transform_guard import compare_transform_guard

AFTER = b'''class FastMCP:
    async def get_tool(self, name, version=None):
        injected = self._get_injected_tool(name) if hashed_lookup_target(self) is None else None
        if injected is not None:
            return injected if await _component_auth_allows(injected) else None
        tool = await super().get_tool(name, version)
        if tool is None:
            return None
        tools = await apply_session_transforms([tool])
        if tools and is_enabled(tools[0]) and await _component_auth_allows(tools[0]):
            return tools[0]
        if version is not None:
            return None
        return complicated_fallback()
'''
BEFORE = AFTER.replace(b" and await _component_auth_allows(tools[0])", b"").replace(b"_component_auth_allows(injected)", b"_tool_auth_allows(injected)")


class TransformGuardTests(unittest.TestCase):
    def test_actual_guard_shapes_separate_selected_published_repair(self):
        before, after = compare_transform_guard(BEFORE), compare_transform_guard(AFTER)
        self.assertFalse(before["accepted"])
        self.assertTrue(after["accepted"])
        self.assertEqual(before["comparison"]["cases"], 32)
        self.assertEqual(before["different_observations"], 2)
        self.assertEqual(before["unauthorized_return_contexts"], 1)

    def test_absent_provider_or_unauthorized_original_does_not_execute_guard(self):
        result = compare_transform_guard(AFTER)
        for row in result["cases"]:
            if not row["provider_found"] or not row["original_allowed"]:
                self.assertEqual(row["auth_calls"], 0)
                self.assertFalse(row["observed_return"])

    def test_removed_or_disabled_transform_never_returns_or_auth_checks(self):
        result = compare_transform_guard(AFTER)
        for row in result["cases"]:
            if not row["transformed_present"] or not row["enabled"]:
                self.assertFalse(row["observed_return"])
                self.assertEqual(row["auth_calls"], 0)

    def test_parameter_default_injection_and_provider_changes_not_guessed(self):
        for old, new in ((b"version=None", b"version='latest'"), (b"self._get_injected_tool(name)", b"unbound_lookup(name)"),
                         (b"await super().get_tool(name, version)", b"await super().get_tool(version, name)")):
            with self.subTest(old=old), self.assertRaises(AdmissionError):
                compare_transform_guard(AFTER.replace(old, new))

    def test_modified_return_fallthrough_or_discarded_authorization_await_is_unsupported(self):
        for old, new in ((b"return tools[0]", b"return tool"), (b"if version is not None:", b"if version is None:"),
                         (b"await _component_auth_allows(tools[0])", b"_component_auth_allows(tools[0])")):
            with self.subTest(old=old), self.assertRaises(AdmissionError):
                compare_transform_guard(AFTER.replace(old, new))

    def test_unexecuted_fallback_is_explicitly_excluded_not_a_full_method_certificate(self):
        result = compare_transform_guard(AFTER)
        self.assertFalse(result["component_or_server_or_advisory_example_executed"])
        self.assertFalse(result["actual_auth_predicate_provider_or_full_lookup_verified"])
        self.assertEqual(result["descriptor"]["excluded_fallback_statement_count"], 1)


if __name__ == "__main__":
    unittest.main()
