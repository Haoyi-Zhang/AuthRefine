from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from source_paths import discover_authorization_paths
from native_casbin import AdmissionError


class SourcePathTests(unittest.TestCase):
    def test_indirect_free_function_entry_is_discovered(self):
        result = discover_authorization_paths(b'def verify(*args):\n return engine.enforce(*args)\nclass Permission:\n def has_permission(self, request):\n  return verify(request.user, request.path, request.method)\n')
        self.assertEqual(result["direct_enforce_functions"], 1)
        self.assertEqual(result["indirect_candidate_functions"], 1)
        self.assertEqual(result["candidate_functions"][1]["candidate_path"][0]["callee"], "verify")

    def test_self_candidate_is_not_reported_as_runtime_bound(self):
        result = discover_authorization_paths(b'class C:\n def sink(self,x):\n  return self.engine.enforce(x)\n def check(self,x):\n  return self.sink(x)\n')
        candidate = result["candidate_functions"][1]
        self.assertFalse(candidate["candidate_path"][0]["runtime_binding_verified"])

    def test_ambiguous_or_conditional_targets_remain_candidates_not_proofs(self):
        source = b'if choice:\n def sink(x):\n  return engine.enforce(x)\ndef check(x):\n return sink(x)\n'
        result = discover_authorization_paths(source)
        self.assertTrue(result["candidate_functions"][1]["candidate_path"][0]["ambiguous"])

    def test_unrelated_and_shadowed_names_not_false_resolved(self):
        result = discover_authorization_paths(b'def sink(x):\n return engine.enforce(x)\ndef check(sink,x):\n return sink(x)\ndef unrelated():\n return True\n')
        self.assertEqual(len(result["candidate_functions"]), 1)
        self.assertEqual(len(result["unresolved_local_calls"]), 1)

    def test_cycles_terminate_and_module_effects_do_not_run(self):
        source = b'raise RuntimeError("never run")\ndef sink(x):\n check(x)\n return engine.enforce(x)\ndef check(x):\n return sink(x)\n'
        result = discover_authorization_paths(source)
        self.assertEqual(len(result["candidate_functions"]), 2)

    def test_bad_source_is_not_an_empty_success(self):
        with self.assertRaises(AdmissionError):
            discover_authorization_paths(b'not valid @@@')

    def test_varargs_do_not_become_false_module_bindings(self):
        source = b'def sink(x):\n return engine.enforce(x)\ndef check(*sink):\n return sink()\n'
        result = discover_authorization_paths(source)
        self.assertEqual(len(result["candidate_functions"]), 1)
        self.assertTrue(result["unresolved_local_calls"])

    def test_async_function_does_not_make_every_native_call_awaited(self):
        result = discover_authorization_paths(b'async def check(x):\n a = engine.enforce(x)\n b = await engine.enforce(x)\n return a, b\n')
        calls = result["candidate_functions"][0]["direct_sink_protocols"]
        self.assertEqual([call["directly_awaited"] for call in calls], [False, True])
        self.assertTrue(all(call["native_return_protocol_verified"] is False for call in calls))

    def test_nested_await_wrapper_is_not_misidentified_as_a_direct_native_await(self):
        result = discover_authorization_paths(b'async def check(x):\n return await wrap(engine.enforce(x))\n')
        self.assertFalse(result["candidate_functions"][0]["direct_sink_protocols"][0]["directly_awaited"])


if __name__ == "__main__":
    unittest.main()
