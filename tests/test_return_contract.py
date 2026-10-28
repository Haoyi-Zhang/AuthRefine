from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from return_contract import extract_tuple_contract, inspect_return_consumers, compare_boolean_guard

PRODUCER = 'class Policy:\n def decide(self, allowed):\n  if allowed:\n   return True, "allowed"\n  return False, "denied"\n'


class ReturnContractTests(unittest.TestCase):
    def test_every_explicit_tuple_return_is_bound(self):
        contract = extract_tuple_contract(PRODUCER, "Policy.decide")
        self.assertEqual(contract["tuple_arity"], 2)
        self.assertEqual(len(contract["normal_return_lines"]), 2)

    def test_early_scalar_or_implicit_return_is_not_ignored(self):
        for source in (PRODUCER.replace('return True, "allowed"', 'return True'), PRODUCER.replace('  return False, "denied"', '  pass')):
            with self.assertRaises(AdmissionError):
                extract_tuple_contract(source, "Policy.decide")

    def test_async_generator_and_decorated_producer_are_not_assumed(self):
        for source in (PRODUCER.replace(' def decide', ' async def decide'), PRODUCER.replace('  if allowed:', '  yield 1\n  if allowed:'),
                       PRODUCER.replace(' def decide', ' @unknown\n def decide')):
            with self.assertRaises(AdmissionError):
                extract_tuple_contract(source, "Policy.decide")

    def test_direct_not_use_has_shortest_interface_counterexample(self):
        contract = extract_tuple_contract(PRODUCER, "Policy.decide")
        calls = inspect_return_consumers('def f():\n if not policy.decide(False):\n  return "reject"', "policy.decide", contract)
        result = compare_boolean_guard(calls["boolean_guards"][0], contract)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["comparison"]["length"], 1)
        self.assertEqual(result["observations"][0], {"input": [False], "reference_test": True, "tuple_observed_test": False})

    def test_two_calls_keep_all_four_boolean_input_combinations(self):
        contract = extract_tuple_contract(PRODUCER, "Policy.decide")
        report = inspect_return_consumers('def f():\n if not policy.decide(x) and not policy.decide(y):\n  return "reject"', "policy.decide", contract)
        result = compare_boolean_guard(report["boolean_guards"][0], contract)
        self.assertEqual(len(result["observations"]), 4)
        self.assertFalse(result["accepted"])

    def test_tuple_unpack_is_not_a_boolean_misuse(self):
        contract = extract_tuple_contract(PRODUCER, "Policy.decide")
        report = inspect_return_consumers('def f():\n allowed, reason = policy.decide(x)\n if not allowed:\n  return "reject"', "policy.decide", contract)
        self.assertEqual(report["boolean_guards"], [])
        self.assertEqual(len(report["unpacked_calls"]), 1)

    def test_indexed_or_other_consumer_use_is_explicitly_unadmitted(self):
        contract = extract_tuple_contract(PRODUCER, "Policy.decide")
        report = inspect_return_consumers('def f():\n if not policy.decide(x)[0]:\n  return "reject"', "policy.decide", contract)
        self.assertEqual(report["boolean_guards"], [])
        self.assertEqual(len(report["other_calls"]), 1)
        self.assertEqual(len(report["opaque_guards"]), 1)

    def test_module_side_effects_are_not_executed(self):
        contract = extract_tuple_contract('raise RuntimeError("do not import")\n' + PRODUCER, "Policy.decide")
        self.assertFalse(contract["source_module_executed"])

    def test_shadowed_or_locally_rebound_receivers_are_not_bound(self):
        contract = extract_tuple_contract(PRODUCER, "Policy.decide")
        for source in ('def f(policy):\n if not policy.decide(x):\n  return "reject"',
                       'def f():\n policy = other\n if not policy.decide(x):\n  return "reject"'):
            report = inspect_return_consumers(source, "policy.decide", contract)
            self.assertEqual(report["boolean_guards"], [])
            self.assertEqual(len(report["other_calls"]), 1)


if __name__ == "__main__":
    unittest.main()
