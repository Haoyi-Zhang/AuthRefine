from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError, EXTRA_MATCHERS, EXPECTED_MATCHER
from python_wrapper import compare_wrapper, extract_wrapper

ROOT = Path(__file__).resolve().parents[1]
MODEL = (ROOT / "external_inputs/casbin/basic_model.conf").read_text(encoding="utf-8")
POLICY = "p, alice, data1, read\np, bob, data2, write"


class PythonWrapperTests(unittest.TestCase):
    def compare(self, expression):
        source = "def authorize(e, subject, resource, action):\n    return " + expression
        return compare_wrapper(source, "authorize", ["subject", "resource", "action"], "e", MODEL, POLICY)

    def test_identity_wrapper(self):
        result = self.compare("e.enforce(subject, resource, action)")
        self.assertTrue(result["accepted"])
        self.assertFalse(result["extraction"]["source_module_executed"])
        self.assertFalse(result["application_security_verified"])

    def test_owned_parameter_permutation_is_found(self):
        result = self.compare("e.enforce(resource, subject, action)")
        self.assertFalse(result["accepted"])
        self.assertEqual(result["comparison"]["length"], 1)

    def test_owned_allow_all_control_is_found_without_native_calls(self):
        result = self.compare("True")
        self.assertFalse(result["accepted"])
        self.assertEqual(result["native_enforce_calls"], 0)

    def test_owned_inversion_control_is_found(self):
        self.assertFalse(self.compare("not e.enforce(subject, resource, action)")["accepted"])

    def test_module_side_effects_are_never_executed(self):
        source = "raise RuntimeError('must not execute module')\n" + \
                 "def authorize(e, u, o, a):\n    return e.enforce(u, o, a)"
        self.assertTrue(compare_wrapper(source, "authorize", ["u", "o", "a"], "e", MODEL, POLICY)["accepted"])

    def test_attribute_inputs_require_a_decoder(self):
        with self.assertRaises(AdmissionError):
            self.compare("e.enforce(subject.name, resource, action)")

    def test_side_effecting_body_is_not_silently_sliced_away(self):
        source = "def authorize(e, u, o, a):\n    mutate_permissions()\n    return e.enforce(u, o, a)"
        with self.assertRaises(AdmissionError):
            extract_wrapper(source, "authorize", ["u", "o", "a"], "e")

    def test_unbound_native_receiver_not_assumed_to_be_casbin(self):
        source = "def authorize(u, o, a):\n    return unrelated.enforce(u, o, a)"
        with self.assertRaises(AdmissionError):
            extract_wrapper(source, "authorize", ["u", "o", "a"], "unrelated")

    def test_decorators_are_not_ignored(self):
        source = "@changes_behavior\ndef authorize(e, u, o, a):\n    return e.enforce(u, o, a)"
        with self.assertRaises(AdmissionError):
            extract_wrapper(source, "authorize", ["u", "o", "a"], "e")

    def test_engine_is_not_also_a_principal_string(self):
        source = "def authorize(e, o, a):\n    return e.enforce(e, o, a)"
        with self.assertRaises(AdmissionError):
            extract_wrapper(source, "authorize", ["e", "o", "a"], "e")

    def test_wildcard_configuration_is_not_misconverted_as_literal_rbac(self):
        rbac = (ROOT / "external_inputs/casbin/rbac_model.conf").read_text(encoding="utf-8")
        model = rbac.replace(EXPECTED_MATCHER["rbac"], EXTRA_MATCHERS["rbac_wildcards"])
        source = "def authorize(e, u, o, a):\n return e.enforce(u, o, a)"
        with self.assertRaises(AdmissionError) as caught:
            compare_wrapper(source, "authorize", ["u", "o", "a"], "e", model, "p, *, data, *")
        self.assertEqual(caught.exception.status, "unsupported")


if __name__ == "__main__":
    unittest.main()
