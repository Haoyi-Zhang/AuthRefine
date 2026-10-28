from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from effect_slice import DataRecord, EffectInterpreter, extract_effect_program
from explicit_effect_body import extract_explicit_bodies
from native_casbin import AdmissionError


class ExplicitBodyTests(unittest.TestCase):
    def test_framework_body_is_explicitly_distinct_from_runtime_dispatch(self):
        source = b"class Service(UnknownFramework):\n def check(self, value):\n  return value.lower() == 'allow'\n"
        program, descriptor = extract_explicit_bodies(source, "Service", ["check"])
        instance = EffectInterpreter(program, DataRecord("receiver", {}), {})
        self.assertTrue(instance.run("check", ["ALLOW"]))
        self.assertFalse(instance.run("check", ["DENY"]))
        self.assertFalse(descriptor["receiver_dispatch_or_inheritance_proved"])
        self.assertEqual(descriptor["base_expressions_not_executed"], ["UnknownFramework"])
        with self.assertRaises(AdmissionError):
            extract_effect_program(source, "Service", ["check"])

    def test_selected_source_rebinding_does_not_become_an_admitted_body(self):
        for source in (b"class Service(Base):\n def check(self):\n  return True\n if flag:\n  check = other\n",
                       b"class Service(Base):\n def check(self):\n  return True\n def check(self):\n  return False\n",
                       b"class Service(Base):\n def __getattr__(self, name):\n  return True\n def check(self):\n  return True\n",
                       b"@replace\nclass Service(Base):\n def check(self):\n  return True\n",
                       b"class Service(Base):\n def check(self):\n  return True\nService = other\n"):
            with self.assertRaises(AdmissionError):
                extract_explicit_bodies(source, "Service", ["check"])

    def test_every_body_must_be_explicit_unique_and_in_the_supported_fragment(self):
        source = b"class Service(Base):\n def check(self):\n  return True\n"
        for names in ([], ["missing"], ["check", "check"]):
            with self.assertRaises(AdmissionError):
                extract_explicit_bodies(source, "Service", names)
        with self.assertRaises(AdmissionError):
            extract_explicit_bodies(b"class Service(Base):\n def check(self):\n  yield 1\n", "Service", ["check"])

    def test_unknown_source_field_cannot_invoke_an_arbitrary_object(self):
        source = b"class Service(Base):\n def check(self):\n  return self.provider.magic()\n"
        program, _ = extract_explicit_bodies(source, "Service", ["check"])
        with self.assertRaises(AdmissionError):
            EffectInterpreter(program, DataRecord("receiver", {"provider": object()}), {}).run("check", [])

    def test_lower_rejects_arguments_and_cannot_be_shadowed(self):
        source = b"class Service(Base):\n def check(self, value):\n  return value.lower(1)\n"
        program, _ = extract_explicit_bodies(source, "Service", ["check"])
        with self.assertRaises(AdmissionError):
            EffectInterpreter(program, DataRecord("receiver", {}), {}).run("check", ["ALLOW"])

    def test_lower_string_argument_cannot_fall_through_to_prefix_removal(self):
        for expression in ('value.lower("AL")', 'value.lower(prefix="AL")', 'value.lower("AL", "L")'):
            source = ("class Service(Base):\n def check(self, value):\n  return " + expression + "\n").encode()
            program, _ = extract_explicit_bodies(source, "Service", ["check"])
            with self.assertRaises(AdmissionError):
                EffectInterpreter(program, DataRecord("receiver", {}), {}).run("check", ["ALLOW"])


if __name__ == "__main__":
    unittest.main()
