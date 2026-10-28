from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from call_handoff import extract_call_handoff, project_handoff
from native_casbin import AdmissionError

SOURCE = '''raise RuntimeError("must never import")
async def submit(subject, resource, action):
    if not guard.check(subject, item=resource, verb=f'"{action}"'):
        return "denied"
    return unrelated_dispatch()
'''


class CallHandoffTests(unittest.TestCase):
    def extract(self, source=SOURCE):
        return extract_call_handoff(source, "submit", "guard.check", ["user", "item", "verb"])

    def test_mixed_positional_keywords_and_quote_template(self):
        descriptor = self.extract()
        self.assertEqual(project_handoff(descriptor, {"subject": "u", "resource": "r", "action": "read"}), ["u", "r", '"read"'])
        self.assertFalse(descriptor["source_module_executed"])
        self.assertFalse(descriptor["caller_path_and_authentication_verified"])

    def test_nested_function_call_does_not_add_a_caller_site(self):
        source = SOURCE.replace('    if not', '    def helper():\n        return guard.check("x", "y", "z")\n    if not')
        self.assertEqual(self.extract(source)["callee"], "guard.check")

    def test_multiple_real_calls_are_ambiguous(self):
        with self.assertRaises(AdmissionError):
            self.extract(SOURCE.replace('    return unrelated_dispatch()', '    return guard.check(subject, resource, action)'))

    def test_parameter_rebinding_is_not_ignored(self):
        with self.assertRaises(AdmissionError):
            self.extract(SOURCE.replace('    if not', '    action = "write"\n    if not'))

    def test_conversion_or_format_spec_is_not_assumed(self):
        for value in ('{action!r}', '{action:10}'):
            with self.assertRaises(AdmissionError):
                self.extract(SOURCE.replace('{action}', value))

    def test_keyword_unpack_or_duplicate_is_not_assumed(self):
        for call in ('guard.check(subject, **options)', 'guard.check(subject, user=subject, item=resource, verb=action)'):
            with self.assertRaises(AdmissionError):
                self.extract(SOURCE.replace('guard.check(subject, item=resource, verb=f\'"{action}"\')', call))

    def test_only_typed_supplied_records_are_admitted(self):
        for record in ({"subject": "u"}, {"subject": "u", "resource": "r", "action": None}):
            with self.assertRaises(AdmissionError):
                project_handoff(self.extract(), record)

    def test_owned_missing_quote_control_changes_the_handoff(self):
        record = {"subject": "u", "resource": "r", "action": "read"}
        changed = self.extract(SOURCE.replace('f\'"{action}"\'', 'action'))
        self.assertNotEqual(project_handoff(self.extract(), record), project_handoff(changed, record))


if __name__ == "__main__":
    unittest.main()
