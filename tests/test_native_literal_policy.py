from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError, _engine, admit_configuration
from native_literal_policy import admit_native_literals
from python_wrapper import compare_wrapper

ROOT = Path(__file__).resolve().parents[1]
MODEL = (ROOT / "external_inputs/casbin/rbac_with_resource_roles_model.conf").read_text(encoding="utf-8")
SOURCE = 'class Guard:\n def check(self, user, item, verb):\n  return self.engine.enforce(user, item, verb)\n'
POLICY = '// permission (p)\np, operator, motor, "set speed"\ng, reader, operator\ng2, device, motor\n'


class NativeLiteralPolicyTests(unittest.TestCase):
    def test_quotes_remain_literal_identity_characters(self):
        config = admit_native_literals(MODEL, POLICY)
        self.assertEqual(config.rows[0][-1], '"set speed"')
        engine = _engine(config)
        self.assertTrue(engine.enforce("reader", "device", '"set speed"'))
        self.assertFalse(engine.enforce("reader", "device", "set speed"))

    def test_original_native_text_and_source_lines_are_retained(self):
        config = admit_native_literals(MODEL, POLICY)
        self.assertEqual(config.policy_text, POLICY)
        self.assertEqual(config.source_lines, [2, 3, 4])

    def test_real_wrapper_comparison_uses_literal_identifiers(self):
        result = compare_wrapper(SOURCE, "Guard.check", ["user", "item", "verb"], "self.engine", MODEL, POLICY,
                                 line_syntax="native-literals")
        self.assertTrue(result["accepted"])
        self.assertIn('"set speed"', result["policy"]["actions"])
        self.assertFalse(result["extraction"]["source_module_executed"])

    def test_strict_default_has_not_silently_changed(self):
        with self.assertRaises(AdmissionError):
            admit_configuration(MODEL, POLICY)

    def test_rfc4180_quoted_comma_is_not_decoded(self):
        with self.assertRaises(AdmissionError):
            admit_native_literals(MODEL, 'p, user, motor, "one,two"')

    def test_nesting_or_unknown_policy_kind_is_not_ignored(self):
        for line in ('p, user, motor, call(x)', 'p2, user, motor, read'):
            with self.assertRaises(AdmissionError):
                admit_native_literals(MODEL, line)

    def test_malformed_native_comment_cannot_be_reported_as_pass(self):
        with self.assertRaises(AdmissionError) as caught:
            compare_wrapper(SOURCE, "Guard.check", ["user", "item", "verb"], "self.engine", MODEL,
                            '// unmatched )\n' + POLICY, line_syntax="native-literals")
        self.assertEqual(caught.exception.status, "native_error")

    def test_owned_argument_swap_is_detected(self):
        changed = SOURCE.replace("enforce(user, item, verb)", "enforce(item, user, verb)")
        result = compare_wrapper(changed, "Guard.check", ["user", "item", "verb"], "self.engine", MODEL, POLICY,
                                 line_syntax="native-literals")
        self.assertFalse(result["accepted"])
        self.assertEqual(result["comparison"]["length"], 1)


if __name__ == "__main__":
    unittest.main()
