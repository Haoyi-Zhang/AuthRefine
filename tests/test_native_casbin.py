"""Benign native-runtime/conversion checks; no application service is started."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError, admit_configuration, compare_native
from public_inputs import MODELS

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "external_inputs" / "casbin"


def inputs(name):
    return ((INPUTS / (name + "_model.conf")).read_text(encoding="utf-8"),
            (INPUTS / (name + "_policy.csv")).read_text(encoding="utf-8"))


class NativeCasbinTests(unittest.TestCase):
    def test_six_frozen_configurations_against_native_runtime(self):
        counts = []
        for name in MODELS:
            with self.subTest(name=name):
                result = compare_native(*inputs(name))
                self.assertTrue(result["accepted"])
                self.assertEqual(result["family"], name)
                self.assertFalse(result["application_entry_points_verified"])
                self.assertEqual(result["policy"]["state"], [])
                self.assertEqual(result["counts"]["native_enforce_calls"] +
                                 result["counts"]["added_cross_domain_cells"],
                                 result["counts"]["converted_request_cells"])
                counts.append(result["counts"])
        self.assertEqual(sum(row["converted_request_cells"] for row in counts), 516)
        self.assertGreater(sum(row["added_cross_domain_cells"] for row in counts), 0)

    def test_no_fallback_for_custom_matcher(self):
        model, policy = inputs("basic")
        with self.assertRaises(AdmissionError) as ctx:
            compare_native(model.replace("r.obj == p.obj", "custom(r.obj, p.obj)"), policy)
        self.assertEqual(ctx.exception.status, "unsupported")

    def test_undeclared_policy_type_not_silently_ignored(self):
        model, policy = inputs("basic")
        with self.assertRaises(AdmissionError):
            compare_native(model, policy + "\np2, alice, data1, read\n")

    def test_extra_model_key_rejected(self):
        model, policy = inputs("basic")
        with self.assertRaises(AdmissionError):
            compare_native(model + "\nm2 = r.sub == p.sub\n", policy)

    def test_quoted_policy_fields_not_treated_as_plain_csv(self):
        model, _ = inputs("basic")
        with self.assertRaises(AdmissionError):
            compare_native(model, 'p, "alice", data1, read')

    def test_empty_policy_and_comments(self):
        model, _ = inputs("basic")
        result = compare_native(model, "  # empty source policy\n\n")
        self.assertTrue(result["accepted"])
        self.assertEqual(result["counts"]["source_policy_rows"], 0)
        self.assertTrue(all(edge[0] == "deny" for edge in result["machine"]["transitions"][0]))

    def test_formatting_and_ordered_source_line_mapping(self):
        model, _ = inputs("basic")
        result = compare_native(model, "# note\n  p, alice, data1, read  \n")
        self.assertTrue(result["accepted"])
        self.assertEqual(result["source_lines"], [2])

    def test_native_expression_failure_does_not_become_a_pass(self):
        model, policy = inputs("basic")
        with self.assertRaises(AdmissionError) as ctx:
            compare_native(model.replace(" && ", "&&"), policy)
        self.assertEqual(ctx.exception.status, "native_error")

    def test_priority_order_is_native_order(self):
        model, _ = inputs("priority")
        for effects in (("allow", "deny"), ("deny", "allow")):
            text = "\n".join(f"p, alice, data1, read, {effect}" for effect in effects)
            result = compare_native(model, text)
            self.assertTrue(result["accepted"])
            index = result["machine"]["alphabet"].index(["alice", "data1", "read"])
            self.assertEqual(result["machine"]["transitions"][0][index][0], effects[0])

    def test_hierarchy_boundary_is_not_claimed_as_full_closure(self):
        model, _ = inputs("rbac")
        def policy(edges):
            return "p, r9, data1, read\n" + "\n".join(f"g, r{i}, r{i+1}" for i in range(edges))
        self.assertTrue(compare_native(model, policy(9))["accepted"])
        with self.assertRaises(AdmissionError) as ctx:
            compare_native(model, policy(10))
        self.assertIn("hierarchy depth", str(ctx.exception))

    def test_zero_checker_budget_is_inconclusive(self):
        from checker import Rejected
        with self.assertRaises(Rejected) as ctx:
            compare_native(*inputs("basic"), work_budget=0)
        self.assertEqual(ctx.exception.kind, "inconclusive")

    def test_limits_are_not_equivalence_results(self):
        model, _ = inputs("basic")
        text = "\n".join(f"p, user{i}, data1, read" for i in range(17))
        with self.assertRaises(AdmissionError) as ctx:
            compare_native(model, text)
        self.assertEqual(ctx.exception.status, "inconclusive")

    def test_cli_preserves_unsupported_status(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / "model.conf"
            policy = Path(directory) / "policy.csv"
            source, _ = inputs("basic")
            model.write_text(source.replace("r.obj == p.obj", "custom(r.obj, p.obj)"), encoding="utf-8")
            policy.write_text("p, alice, data1, read\n", encoding="utf-8")
            run = subprocess.run([sys.executable, "-B", str(ROOT / "src" / "native_casbin.py"),
                                  str(model), str(policy)], capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 2, run.stderr)
            result = json.loads(run.stdout)
            self.assertEqual(result["status"], "unsupported")
            self.assertIsNone(result["accepted"])


if __name__ == "__main__":
    unittest.main()
