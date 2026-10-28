import ast
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from record_projection import compare_projection_cases, extract_record_projection, main, project_record

SOURCE = b'''async def build(actor, items):
 upstream_provider_not_executed()
 payload = {"owner": actor, "attributes": {}}
 for index, item in enumerate(items):
  if item:
   payload["attributes"][f"attribute_{index}"] = item
 transport_not_executed(payload)
'''
BARRIER = ast.parse("transport_not_executed(payload)").body[0]


class RecordProjectionTests(unittest.TestCase):
    def extract(self, source=SOURCE):
        return extract_record_projection(source, "build", "payload", BARRIER)

    def test_actual_ast_block_projects_fields_without_running_providers_or_transport(self):
        plan = self.extract()
        self.assertEqual(plan["required"], ["actor", "items"])
        row = project_record(plan, {"actor": "alice", "items": ["", "reader", "reader"]})
        self.assertEqual(row["value"], {"owner": "alice", "attributes": {"attribute_1": "reader", "attribute_2": "reader"}})
        self.assertFalse(row["field_mapping_hand_transcribed"])
        self.assertFalse(row["full_function_or_reachability_proved"])
        self.assertEqual(plan["descriptor"]["earlier_statements_not_interpreted"], 1)

    def test_renamed_fields_and_index_labels_follow_source_not_an_old_mapping(self):
        source = SOURCE.replace(b'"owner"', b'"principal"').replace(b'"attributes"', b'"traits"').replace(b"attribute_", b"trait_")
        row = project_record(self.extract(source), {"actor": "bob", "items": ["writer"]})
        self.assertEqual(row["value"], {"principal": "bob", "traits": {"trait_0": "writer"}})

    def test_changed_scalar_assignment_is_observable_not_silently_pinned(self):
        row = project_record(self.extract(SOURCE.replace(b'"owner": actor', b'"owner": "other"')),
            {"items": ["reader"]})
        self.assertEqual(row["value"]["owner"], "other")

    def test_unknown_statement_cannot_be_skipped_to_a_later_barrier(self):
        source = SOURCE.replace(b" for index", b" unknown_effect(payload)\n for index")
        with self.assertRaises(AdmissionError):
            self.extract(source)

    def test_duplicate_initialization_or_dynamic_selected_binding_is_not_admitted(self):
        for source in (SOURCE.replace(b" transport_not", b" payload = {}\n transport_not"),
                SOURCE + b"build = replacement\n", b"@unknown\n" + SOURCE):
            with self.assertRaises(AdmissionError):
                self.extract(source)

    def test_source_parameter_cannot_shadow_an_implicitly_bound_primitive(self):
        for name in (b"enumerate", b"str", b"sorted"):
            source = SOURCE.replace(b"build(actor, items)", b"build(actor, items, " + name + b")")
            with self.assertRaises(AdmissionError):
                self.extract(source)

    def test_early_return_and_inexact_input_bindings_fail_closed(self):
        with self.assertRaises(AdmissionError):
            self.extract(SOURCE.replace(b"  if item:", b"  if item:\n   return payload\n  if item:"))
        plan = self.extract()
        for values in ({"actor": "alice"}, {"actor": "alice", "items": [], "extra": 1}):
            with self.assertRaises(AdmissionError):
                project_record(plan, values)

    def test_input_snapshot_not_mutated_and_source_budget_not_bypassed(self):
        values = {"actor": "alice", "items": ["reader"]}
        row = project_record(self.extract(), values)
        row["value"]["attributes"]["attribute_0"] = "changed"
        self.assertEqual(values, {"actor": "alice", "items": ["reader"]})
        with self.assertRaises(AdmissionError):
            project_record(self.extract(), values, step_limit=3)

    def test_no_opaque_host_values_or_unbounded_sequences_enter_projection(self):
        plan = self.extract()
        for items in ([object()], ["a"] * 129):
            with self.assertRaises(AdmissionError):
                project_record(plan, {"actor": "alice", "items": items})

    def test_typed_reference_distinguishes_boolean_from_integer(self):
        source = SOURCE.replace(b'"owner": actor', b'"owner": True')
        result = compare_projection_cases(self.extract(source), [{"given_values": {"items": []},
            "expected_mapping": {"owner": 1, "attributes": {}}}])
        self.assertEqual(result["mismatches"], 1)

    def test_unresolved_cases_and_late_mismatch_stay_in_denominator(self):
        result = compare_projection_cases(self.extract(), [
            {"given_values": {"actor": "alice"}, "expected_mapping": {}},
            {"given_values": {"actor": "alice", "items": []}, "expected_mapping": {"owner": "alice", "attributes": {}}},
            {"given_values": {"actor": "alice", "items": []}, "expected_mapping": {"owner": "other", "attributes": {}}}])
        self.assertEqual((result["cases"], result["agreements"], result["mismatches"], result["unresolved"]), (3, 1, 1, 1))
        self.assertFalse(result["accepted"])

    def test_cli_retains_new_input_failure_without_overwriting_an_old_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.py").write_bytes(SOURCE)
            (root / "cases.json").write_text(json.dumps([{"given_values": {"actor": "a", "items": []},
                "expected_mapping": {"owner": "a", "attributes": {}}}]), encoding="utf-8")
            args = ["--source", str(root / "source.py"), "--function", "build", "--record", "payload",
                "--barrier", "transport_not_executed(payload)", "--cases", str(root / "cases.json"), "--receipt", str(root / "receipt.json")]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
            before = (root / "receipt.json").read_bytes()
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(args)
            self.assertEqual((root / "receipt.json").read_bytes(), before)
            (root / "cases.json").write_text("[]", encoding="utf-8")
            args[-1] = str(root / "failed.json")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 2)
            self.assertIsNone(json.loads((root / "failed.json").read_text())["accepted"])


if __name__ == "__main__":
    unittest.main()
