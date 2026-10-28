import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_pipeline import main

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "external_inputs/casbin/basic_model.conf"
POLICY = ROOT / "external_inputs/casbin/basic_policy.csv"


class NativePipelineTests(unittest.TestCase):
    def invoke(self, args):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main([str(arg) for arg in args])
        return code, json.loads(stream.getvalue())

    def test_persistent_source_boundary_keeps_mismatch_and_owned_repair_separate(self):
        from test_persistent_store import SOURCE, ROWS
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.py").write_bytes(SOURCE)
            (root / "rows.json").write_text(json.dumps(ROWS[:1]), encoding="utf-8")
            args = ["persistent-store", "--source", root / "source.py", "--model", MODEL, "--rows", root / "rows.json"]
            for mode, extra, expected in (("persistent", [], 1), ("live", ["--memory-only"], 0),
                                           ("owned_repair", ["--owned-explicit-save"], 0)):
                code, summary = self.invoke([*args, *extra, "--receipt", root / (mode + ".json")])
                self.assertEqual(code, expected)
                report = json.loads((root / (mode + ".json")).read_text())
                self.assertFalse(report["application_or_upstream_tests_executed"])
                self.assertEqual(report["owned_explicit_save_control"], mode == "owned_repair")

    def test_domain_role_updates_entry_does_not_claim_database_or_full_chain(self):
        from test_threadpool_roles import SOURCE, MODEL as DOMAIN_MODEL
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.py").write_bytes(SOURCE)
            (root / "model.conf").write_text(DOMAIN_MODEL, encoding="utf-8")
            code, summary = self.invoke(["domain-role-updates", "--source", root / "source.py", "--model", root / "model.conf",
                                         "--receipt", root / "receipt.json"])
            self.assertEqual(code, 0)
            report = json.loads((root / "receipt.json").read_text())
            self.assertFalse(report["database_scd2_commit_adapter_or_threadpool_verified"])
            self.assertFalse(report["full_permission_check_chain_verified"])
            self.assertEqual(len(report["cases"]), 40)

    def test_new_state_flow_modes_keep_runtime_failures_in_new_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.py").write_text("# owned input", encoding="utf-8")
            (root / "rows.json").write_text("[]", encoding="utf-8")
            for mode, function, extra in (("persistent-store", "persistent_store.compare_store", ["--rows", root / "rows.json"]),
                                          ("domain-role-updates", "threadpool_roles.compare_domain_updates", [])):
                receipt = root / (mode + ".json")
                with patch(function, side_effect=RuntimeError("owned runtime failure control")):
                    code, summary = self.invoke([mode, "--source", root / "source.py", "--model", MODEL, *extra, "--receipt", receipt])
                self.assertEqual(code, 2)
                self.assertIsNone(summary["accepted"])
                self.assertEqual(summary["status"], "native_error")
                self.assertTrue(receipt.exists())

    def test_version_cache_entry_keeps_field_comparison_and_typed_error_separate(self):
        from test_versioned_cache import SOURCE, MODEL as VERSION_MODEL, EPOCHS, REQUESTS
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "model.conf").write_text(VERSION_MODEL, encoding="utf-8")
            (root / "source.py").write_bytes(SOURCE)
            (root / "epochs.json").write_text(json.dumps(EPOCHS), encoding="utf-8")
            (root / "requests.json").write_text(json.dumps(REQUESTS), encoding="utf-8")
            args = ["version-cache", "--source", root / "source.py", "--model", root / "model.conf", "--epochs", root / "epochs.json", "--requests", root / "requests.json"]
            code, summary = self.invoke([*args, "--receipt", root / "pass.json"])
            self.assertEqual(code, 0)
            report = json.loads((root / "pass.json").read_text())
            self.assertFalse(report["mysql_isolation_or_concurrent_snapshot_consistency_verified"])
            changed = SOURCE.replace(b"cache = await self._get_cache()", b"raise AuthorizationUnavailableError('owned provider failure')")
            (root / "source.py").write_bytes(changed)
            code, summary = self.invoke([*args, "--receipt", root / "error.json"])
            self.assertEqual(code, 2)
            self.assertEqual(summary["status"], "source_error")
            self.assertIsNone(summary["accepted"])

    def test_cache_first_entry_retains_separate_audit_difference(self):
        from test_cached_decision import SOURCE, MODEL as CACHE_MODEL, REFERENCE_POLICY
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "model.conf").write_text(CACHE_MODEL, encoding="utf-8")
            (root / "source.py").write_bytes(SOURCE)
            (root / "policy.csv").write_text(REFERENCE_POLICY, encoding="utf-8")
            code, summary = self.invoke(["cache-first", "--source", root / "source.py", "--model", root / "model.conf",
                "--policy", root / "policy.csv", "--receipt", root / "result.json"])
            self.assertEqual(code, 0)
            report = json.loads((root / "result.json").read_text())
            self.assertFalse(report["all_checks_audited_contract"]["accepted"])
            self.assertEqual(report["cache_hit_cases_without_audit"], 216)

    def test_post_transform_historical_guard_is_a_scoped_non_native_comparison(self):
        from test_transform_guard import AFTER
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.py").write_bytes(AFTER)
            code, summary = self.invoke(["historical-boundary", "--interface", "post-transform-guard", "--source", root / "source.py",
                                         "--receipt", root / "result.json"])
            self.assertEqual(code, 0)
            report = json.loads((root / "result.json").read_text())
            self.assertFalse(report["source_projection"]["actual_auth_predicate_provider_or_full_lookup_verified"])
            self.assertNotIn("engine", report["runtime"])

    def test_native_configuration_entry_point_and_atomic_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            args = ["configuration", "--model", MODEL, "--policy", POLICY, "--receipt", receipt]
            code, summary = self.invoke(args)
            self.assertEqual(code, 0)
            self.assertTrue(summary["accepted"])
            report = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertFalse(report["application_entry_points_verified"])
            before = receipt.read_bytes()
            code, summary = self.invoke(args)
            self.assertEqual(code, 2)
            self.assertIsNone(summary["accepted"])
            self.assertEqual(receipt.read_bytes(), before)

    def test_historical_source_boundary_is_not_reported_as_native_application_execution(self):
        from test_historical_boundary import PERMISSION, OLD_PERMISSION
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, source in (("before", OLD_PERMISSION), ("after", PERMISSION)):
                (root / (name + ".py")).write_bytes(source)
                code, summary = self.invoke(["historical-boundary", "--interface", "sync-permissions", "--source", root / (name + ".py"),
                                             "--receipt", root / (name + ".json")])
                self.assertEqual(code, 1 if name == "before" else 0)
                report = json.loads((root / (name + ".json")).read_text())
                self.assertFalse(report["source_or_exploit_executed"])
                self.assertNotIn("engine", report["runtime"])

    def test_yaml_policy_entry_preserves_ignored_fields_and_selected_scope(self):
        from test_policy_slice import PROGRAM
        from test_yaml_policy import MODEL as GATEWAY_MODEL
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.py").write_bytes(PROGRAM)
            (root / "model.conf").write_text(GATEWAY_MODEL, encoding="utf-8")
            (root / "policy.csv").write_text("# empty", encoding="utf-8")
            (root / "policy.yaml").write_text('roles: {}\nrules:\n- condition: {user: reader, tool_permissions: [write]}\n  action: allow\n  metadata: {require_approval: true}\n', encoding="utf-8")
            (root / "contexts.json").write_text('[{"user":"reader","groups":[]}]', encoding="utf-8")
            (root / "domain.json").write_text('{"resources":["mcp:dev:read"],"actions":["read"]}', encoding="utf-8")
            code, summary = self.invoke(["yaml-policy", "--model", root / "model.conf", "--policy", root / "policy.csv",
                "--source", root / "source.py", "--yaml-policy", root / "policy.yaml", "--contexts", root / "contexts.json",
                "--domain", root / "domain.json", "--receipt", root / "receipt.json"])
            self.assertEqual(code, 0)
            self.assertTrue(summary["accepted"])
            report = json.loads((root / "receipt.json").read_text())
            self.assertFalse(report["whole_application_verified"])
            self.assertEqual(report["ignored_input_fields_not_certified_as_enforced"][0]["condition_keys"], ["tool_permissions"])

    def test_snapshot_policy_entry_keeps_ready_and_owned_database_scope(self):
        from test_snapshot_policy import PROGRAM, MODEL, RULES, OWNERS, REQUESTS
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.py").write_bytes(PROGRAM)
            (root / "model.conf").write_text(MODEL, encoding="utf-8")
            for name, data in (("rows", RULES), ("owners", OWNERS), ("requests", REQUESTS)):
                (root / (name + ".json")).write_text(json.dumps(data), encoding="utf-8")
            code, summary = self.invoke(["snapshot-policy", "--source", root / "source.py", "--model", root / "model.conf",
                "--rows", root / "rows.json", "--owners", root / "owners.json", "--requests", root / "requests.json", "--receipt", root / "receipt.json"])
            self.assertEqual(code, 0)
            report = json.loads((root / "receipt.json").read_text())
            self.assertFalse(report["initialization_admin_sync_transactions_or_orm_verified"])
            self.assertEqual(report["counts"]["consumer_cells"], 30)

    def test_fixed_family_entry_keeps_a_complete_diagnostic_not_a_blanket_pass(self):
        from diagnostic_example import example
        policy, machine = example()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            (root / "machine.json").write_text(json.dumps(machine), encoding="utf-8")
            code, summary = self.invoke(["family-diagnosis", "--reference-json", root / "policy.json",
                "--machine-json", root / "machine.json", "--receipt", root / "diagnostic.json"])
            self.assertEqual(code, 2)
            self.assertEqual(summary["status"], "diagnosed")
            report = json.loads((root / "diagnostic.json").read_text())
            self.assertEqual(report["classification"], "some")
            self.assertEqual(len(report["profiles"]), 4)
            self.assertTrue(report["algorithms_agree"])
            self.assertNotIn("engine", report["runtime"])

    def test_handoff_entry_projects_strings_without_claiming_whole_caller_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "caller.py").write_text('def submit(u, r, a):\n return gate.check(u, item=r, action=f\'"{a}"\')\n', encoding="utf-8")
            (root / "record.json").write_text('{"u":"reader","r":"motor","a":"read"}', encoding="utf-8")
            code, summary = self.invoke(["call-handoff", "--source", root / "caller.py", "--function", "submit", "--callee", "gate.check",
                "--parameters", "user", "item", "action", "--inputs", root / "record.json", "--receipt", root / "receipt.json"])
            self.assertEqual(code, 2)
            report = json.loads((root / "receipt.json").read_text())
            self.assertEqual(report["consumer_arguments"], ["reader", "motor", '"read"'])
            self.assertIsNone(summary["accepted"])
            self.assertNotIn("engine", report["runtime"])

    def test_return_protocol_cli_reports_scoped_owned_counterexamples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "producer.py").write_text('def decide(value):\n return value, "reason"\n', encoding="utf-8")
            (root / "consumer.py").write_text('def route():\n if not gate.decide(False):\n  return "reject"\n', encoding="utf-8")
            code, summary = self.invoke(["return-contract", "--producer-source", root / "producer.py", "--producer-function", "decide",
                "--source", root / "consumer.py", "--callee", "gate.decide", "--receipt", root / "receipt.json"])
            report = json.loads((root / "receipt.json").read_text())
            self.assertEqual(code, 2)
            self.assertFalse(report["comparisons"][0]["accepted"])
            self.assertIsNone(summary["accepted"])
            self.assertFalse(report["whole_application_verified"])
            self.assertNotIn("engine", report["runtime"])

    def test_mismatch_is_distinct_from_unsupported(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "owned_wrapper.py"
            # This is test-fixture generation inside a temporary directory;
            # no supplied application module is imported or executed.
            source.write_text("def check(engine, subject, resource, action):\n    return True\n", encoding="utf-8")
            args = ["wrapper", "--model", MODEL, "--policy", POLICY, "--source", source,
                    "--function", "check", "--engine", "engine", "--parameters", "subject", "resource", "action"]
            code, summary = self.invoke(args)
            self.assertEqual(code, 1)
            self.assertFalse(summary["accepted"])
            source.write_text("def check(engine, subject, resource, action):\n    return unknown()\n", encoding="utf-8")
            code, summary = self.invoke(args)
            self.assertEqual(code, 2)
            self.assertEqual(summary["status"], "unsupported")
            self.assertIsNone(summary["accepted"])

    def test_unreadable_inputs_are_not_success(self):
        code, report = self.invoke(["configuration", "--model", "missing-owned-fixture", "--policy", POLICY])
        self.assertEqual(code, 2)
        self.assertIsNone(report["accepted"])
        self.assertEqual(report["status"], "missing_input")

    def test_missing_or_unsupported_inputs_are_saved_in_denominator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.json"
            code, report = self.invoke(["configuration", "--model", root / "not-present", "--policy", POLICY, "--receipt", missing])
            self.assertEqual(code, 2)
            self.assertTrue(report["receipt_written"])
            self.assertEqual(json.loads(missing.read_text())["status"], "missing_input")
            source = root / "owned.py"
            source.write_text('def check(engine, subject, resource, action):\n return unknown()\n', encoding="utf-8")
            receipt = root / "unsupported.json"
            code, report = self.invoke(["wrapper", "--model", MODEL, "--policy", POLICY, "--source", source,
                "--function", "check", "--engine", "engine", "--parameters", "subject", "resource", "action", "--receipt", receipt])
            self.assertEqual(code, 2)
            self.assertTrue(report["receipt_written"])
            self.assertEqual(json.loads(receipt.read_text())["status"], "unsupported")

    def test_existing_success_cannot_be_mistaken_for_a_new_failed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "existing.json"
            receipt.write_text('{"accepted": true, "old": true}', encoding="utf-8")
            original = receipt.read_bytes()
            code, report = self.invoke(["configuration", "--model", "missing-owned-fixture", "--policy", POLICY, "--receipt", receipt])
            self.assertEqual(code, 2)
            self.assertEqual(report["status"], "receipt_error")
            self.assertEqual(report["evaluation_status"], "missing_input")
            self.assertFalse(report["receipt_written"])
            self.assertEqual(receipt.read_bytes(), original)

    def test_cache_entry_point_uses_explicit_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = Path(directory) / "rows.json"
            rows.write_text('[["alice", "records", "read"]]', encoding="utf-8")
            code, report = self.invoke(["cache", "--model", MODEL, "--rows", rows])
            self.assertEqual(code, 0)
            self.assertEqual(report["native_enforce_calls"], 4)

    def test_duplicate_json_fields_cannot_override_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            domain = Path(directory) / "domain.json"
            domain.write_text('{"principals": [], "principals": ["alice"]}', encoding="utf-8")
            code, report = self.invoke(["configuration", "--model", MODEL, "--policy", POLICY, "--domain", domain])
            self.assertEqual(code, 2)
            self.assertIsNone(report["accepted"])

    def test_scan_with_no_supported_candidates_retains_a_nonpass_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "owned.py"
            source.write_text("def unrelated():\n    return True\n", encoding="utf-8")
            domain = Path(directory) / "domain.json"
            domain.write_text('{"principals":["anonymous"],"resources":["/"],"actions":["GET"]}', encoding="utf-8")
            receipt = Path(directory) / "scan.json"
            code, report = self.invoke(["request-scan", "--model", MODEL, "--policy", POLICY,
                                       "--source", source, "--domain", domain, "--receipt", receipt])
            self.assertEqual(code, 2)
            self.assertEqual(report["status"], "unsupported")
            full = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(full["candidate_functions"], 0)
            self.assertFalse(full["whole_application_verified"])

    def test_query_filter_cli_distinguishes_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "filter.py"
            source.write_text('def tenant_filtered(stmt, model, principal):\n return stmt.where(model.tenant_id == principal.tenant_id)\n', encoding="utf-8")
            code, report = self.invoke(["query-filter", "--source", source])
            self.assertEqual(code, 0)
            self.assertEqual(report["native_select_executions"], 12)
            source.write_text('def tenant_filtered(stmt, model, principal):\n return stmt\n', encoding="utf-8")
            code, report = self.invoke(["query-filter", "--source", source])
            self.assertEqual(code, 1)
            self.assertFalse(report["accepted"])

    def test_relational_seed_cli_never_persists_unselected_password(self):
        from test_relational_policy import ADAPTER, MODELS, USERS, fixture
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in (("adapter.py", ADAPTER), ("models.py", MODELS), ("users.py", USERS), ("seed.sql", fixture())):
                (root / name).write_bytes(data)
            receipt = root / "result.json"
            code, report = self.invoke(["relational-seed", "--adapter-source", root / "adapter.py", "--model-source", root / "models.py",
                "--user-source", root / "users.py", "--seed", root / "seed.sql", "--receipt", receipt])
            self.assertEqual(code, 0)
            self.assertTrue(report["accepted"])
            text = receipt.read_text()
            self.assertNotIn("never-project", text)
            self.assertFalse(json.loads(text)["current_deployment_state_verified"])

    def test_rest_configuration_cli_uses_explicit_domain(self):
        from test_rest_policy import model, ROWS, DOMAIN
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "model").write_text(model(), encoding="utf-8")
            (root / "policy").write_text("\n".join(", ".join(row) for row in ROWS), encoding="utf-8")
            (root / "domain").write_text(json.dumps(DOMAIN), encoding="utf-8")
            code, report = self.invoke(["rest-configuration", "--model", root / "model", "--policy", root / "policy", "--domain", root / "domain"])
            self.assertEqual(code, 0)
            self.assertEqual(report["native_enforce_calls"], 45)

    def test_indirect_path_discovery_never_claims_a_semantic_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "owned.py"
            source.write_text('def sink(*args):\n return engine.enforce(*args)\ndef entry(x):\n return sink(x)\n', encoding="utf-8")
            receipt = Path(directory) / "discovery.json"
            code, report = self.invoke(["source-paths", "--source", source, "--receipt", receipt])
            self.assertEqual(code, 2)
            self.assertIsNone(report["accepted"])
            full = json.loads(receipt.read_text())
            self.assertEqual(full["indirect_candidate_functions"], 1)
            self.assertNotIn("engine", full["runtime"])

    def test_tenant_lookup_cli_retains_scope(self):
        from test_tenant_lookup import LOOKUP, FILTER
        from test_tenant_dependency import SOURCE
        from tenant_routes import SCHEMA
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in (("lookup.py", LOOKUP), ("dependency.py", SOURCE), ("query.py", FILTER)):
                (root / name).write_bytes(data)
            (root / "model.conf").write_text("\n".join("[" + section + "]\n" + "\n".join(k + " = " + v for k, v in fields.items())
                for section, fields in SCHEMA.items()), encoding="utf-8")
            (root / "policy.csv").write_text("p, role:tenant_viewer, /api/v1/tasks*, ^GET$, tenant_match\np, role:tenant_operator, /api/v1/tasks*, ^GET$, tenant_match", encoding="utf-8")
            receipt = root / "receipt.json"
            code, report = self.invoke(["tenant-lookup", "--model", root / "model.conf", "--policy", root / "policy.csv",
                "--source", root / "lookup.py", "--function", "get_task", "--dependency-source", root / "dependency.py",
                "--query-source", root / "query.py", "--receipt", receipt])
            self.assertEqual(code, 0)
            full = json.loads(receipt.read_text())
            self.assertFalse(full["whole_application_verified"])
            self.assertIn("dependency_source", full["input_paths"])

    def test_tenant_configuration_cli_is_not_a_whole_app_verdict(self):
        from tenant_routes import SCHEMA
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "model").write_text("\n".join("[" + section + "]\n" + "\n".join(k + " = " + v for k, v in fields.items())
                for section, fields in SCHEMA.items()), encoding="utf-8")
            (root / "policy").write_text("p, viewer, /tasks*, ^GET$, tenant_match", encoding="utf-8")
            receipt = root / "result.json"
            code, report = self.invoke(["tenant-configuration", "--model", root / "model", "--policy", root / "policy", "--receipt", receipt])
            self.assertEqual(code, 0)
            full = json.loads(receipt.read_text())
            self.assertFalse(full["resource_tenant_origin_verified"])
            self.assertFalse(full["whole_application_verified"])


    def test_request_outcome_cli_preserves_source_mismatch_and_owned_control(self):
        from test_request_outcomes import SOURCE, CONTROL, model
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "model").write_text(model(), encoding="utf-8")
            for name, data, expected in (("source", SOURCE, 1), ("owned_control", CONTROL, 0)):
                (root / name).write_bytes(data)
                receipt = root / (name + ".json")
                code, report = self.invoke(["request-outcomes", "--source", root / name, "--model", root / "model", "--receipt", receipt])
                self.assertEqual(code, expected)
                full = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertEqual(full["source_projection"]["cases"], 1176)
                self.assertFalse(full["whole_application_verified"])

    def test_request_outcome_runtime_failure_writes_a_new_nonpass_receipt(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").write_bytes(b"owned")
            (root / "model").write_text("owned", encoding="utf-8")
            receipt = root / "failure.json"
            with patch("request_outcomes.compare_request_outcomes", side_effect=RuntimeError("owned failure")):
                code, report = self.invoke(["request-outcomes", "--source", root / "source", "--model", root / "model", "--receipt", receipt])
            self.assertEqual(code, 2)
            self.assertIsNone(report["accepted"])
            self.assertEqual(json.loads(receipt.read_text(encoding="utf-8"))["status"], "native_error")


if __name__ == "__main__":
    unittest.main()
