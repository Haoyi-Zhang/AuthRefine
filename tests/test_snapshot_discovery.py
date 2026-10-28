import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from native_pipeline import main
from native_runtime import engine_identity
from snapshot_discovery import discover_snapshot_chain
from test_snapshot_policy import MODEL, OWNERS, PROGRAM, REQUESTS, RULES


def service():
    initializer = b''' async def init(self):
  async with given_lock:
   model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policy", "rules.conf")
   self._enforcer = casbin.Enforcer(model_path)
'''
    return b"import os\nimport casbin\n" + PROGRAM.replace(b"class PermissionService:\n", b"class PermissionService:\n" + initializer)


def schema():
    result = "from tortoise import fields\nfrom tortoise.models import Model\nclass CasbinRule(Model):\n ptype = fields.CharField(max_length=10)\n"
    result += "".join(f" v{i} = fields.CharField(max_length=255, null=True)\n" for i in range(6))
    result += "class ResourceOwner(Model):\n user_id = fields.IntField()\n resource_type = fields.CharField(max_length=50)\n resource_id = fields.IntField()\n"
    return result.encode()


class SnapshotDiscoveryTests(unittest.TestCase):
    def members(self):
        runtime = engine_identity()
        return {"service/gate.py": service(), "app/models/permission.py": schema(), "policy/rules.conf": MODEL.encode(),
            "pyproject.toml": ("[project]\ndependencies = [\"" + runtime["distribution"] + ">=" + runtime["release"]
                + "\"]\nrequires-python = \">=3.13\"\n").encode()}

    def run_archive(self, members=None, *, rules=RULES, ready=True):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "source.zip"
            with zipfile.ZipFile(archive, "w") as stream:
                for name, raw in (self.members() if members is None else members).items():
                    stream.writestr("root/" + name, raw)
            return discover_snapshot_chain(archive, deepcopy(rules), deepcopy(OWNERS), deepcopy(REQUESTS), ready=ready)

    def test_archive_finds_actual_service_schema_source_path_and_ready_comparison(self):
        result = self.run_archive()
        self.assertTrue(result["accepted"])
        self.assertEqual(result["selected_source_chain_comparisons"], 1)
        candidate = result["candidate_services"][0]
        self.assertEqual(candidate["model_member"], "policy/rules.conf")
        self.assertEqual(candidate["schema_member"], "app/models/permission.py")
        self.assertEqual(candidate["comparison"]["counts"]["consumer_cells"], 30)
        self.assertFalse(candidate["dependency"]["full_source_application_environment_verified"])
        self.assertFalse(candidate["model_origin"]["initializer_locks_guards_admin_sync_and_reachability_verified"])

    def test_class_and_import_package_and_file_names_are_not_project_maps(self):
        members = self.members()
        raw = members.pop("service/gate.py").replace(b"PermissionService", b"RenamedGate").replace(b"app.models.permission", b"owned.records")
        members["other/service/entry.py"] = raw
        members["other/policy/rules.conf"] = members.pop("policy/rules.conf")
        members["other/owned/records.py"] = members.pop("app/models/permission.py")
        result = self.run_archive(members)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["candidate_services"][0]["class"], "RenamedGate")
        self.assertEqual(result["candidate_services"][0]["schema_module"], "owned.records")

    def test_missing_ready_precondition_is_not_an_initialization_success(self):
        with self.assertRaises(AdmissionError) as error:
            self.run_archive(ready=False)
        self.assertEqual(error.exception.status, "input_rejected")

    def test_wrong_domain_join_is_a_mismatch_not_normalized_to_the_reference(self):
        members = self.members()
        members["service/gate.py"] = members["service/gate.py"].replace(b"{resource_type}_{resource_id}", b"{resource_type}-{resource_id}")
        self.assertFalse(self.run_archive(members)["accepted"])

    def test_unknown_path_or_cwd_path_is_retained_unsupported(self):
        for replacement in (b"unprovided_path()", b"'policy/rules.conf'", b"os.path.join(os.path.dirname(__file__), '../rules.conf')"):
            members = self.members()
            members["service/gate.py"] = members["service/gate.py"].replace(
                b'os.path.join(os.path.dirname(os.path.dirname(__file__)), "policy", "rules.conf")', replacement)
            self.assertIsNone(self.run_archive(members)["accepted"])

    def test_competing_schema_import_roots_are_not_chosen_by_success(self):
        members = self.members()
        members["another/app/models/permission.py"] = schema()
        result = self.run_archive(members)
        self.assertIsNone(result["accepted"])
        self.assertEqual(result["candidate_services"][0]["status"], "ambiguous_input")

    def test_schema_wrong_type_nullability_duplicate_or_conditional_write_is_rejected(self):
        for changed in (schema().replace(b"user_id = fields.IntField()", b"user_id = fields.CharField(max_length=50)"),
                schema().replace(b"null=True", b"null=False", 1),
                schema().replace(b"class ResourceOwner", b" v0 = fields.CharField(max_length=20, null=True)\nclass ResourceOwner"),
                schema().replace(b"class ResourceOwner", b" if unknown:\n  v0 = fields.CharField(max_length=20, null=True)\nclass ResourceOwner")):
            members = self.members()
            members["app/models/permission.py"] = changed
            self.assertIsNone(self.run_archive(members)["accepted"])

    def test_source_column_capacity_rejects_impossible_owned_rows(self):
        members = self.members()
        members["app/models/permission.py"] = schema().replace(b"max_length=255", b"max_length=2")
        result = self.run_archive(members)
        self.assertIsNone(result["accepted"])
        self.assertEqual(result["candidate_services"][0]["status"], "input_rejected")

    def test_local_or_module_primitive_rebinding_is_not_source_path_resolution(self):
        for changed in (service() + b"\nos = other\n", service() + b"\nstr = other\n",
                service().replace(b"   model_path =", b"   os = other\n   model_path ="),
                service().replace(b"   model_path =", b"   casbin.Enforcer = other\n   model_path ="),
                service().replace(b"   model_path =", b"   os.path.dirname = other\n   model_path =")):
            members = self.members()
            members["service/gate.py"] = changed
            self.assertIsNone(self.run_archive(members)["accepted"])

    def test_all_candidate_services_retained_if_only_one_has_a_valid_model(self):
        members = self.members()
        members["service/bad.py"] = service().replace(b"PermissionService", b"OtherGate").replace(b'"rules.conf"', b'"missing.conf"')
        result = self.run_archive(members)
        self.assertIsNone(result["accepted"])
        self.assertEqual(result["selected_source_chain_comparisons"], 1)
        self.assertEqual(len(result["candidate_services"]), 2)

    def test_dependency_unknown_constraint_or_future_minimum_is_not_accepted(self):
        for dependency in ("casbin>=999.0.0", "casbin~=1.36", "casbin>=1.36.0,<2"):
            members = self.members()
            members["pyproject.toml"] = f'[project]\ndependencies=["{dependency}"]\nrequires-python=">=3.13"\n'.encode()
            result = self.run_archive(members)
            self.assertIsNone(result["accepted"])

    def test_source_module_and_orm_are_never_imported_even_if_startup_raises(self):
        members = self.members()
        members["service/gate.py"] += b"\nraise AssertionError('unexecuted source startup')\n"
        result = self.run_archive(members)
        self.assertTrue(result["accepted"])
        self.assertFalse(result["source_modules_orm_tests_or_services_executed"])
        self.assertFalse(result["whole_application_verified"])

    def test_zero_candidates_and_inventory_limits_do_not_become_a_pass(self):
        result = self.run_archive({"unrelated.py": b"pass"})
        self.assertEqual(result["status"], "missing_input")
        self.assertIsNone(result["accepted"])

    def test_cli_writes_scoped_receipt_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "source.zip"
            with zipfile.ZipFile(archive, "w") as stream:
                for name, raw in self.members().items(): stream.writestr("root/" + name, raw)
            for name, value in (("rows", RULES), ("owners", OWNERS), ("requests", REQUESTS)):
                (root / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")
            args = ["snapshot-application", "--archive", str(archive), "--rows", str(root/"rows.json"),
                "--owners", str(root/"owners.json"), "--requests", str(root/"requests.json"),
                "--ready-interface", "--receipt", str(root/"receipt.json")]
            with contextlib.redirect_stdout(io.StringIO()): code = main(args)
            self.assertEqual(code, 0)
            saved = (root/"receipt.json").read_bytes()
            with contextlib.redirect_stdout(io.StringIO()): code = main(args)
            self.assertEqual(code, 2)
            self.assertEqual((root/"receipt.json").read_bytes(), saved)


if __name__ == "__main__":
    unittest.main()
