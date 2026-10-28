"""Owned source archives for path-free YAML-chain discovery; never imported."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_runtime import engine_identity
from yaml_discovery import discover_yaml_chain
from test_policy_slice import PROGRAM
from test_yaml_policy import MODEL, DATA, CONTEXTS, DOMAIN

CONSTRUCTOR = b''' def __init__(self, blueprint=None, store=None, document=None):
  if blueprint is None:
   blueprint = options.schema_file
  if store is None:
   store = options.row_file
  if document is None:
   document = options.document_file
  self.yaml_policy_path = Path(document)
  self.yaml_policy = self._load_yaml_policy()
  self._ensure_config_files(Path(blueprint), Path(store))
  self.enforcer = casbin.Enforcer(str(blueprint), str(store))
  self._sync_yaml_to_casbin()
 def _load_yaml_policy(self):
  if self.yaml_policy_path.exists():
   with open(self.yaml_policy_path, 'r') as f:
    return yaml.safe_load(f) or {}
  return {'roles': {}, 'user_roles': {}, 'group_roles': {}, 'rules': [], 'default_policy': 'deny'}
 def _ensure_config_files(self, a, b):
  if not a.exists():
   raise RuntimeError("never execute this owned branch")
  if not b.exists():
   raise RuntimeError("never execute this owned branch")
'''


def files():
    source = PROGRAM.replace(b"class PolicyEngine:", b"class BoundRules:\n" + CONSTRUCTOR)
    source = b"import casbin\nimport yaml\nfrom pathlib import Path\nfrom runtime.config import options\n" + source
    declaration = engine_identity()
    return {"logic/checks.py": source,
        "runtime/config.py": b'''from pydantic_settings import BaseSettings
class RuntimeDefaults(BaseSettings):
 schema_file: str = "assets/model.conf"
 row_file: str = "assets/rows.csv"
 document_file: str = "assets/access.yaml"
options = RuntimeDefaults()
''', "assets/model.conf": MODEL.encode(), "assets/rows.csv": b"# empty\n",
        "assets/access.yaml": json.dumps(DATA).encode(),
        "requirements.txt": (declaration["distribution"] + "==" + declaration["release"] + "\nPyYAML==6.0.2\n").encode()}


def save_archive(path, source_files):
    with zipfile.ZipFile(path, "w") as bundle:
        for name, value in source_files.items():
            bundle.writestr("owned/" + name, value)


class YamlDiscoveryTests(unittest.TestCase):
    def evaluate(self, changes=None, remove=(), **kwargs):
        data = files()
        data.update(changes or {})
        for name in remove:
            data.pop(name)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owned.zip"
            save_archive(path, data)
            return discover_yaml_chain(path, CONTEXTS, DOMAIN, **kwargs)

    def test_archive_and_contexts_are_enough_no_per_project_paths_or_class(self):
        result = self.evaluate()
        self.assertTrue(result["accepted"], result.get("reason"))
        self.assertEqual(result["source_chain"]["producer_consumer"]["class"], "BoundRules")
        self.assertEqual(result["source_chain"]["input_paths"]["yaml"], "assets/access.yaml")
        self.assertEqual(result["comparison"]["counts"]["consumer_cells"], 12)
        self.assertFalse(result["whole_application_verified"])

    def test_package_class_fields_and_config_paths_are_not_hard_coded(self):
        data = files()
        settings = data["runtime/config.py"].replace(b"RuntimeDefaults", b"OtherDefaults").replace(b"options", b"local_config")
        settings = settings.replace(b"schema_file", b"custom_schema").replace(b"row_file", b"custom_rows").replace(b"document_file", b"custom_document")
        source = data["logic/checks.py"].replace(b"from runtime.config import options", b"from deployment.defaults import local_config")
        source = source.replace(b"options.", b"local_config.").replace(b"BoundRules", b"OtherRules")
        source = source.replace(b"schema_file", b"custom_schema").replace(b"row_file", b"custom_rows").replace(b"document_file", b"custom_document")
        result = self.evaluate({"other/rules.py": source, "deployment/defaults.py": settings}, remove=("logic/checks.py", "runtime/config.py"))
        self.assertTrue(result["accepted"], result.get("reason"))
        self.assertEqual(result["source_chain"]["settings"]["class"], "OtherDefaults")

    def test_two_candidate_classes_do_not_select_the_successful_one(self):
        result = self.evaluate({"second/rules.py": files()["logic/checks.py"]})
        self.assertEqual(result["status"], "ambiguous_input")
        self.assertIsNone(result["accepted"])
        self.assertNotIn("comparison", result)

    def test_missing_file_and_scan_budget_do_not_become_passes(self):
        missing = self.evaluate(remove=("assets/access.yaml",))
        self.assertEqual(missing["status"], "missing_input")
        self.assertIsNone(missing["accepted"])
        limited = self.evaluate(max_python_members=1)
        self.assertEqual(limited["status"], "inconclusive")
        self.assertFalse(limited["discovery_complete"])

    def test_side_effectful_module_code_is_not_executed(self):
        result = self.evaluate({"never_import.py": b'raise RuntimeError("never execute")\n'})
        self.assertTrue(result["accepted"])
        self.assertFalse(result["source_modules_imported_or_executed"])

    def test_engine_dependency_and_distribution_must_match_source(self):
        for requirement in (b"casbin==99.0.0\nPyYAML==6.0.2", b"casbin>=1.0\nPyYAML==6.0.2"):
            result = self.evaluate({"requirements.txt": requirement})
            self.assertEqual(result["status"], "dependency_missing")
            self.assertIsNone(result["accepted"])

    def test_settings_rebinding_or_field_override_is_not_a_literal_default(self):
        settings = files()["runtime/config.py"]
        for suffix in (b'\noptions.schema_file = "other.conf"\n', b'\noptions = RuntimeDefaults()\n'):
            result = self.evaluate({"runtime/config.py": settings + suffix})
            self.assertIsNone(result["accepted"])
        changed = settings.replace(b"options = RuntimeDefaults()", b'options = RuntimeDefaults(schema_file="other.conf")')
        self.assertIsNone(self.evaluate({"runtime/config.py": changed})["accepted"])

    def test_conditional_or_dynamic_paths_and_escaping_paths_are_not_guessed(self):
        settings = files()["runtime/config.py"]
        for value in (b'get_model_path()', b'"../outside.conf"', b'"C:/outside.conf"'):
            changed = settings.replace(b'"assets/model.conf"', value)
            self.assertIsNone(self.evaluate({"runtime/config.py": changed})["accepted"])

    def test_constructor_order_overrides_and_additional_operations_require_admission(self):
        source = files()["logic/checks.py"]
        for changed in (source.replace(b"  self.enforcer =", b"  self._sync_yaml_to_casbin()\n  self.enforcer ="),
                        source.replace(b"  self.yaml_policy_path =", b'  blueprint = "other.conf"\n  self.yaml_policy_path ='),
                        source + b"\nBoundRules.__init__ = replacement\n"):
            self.assertIsNone(self.evaluate({"logic/checks.py": changed})["accepted"])

    def test_loader_or_helper_change_cannot_be_ignored(self):
        source = files()["logic/checks.py"]
        for changed in (source.replace(b"yaml.safe_load(f)", b"yaml.unsafe_load(f)"),
                        source.replace(b" def _load_yaml_policy", b" async def _load_yaml_policy"),
                        source.replace(b"  if not a.exists():", b"  if a.exists():")):
            self.assertIsNone(self.evaluate({"logic/checks.py": changed})["accepted"])

    def test_primitive_rebinding_is_not_accepted_as_original_native_call(self):
        source = files()["logic/checks.py"]
        for prefix in (b"casbin = other\n", b"str = other\n", b"Path = other\n"):
            self.assertIsNone(self.evaluate({"logic/checks.py": prefix + source})["accepted"])

    def test_owned_producer_fault_is_detected_after_automatic_discovery(self):
        source = files()["logic/checks.py"].replace(b'add_policy(role, permission.get("resource", "*"), verb)',
                                                     b'add_policy(permission.get("resource", "*"), role, verb)')
        result = self.evaluate({"logic/checks.py": source})
        self.assertFalse(result["accepted"])
        self.assertFalse(result["comparison"]["producer_rows_agree"])

    def test_owned_priority_fault_keeps_correct_producer_and_different_consumer(self):
        source = files()["logic/checks.py"].replace(b"reverse=True", b"reverse=False")
        result = self.evaluate({"logic/checks.py": source})
        self.assertFalse(result["accepted"])
        self.assertTrue(result["comparison"]["producer_rows_agree"])

    def test_absent_or_invalid_archive_has_typed_nonpass_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = discover_yaml_chain(Path(directory) / "missing.zip", CONTEXTS, DOMAIN)
            self.assertEqual(missing["status"], "missing_input")
            path = Path(directory) / "bad.zip"
            path.write_bytes(b"not-a-zip")
            self.assertIsNone(discover_yaml_chain(path, CONTEXTS, DOMAIN)["accepted"])

    def test_unified_cli_records_success_or_missing_without_manual_module_mapping(self):
        from native_pipeline import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            save_archive(root / "source.zip", files())
            (root / "contexts.json").write_text(json.dumps(CONTEXTS), encoding="utf-8")
            (root / "domain.json").write_text(json.dumps(DOMAIN), encoding="utf-8")
            args = ["yaml-application", "--archive", str(root / "source.zip"), "--contexts", str(root / "contexts.json"),
                    "--domain", str(root / "domain.json"), "--receipt", str(root / "receipt.json")]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
            original = (root / "receipt.json").read_bytes()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(original, (root / "receipt.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
