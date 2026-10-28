import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from file_wrapper_discovery import discover_file_wrappers
from native_casbin import AdmissionError
from native_pipeline import main
from native_runtime import engine_identity

MODEL = (Path(__file__).resolve().parents[1] / "external_inputs/casbin/basic_model.conf").read_bytes()
CONTRACT = ("principal", "resource", "action")


def members(package="permissions", cls="Gate", receiver="engine", parameters=("subject", "resource", "action")):
    identity = engine_identity()
    names = ", ".join(parameters)
    return {
        package + "/bridge.py": (f"import casbin\nclass {cls}:\n"
            f" def __init__(self, model=None, policy=None):\n  self.{receiver} = casbin.Enforcer(model, policy)\n"
            f" def decide(self, {names}):\n  return self.{receiver}.enforce({names})\n").encode(),
        "runtime/entry.py": (f"from {package}.bridge import {cls}\nfrom pathlib import Path\n"
            "source_root = Path(__file__).resolve().parent.parent\n"
            "first = Path(source_root / 'config' / 'model.conf')\nsecond = Path(source_root / 'config' / 'policy.csv')\n"
            f"active = {cls}(str(first), str(second))\n").encode(),
        "config/model.conf": MODEL, "config/policy.csv": b"p, alice, item, read\n",
        "requirements.txt": (identity["distribution"] + "==" + identity["release"] + "\n").encode(),
    }


def archive(path, files):
    with zipfile.ZipFile(path, "w") as bundle:
        for member, content in files.items():
            bundle.writestr("owned-source/" + member, content)


class FileWrapperDiscoveryTests(unittest.TestCase):
    def evaluate(self, files=None, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source.zip"
            archive(path, members() if files is None else files)
            return discover_file_wrappers(path, ordered_argument_contract=CONTRACT, **kwargs)

    def test_auto_source_path_constructor_and_parameter_binding(self):
        result = self.evaluate()
        self.assertTrue(result["accepted"])
        self.assertEqual(result["selected_instance_comparisons"], 1)
        instance = result["candidate_classes"][0]["instances"][0]
        self.assertEqual((instance["model"], instance["policy"]), ("config/model.conf", "config/policy.csv"))
        self.assertFalse(result["whole_application_verified"])
        self.assertFalse(result["source_modules_imported_or_executed"])

    def test_names_paths_and_native_attribute_are_not_project_specific(self):
        result = self.evaluate(members("custom_policy", "Warden", "checker", ("actor", "target", "verb")))
        self.assertTrue(result["accepted"])
        self.assertEqual(result["candidate_classes"][0]["descriptor"]["methods"][0]["parameters"], ["actor", "target", "verb"])

    def test_owned_argument_permutation_does_not_change_the_explicit_contract(self):
        files = members()
        files["permissions/bridge.py"] = files["permissions/bridge.py"].replace(
            b"enforce(subject, resource, action)", b"enforce(resource, subject, action)")
        result = self.evaluate(files)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["candidate_classes"][0]["instances"][0]["comparisons"][0]["comparison"]["length"], 1)

    def test_later_dynamic_path_cannot_reuse_an_earlier_literal(self):
        files = members()
        files["runtime/entry.py"] = files["runtime/entry.py"].replace(b"active = Gate", b"first = dynamic_path()\nactive = Gate")
        self.assertIsNone(self.evaluate(files)["accepted"])

    def test_source_root_assignment_overwrites_an_earlier_unknown_value(self):
        files = members()
        files["runtime/entry.py"] = files["runtime/entry.py"].replace(b"source_root = Path", b"source_root = arbitrary_old_value()\nsource_root = Path")
        self.assertTrue(self.evaluate(files)["accepted"])

    def test_source_package_and_direct_file_roots_must_converge(self):
        files = members()
        files["handlers/handlers.py"] = files.pop("permissions/bridge.py")
        files["handlers/__init__.py"] = b"from .handlers import Gate\n"
        files["runtime/entry.py"] = files["runtime/entry.py"].replace(b"from permissions.bridge import Gate", b"from handlers import Gate")
        result = self.evaluate(files)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["candidate_classes"][0]["instances"][0]["import_members"], ["handlers/__init__.py", "handlers/handlers.py"])

    def test_ambiguous_import_root_cannot_choose_the_passing_source(self):
        files = members()
        files["other/permissions/bridge.py"] = b"class Gate:\n pass\n"
        result = self.evaluate(files)
        self.assertIsNone(result["accepted"])
        self.assertEqual(result["candidate_classes"][0]["instances"][0]["status"], "ambiguous_input")

    def test_rebound_trusted_import_or_builtin_does_not_pass(self):
        for member, content in (("permissions/bridge.py", b"casbin = other\n"),
                ("runtime/entry.py", b"Path = other\n"), ("runtime/entry.py", b"str = other\n")):
            files = members()
            files[member] += content
            self.assertIsNone(self.evaluate(files)["accepted"])

    def test_engine_pin_mismatch_is_not_an_equivalence_result(self):
        files = members()
        files["requirements.txt"] = b"casbin==0.0.0\n"
        result = self.evaluate(files)
        self.assertIsNone(result["accepted"])
        self.assertEqual(result["candidate_classes"][0]["instances"][0]["status"], "dependency_missing")

    def test_missing_configuration_or_incomplete_scan_does_not_pass(self):
        files = members()
        del files["config/policy.csv"]
        self.assertIsNone(self.evaluate(files)["accepted"])
        with self.assertRaises(AdmissionError):
            self.evaluate(max_python_members=1)

    def test_native_receiver_property_cannot_be_assumed_an_ordinary_attribute(self):
        files = members()
        files["permissions/bridge.py"] += b" @property\n def engine(self):\n  return other\n"
        self.assertIsNone(self.evaluate(files)["accepted"])

    def test_unmodeled_constructor_operations_are_not_silently_sliced_off(self):
        files = members()
        files["permissions/bridge.py"] = files["permissions/bridge.py"].replace(b"  self.engine =", b"  change_policy()\n  self.engine =")
        self.assertIsNone(self.evaluate(files)["accepted"])

    def test_source_side_effects_are_never_executed(self):
        files = members()
        files["runtime/entry.py"] = b"raise RuntimeError('owned source must never execute')\n" + files["runtime/entry.py"]
        self.assertTrue(self.evaluate(files)["accepted"])

    def test_missing_explicit_input_contract_and_aggregate_work_cap_do_not_pass(self):
        with self.assertRaises(AdmissionError):
            discover_file_wrappers("unused.zip", ordered_argument_contract=("guess", "roles", "names"))
        with patch("file_wrapper_discovery.MAX_NATIVE_WORK", 1), patch("file_wrapper_discovery.compare_wrapper") as compare:
            self.assertIsNone(self.evaluate()["accepted"])
            compare.assert_not_called()

    def test_unified_cli_requires_contract_and_keeps_current_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive(root / "source.zip", members())
            args = ["file-wrapper-application", "--archive", str(root / "source.zip"),
                "--ordered-method-contract", "principal-resource-action", "--receipt", str(root / "receipt.json")]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
            result = json.loads((root / "receipt.json").read_text())
            self.assertTrue(result["accepted"])
            self.assertEqual(result["mode"], "file-wrapper-application")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 2)


if __name__ == "__main__":
    unittest.main()
