import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import casbin
from native_casbin import AdmissionError
from native_runtime import engine_identity, PROFILES


class NativeRuntimeTests(unittest.TestCase):
    def test_active_distribution_and_imported_module_are_bound(self):
        result = engine_identity()
        self.assertIn(result["profile"], PROFILES)
        self.assertEqual(Path(result["imported_module"]), Path(casbin.__file__).resolve())

    def test_unknown_release_or_profile_is_not_accepted(self):
        with patch.dict(os.environ, {"AUTHREFINE_RUNTIME": "unreviewed"}):
            with self.assertRaises(AdmissionError):
                engine_identity()

    def test_shadowed_import_does_not_pass_metadata_check(self):
        with patch.object(casbin, "__file__", str(Path(__file__).with_name("owned_shadow.py"))):
            with self.assertRaises(AdmissionError) as caught:
                engine_identity()
            self.assertEqual(caught.exception.status, "dependency_missing")

    def test_declared_release_is_checked_before_native_work(self):
        class WrongDistribution:
            version = "unreviewed"
        with patch("native_runtime.metadata.distribution", return_value=WrongDistribution()):
            with self.assertRaises(AdmissionError):
                engine_identity()


if __name__ == "__main__":
    unittest.main()
