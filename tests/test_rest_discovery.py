import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from rest_discovery import discover_rest_chain, main
from test_rest_source_chain import DOMAIN, archive, members


class RestDiscoveryTests(unittest.TestCase):
    def evaluate(self, updates=None, remove=(), **kwargs):
        files = members()
        files.update(updates or {})
        for key in remove:
            del files[key]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.zip"
            archive(path, files)
            return discover_rest_chain(path, DOMAIN, **kwargs)

    def test_source_paths_are_discovered_without_settings_or_seed_arguments(self):
        result = self.evaluate()
        self.assertTrue(result["accepted"])
        self.assertEqual(result["settings_candidates"], ["project/settings.py"])
        self.assertEqual(result["seed_candidates"], ["data/seed.sql"])
        self.assertEqual(result["comparison"]["native_enforce_calls"], 12)
        self.assertNotIn("never-project", json.dumps(result))
        self.assertFalse(result["whole_application_verified"])

    def test_settings_filename_and_seed_filename_are_not_hard_coded(self):
        files = members()
        result = self.evaluate({"arbitrary/runtime_setup.py": files["project/settings.py"],
                                "assets/policy_rows.sql": files["data/seed.sql"]},
                               remove=("project/settings.py", "data/seed.sql"))
        self.assertTrue(result["accepted"])
        self.assertEqual(result["settings_candidates"], ["arbitrary/runtime_setup.py"])

    def test_two_settings_are_ambiguous_not_choose_the_passing_one(self):
        result = self.evaluate({"other/config.py": members()["project/settings.py"]})
        self.assertEqual(result["status"], "ambiguous_input")
        self.assertIsNone(result["accepted"])
        self.assertNotIn("comparison", result)

    def test_two_seeds_are_ambiguous_even_if_identical(self):
        result = self.evaluate({"other/seed.sql": members()["data/seed.sql"]})
        self.assertEqual(result["status"], "ambiguous_input")
        self.assertIsNone(result["accepted"])

    def test_missing_input_and_scan_exhaustion_do_not_pass(self):
        missing = self.evaluate(remove=("data/seed.sql",))
        self.assertEqual(missing["status"], "missing_input")
        partial = self.evaluate(max_python_members=1)
        self.assertEqual(partial["status"], "inconclusive")
        self.assertFalse(partial["discovery_complete"])
        self.assertIsNone(partial["accepted"])

    def test_comment_and_string_do_not_create_settings_candidate(self):
        result = self.evaluate({"notes.py": b'# REST_FRAMEWORK = {}\nx = "REST_FRAMEWORK"\n'})
        self.assertTrue(result["accepted"])
        self.assertEqual(len(result["settings_candidates"]), 1)

    def test_source_side_effects_are_never_executed(self):
        result = self.evaluate({"unrelated.py": b'raise RuntimeError("never execute source")\n'})
        self.assertTrue(result["accepted"])

    def test_dynamic_settings_or_broken_settings_are_not_ignored(self):
        for source in (b'REST_FRAMEWORK = dynamic_call()\n', b'REST_FRAMEWORK = (\n'):
            result = self.evaluate({"project/settings.py": source})
            self.assertIsNone(result["accepted"])
            self.assertNotEqual(result["status"], "agreement")

    def test_source_mismatch_is_preserved_after_automatic_discovery(self):
        changed = members()["apps/roles/models.py"].replace(
            b'"user":user.username, "role":self.name', b'"role":self.name, "user":user.username')
        result = self.evaluate({"apps/roles/models.py": changed})
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "mismatch")

    def test_cli_keeps_failure_receipt_and_cannot_reuse_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive(root / "source.zip", {"notes.py": b"pass"})
            (root / "domain.json").write_text(json.dumps(DOMAIN), encoding="utf-8")
            args = ["--archive", str(root / "source.zip"), "--domain", str(root / "domain.json"),
                    "--receipt", str(root / "receipt.json")]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(json.loads((root / "receipt.json").read_text())["status"], "missing_input")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(args)


if __name__ == "__main__":
    unittest.main()
