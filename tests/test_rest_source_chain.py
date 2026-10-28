import contextlib
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from native_runtime import engine_identity
from rest_source_chain import SourceArchive, compare_rest_source_chain
from test_relational_policy import ADAPTER, MODELS, USERS, fixture
from test_rest_policy import CONSUMER, model

DOMAIN = {"principals": ["alice", "owner", "other"], "resources": ["/docs/1", "/other"], "actions": ["GET", "POST"]}


def members():
    # A renamed package/class/model path demonstrates source linkage rather
    # than another hard-coded Pgoops path table. All fixture files are owned.
    engine = engine_identity()
    return {"project/settings.py": b'''INSTALLED_APPS = ["apps.people.apps.PeopleConfig"]
AUTH_USER_MODEL = "people.UserProfile"
REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated", "security.access.AccessPermission"]}
''', "security/access.py": CONSUMER.replace(b"ApiRBACPermission", b"AccessPermission").replace(b"apps.pgo_permission", b"apps.roles").replace(b'"config", "prem_model.conf"', b'"policies", "active.conf"'),
        "apps/roles/utils/adapter.py": ADAPTER,
        "apps/roles/models.py": MODELS,
        "apps/people/models.py": USERS.replace(b"apps.pgo_permission", b"apps.roles"),
        "apps/people/apps.py": b'from django.apps import AppConfig\nclass PeopleConfig(AppConfig):\n name = "apps.people"\n',
        "policies/active.conf": model().encode(), "data/seed.sql": fixture(),
        "pyproject.toml": ('[tool.poetry.dependencies]\n' + engine["distribution"] + ' = "^' + engine["release"] + '"\n').encode()}


def archive(path, files):
    with zipfile.ZipFile(path, "w") as bundle:
        for name, data in files.items():
            bundle.writestr("owned/" + name, data)


class RestSourceChainTests(unittest.TestCase):
    def check(self, changes=None):
        files = members()
        files.update(changes or {})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.zip"
            archive(path, files)
            return compare_rest_source_chain(path, "project/settings.py", "data/seed.sql", DOMAIN)

    def test_renamed_modules_and_configuration_are_followed_without_imports(self):
        result = self.check()
        self.assertTrue(result["accepted"])
        self.assertEqual(result["native_enforce_calls"], 12)
        self.assertEqual(result["source_chain"]["consumer"], "security/access.py")
        self.assertEqual(result["source_chain"]["native_model"], "policies/active.conf")
        self.assertFalse(result["whole_application_verified"])
        self.assertFalse(result["source_modules_imported_or_executed"])
        self.assertNotIn("never-project", json.dumps(result))

    def test_source_dictionary_control_remains_a_mismatch_end_to_end(self):
        source = members()["apps/roles/models.py"].replace(b'"user":user.username, "role":self.name', b'"role":self.name, "user":user.username')
        result = self.check({"apps/roles/models.py": source})
        self.assertFalse(result["accepted"])
        self.assertFalse(result["native_comparison"]["accepted"])

    def test_permission_argument_order_not_silently_normalized(self):
        source = members()["security/access.py"].replace(b"verify_permission(username, path, method)", b"verify_permission(path, username, method)")
        with self.assertRaises(AdmissionError):
            self.check({"security/access.py": source})

    def test_setting_overrides_and_extra_default_permissions_are_not_guessed(self):
        source = members()["project/settings.py"]
        for changed in (source + b'\nREST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"] = []\n',
                        source + b'\nif condition:\n REST_FRAMEWORK = {}\n',
                        source.replace(b'{"DEFAULT_PERMISSION_CLASSES":', b'{"DEFAULT_PERMISSION_CLASSES": [], "DEFAULT_PERMISSION_CLASSES":'),
                        source.replace(b'"security.access.AccessPermission"', b'"security.access.AccessPermission", "custom.Other"')):
            with self.assertRaises(AdmissionError):
                self.check({"project/settings.py": changed})

    def test_wrong_distribution_or_version_is_dependency_gap(self):
        with self.assertRaises(AdmissionError) as caught:
            self.check({"pyproject.toml": b'[tool.poetry.dependencies]\ncasbin = "^99.0.0"\n'})
        self.assertEqual(caught.exception.status, "dependency_missing")

    def test_duplicate_or_escaping_members_are_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.zip"
            with zipfile.ZipFile(path, "w") as bundle:
                bundle.writestr("owned/../escape.py", b"pass")
            with self.assertRaises(AdmissionError):
                SourceArchive(path)
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "w") as bundle:
                    bundle.writestr("owned/a.py", b"pass")
                    bundle.writestr("owned/a.py", b"pass")
            with self.assertRaises(AdmissionError):
                SourceArchive(path)

    def test_selected_link_and_ambiguous_module_are_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.zip"
            info = zipfile.ZipInfo("owned/linked.py")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(path, "w") as bundle:
                bundle.writestr(info, "../../not-read")
                bundle.writestr("owned/dual.py", "pass")
                bundle.writestr("owned/dual/__init__.py", "pass")
            reader = SourceArchive(path)
            try:
                with self.assertRaises(AdmissionError):
                    reader.read("linked.py")
                with self.assertRaises(AdmissionError):
                    reader.module_path("dual")
            finally:
                reader.close()

    def test_missing_source_member_is_retained_as_missing_input(self):
        files = members()
        del files["apps/people/models.py"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.zip"
            archive(path, files)
            with self.assertRaises(AdmissionError) as caught:
                compare_rest_source_chain(path, "project/settings.py", "data/seed.sql", DOMAIN)
            self.assertEqual(caught.exception.status, "missing_input")

    def test_invalid_zip_is_not_an_uncaught_error_or_pass(self):
        from native_pipeline import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad.zip").write_bytes(b"not-a-zip")
            (root / "domain.json").write_text(json.dumps(DOMAIN), encoding="utf-8")
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = main(["rest-application", "--archive", str(root / "bad.zip"), "--settings", "settings.py",
                    "--seed", "seed.sql", "--domain", str(root / "domain.json")])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(stream.getvalue())["status"], "invalid")

    def test_cli_reads_archive_and_does_not_overwrite_receipt(self):
        from native_pipeline import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive(root / "source.zip", members())
            (root / "domain.json").write_text(json.dumps(DOMAIN), encoding="utf-8")
            args = ["rest-application", "--archive", str(root / "source.zip"), "--settings", "project/settings.py",
                    "--seed", "data/seed.sql", "--domain", str(root / "domain.json"), "--receipt", str(root / "receipt.json")]
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(args)
            self.assertEqual(code, 0)
            receipt = (root / "receipt.json").read_bytes()
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(args)
            self.assertEqual(code, 2)
            self.assertEqual((root / "receipt.json").read_bytes(), receipt)


if __name__ == "__main__":
    unittest.main()
