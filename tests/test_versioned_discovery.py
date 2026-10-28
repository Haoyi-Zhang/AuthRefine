"""Owned bounded source archives; no foreign source module or test executes."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from native_casbin import AdmissionError
from native_runtime import engine_identity
from versioned_discovery import discover_versioned_chain
from test_versioned_cache import SOURCE, MODEL, EPOCHS, REQUESTS

PREFIX = b'''from pathlib import Path
from dataclasses import dataclass
from app.entities.authz_policy import AuthzPolicy
class AuthorizationError(Exception): pass
class AuthorizationUnavailableError(Exception): pass
@dataclass(frozen=True)
class _PolicyCache:
    version: int
    enforcer: casbin.Enforcer
    policies: tuple[AuthzPolicy, ...]
'''
SERVICE = SOURCE.replace(b'import casbin\n', b'import casbin\n' + PREFIX).replace(
    b'class AuthorizationService:\n', b'''class AuthorizationService:
    def __init__(self, repository, model_path=None, cache_state=None):
        self.repository = repository
        self.model_path = model_path or (Path(__file__).parents[2] / "conf" / "model.conf")
        self._cache_state = cache_state
''')
AUTH = b'''from dataclasses import dataclass
@dataclass(frozen=True)
class PermissionSnapshot:
    policy_version: int
    allowed_metrics: frozenset[str]
    allowed_tables: frozenset[str]
    allowed_columns: frozenset[str]
    allowed_department_ids: frozenset[str]
    sql_fallback_allowed: bool
'''


class VersionedDiscoveryTests(unittest.TestCase):
    def bundle(self, directory, service=SERVICE, auth=AUTH, model=MODEL, manifest=None, extra=None, member='app/services/cache.py'):
        identity = engine_identity()
        manifest = manifest or '[project]\nrequires-python=">=3.12"\ndependencies=["' + identity['distribution'] + '==' + identity['release'] + '"]\n'
        files = {member: service, 'app/entities/auth.py': auth, 'conf/model.conf': model, 'pyproject.toml': manifest, **(extra or {})}
        path = Path(directory) / 'source.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            for name, data in files.items():
                archive.writestr('owned/' + name, data)
        return path

    def run_bundle(self, **kwargs):
        with tempfile.TemporaryDirectory() as temp:
            return discover_versioned_chain(self.bundle(temp, **kwargs), EPOCHS, REQUESTS,
                default_model=True, stable_epochs=True)

    def test_default_source_root_records_dependency_and_cache_comparison(self):
        result = self.run_bundle()
        self.assertTrue(result['accepted'])
        service = result['candidate_services'][0]
        self.assertEqual(service['model_member'], 'conf/model.conf')
        self.assertEqual(service['comparison']['authorization']['cases'], 96)
        self.assertEqual(service['comparison']['snapshots']['cases'], 32)
        self.assertFalse(result['source_applications_orm_tests_or_services_executed'])

    def test_service_file_and_class_are_discovered_not_per_project_mapped(self):
        result = self.run_bundle(service=SERVICE.replace(b'AuthorizationService', b'FreshPolicyService'), member='other/submodule/arbitrary.py')
        self.assertTrue(result['accepted'])
        self.assertEqual(result['candidate_services'][0]['class'], 'FreshPolicyService')

    def test_cache_constructor_order_is_bound_not_silently_assumed(self):
        changed = SERVICE.replace(b'    version: int\n    enforcer: casbin.Enforcer', b'    enforcer: casbin.Enforcer\n    version: int')
        self.assertIsNone(self.run_bundle(service=changed)['accepted'])

    def test_non_simple_annotations_do_not_invent_dataclass_constructor_fields(self):
        self.assertIsNone(self.run_bundle(service=SERVICE.replace(b'version: int', b'(version): int'))['accepted'])

    def test_async_initializer_override_and_exception_builtin_rebinding_are_rejected(self):
        for changed in (SERVICE.replace(b'class AuthorizationService:\n',
                b'class AuthorizationService:\n    async def __init__(self): pass\n'),
                b'Exception = BaseException\n' + SERVICE):
            self.assertIsNone(self.run_bundle(service=changed)['accepted'])

    def test_snapshot_constructor_field_type_order_and_methods_are_bound(self):
        for auth in (AUTH.replace(b'policy_version: int', b'policy_version: bool'),
                     AUTH + b'    def __post_init__(self):\n        raise Exception()\n',
                     AUTH.replace(b'allowed_tables:', b'different_tables:')):
            with self.subTest(auth=auth):
                self.assertIsNone(self.run_bundle(auth=auth)['accepted'])

    def test_no_epoch_or_default_model_premise_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.bundle(temp)
            for args in ({}, {'default_model': True}, {'stable_epochs': True}):
                with self.assertRaises(AdmissionError):
                    discover_versioned_chain(path, EPOCHS, REQUESTS, **args)

    def test_wrong_engine_declaration_is_not_an_alternative_environment_pass(self):
        result = self.run_bundle(manifest='[project]\ndependencies=["casbin==0.0.0"]\n')
        self.assertIsNone(result['accepted'])
        self.assertEqual(result['candidate_services'][0]['status'], 'dependency_missing')

    def test_model_default_parameter_and_rebinding_are_checked(self):
        for before, after in ((b'model_path=None', b'model_path="other.conf"'),
                (b'self.repository = repository', b'self.repository = repository\n        model_path = "other.conf"'),
                (b'self._cache_state = cache_state', b'self._cache_state = cache_state\n        self.model_path: str = "other.conf"')):
            self.assertIsNone(self.run_bundle(service=SERVICE.replace(before, after))['accepted'])

    def test_dynamic_or_escaping_file_path_is_rejected(self):
        for changed in (SERVICE.replace(b'Path(__file__).parents[2]', b'Path(__file__).parents[12]'),
                SERVICE.replace(b' / "conf"', b' / "../conf"'),
                SERVICE.replace(b'Path(__file__)', b'unknown_path(__file__)')):
            self.assertIsNone(self.run_bundle(service=changed)['accepted'])

    def test_error_class_behavior_and_service_descriptors_not_ignored(self):
        for changed in (SERVICE.replace(b'class AuthorizationError(Exception): pass', b'class AuthorizationError(BaseException): pass'),
                SERVICE.replace(b'class AuthorizationService:\n', b'class AuthorizationService:\n    @property\n    def model_path(self): return "other"\n')):
            self.assertIsNone(self.run_bundle(service=changed)['accepted'])

    def test_missing_and_ambiguous_records_never_return_a_clean_success(self):
        for auth in (b'# absent', AUTH + AUTH):
            self.assertIsNone(self.run_bundle(auth=auth)['accepted'])

    def test_a_real_decision_mismatch_is_retained_not_dropped_as_unsupported(self):
        changed = SERVICE.replace(b"f'role:{role}'", b"f'roles:{role}'")
        result = self.run_bundle(service=changed)
        self.assertIs(result['accepted'], False)
        self.assertEqual(result['status'], 'mismatch')

    def test_source_inventory_cap_preserves_inconclusive_outcome(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.bundle(temp)
            with self.assertRaises(AdmissionError) as error:
                discover_versioned_chain(path, EPOCHS, REQUESTS, default_model=True, stable_epochs=True, max_python_members=1)
            self.assertEqual(error.exception.status, 'inconclusive')

    def test_cli_keeps_missing_premises_and_success_in_separate_new_receipts(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.bundle(temp)
            epochs, requests = Path(temp) / 'epochs.json', Path(temp) / 'requests.json'
            epochs.write_text(json.dumps(EPOCHS))
            requests.write_text(json.dumps(REQUESTS))
            cli = Path(__file__).resolve().parents[1] / 'src/native_pipeline.py'
            common = [sys.executable, '-B', str(cli), 'version-cache-application', '--archive', str(path),
                '--epochs', str(epochs), '--requests', str(requests)]
            absent, good = Path(temp) / 'absent.json', Path(temp) / 'admitted.json'
            result = subprocess.run(common + ['--receipt', str(absent)], capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 2)
            self.assertIsNone(json.loads(absent.read_text())['accepted'])
            result = subprocess.run(common + ['--default-model', '--stable-epochs', '--receipt', str(good)], capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(good.read_text())['accepted'])
            self.assertIsNone(json.loads(absent.read_text())['accepted'])


if __name__ == '__main__':
    unittest.main()
