import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import os
import subprocess
import sys

import verify_release
import reproduce

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import checker
import compiler
import language


class ReleaseCliContractTests(unittest.TestCase):
    def test_campaign_command_passes_fresh_output_and_frozen_baseline(self):
        output = Path("/temporary/run-output")
        baseline = Path("/artifact/results")
        command = verify_release.campaign_command(output, baseline)
        self.assertEqual(command[1], "reproduce.py")
        self.assertEqual(command[command.index("--output") + 1], str(output))
        self.assertEqual(command[command.index("--compare") + 1], str(baseline))

    def test_campaign_acceptance_requires_materialized_records_not_return_code_only(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            output = Path(temporary_name)
            (output / "summary.json").write_text(
                json.dumps({"primary_cases": 10000, "baseline_scientific_records_match": True})
            )
            (output / "reproduction.json").write_text(
                json.dumps(
                    {
                        "primary_cases": 10000,
                        "baseline_scientific_records_match": True,
                        "fresh_reproduction": True,
                        "resumed": False,
                        "documented_commands_succeeded": True,
                        "execution_environment": {
                            "platform": "Linux",
                            "peak_rss_unit": "KiB",
                            "python_hash_seed": "1729",
                            "timezone": "UTC",
                        },
                    }
                )
            )
            with self.assertRaises(ValueError):
                verify_release.inspect_campaign_output(
                    output,
                    expected_seed="1729",
                    expected_timezone="UTC",
                )

    def test_failed_matrix_returns_failure_without_secondary_exception(self):
        with patch.object(verify_release.shutil, 'copytree'), patch.object(
            verify_release, 'run', return_value={'returncode': 1, 'output_tail': 'owned failure'}
        ):
            report = verify_release.run_campaign_matrix()
        self.assertFalse(report['ok'])
        self.assertFalse(report['cross_configuration_scientific_match'])
        self.assertEqual(report['configuration_count'], 4)
        self.assertTrue(all(row['evidence'] is None for row in report['configurations']))

    def test_verifier_timeout_is_reported_as_failure(self):
        error = subprocess.TimeoutExpired(['owned-fixture'], 1, output=b'partial output')
        with patch.object(verify_release.subprocess, 'run', side_effect=error):
            report = verify_release.run(['owned-fixture'], timeout=1)
        self.assertEqual(report['returncode'], 124)
        self.assertTrue(report['timed_out'])
        self.assertEqual(report['output_tail'], 'partial output')

    def test_fresh_reproduction_is_not_archive_extraction(self):
        # Mock coverage only to isolate the provenance contract; no campaign is run.
        with tempfile.TemporaryDirectory() as temporary_name:
            output = Path(temporary_name)
            summary = {'primary_cases': 10000, 'baseline_scientific_records_match': True}
            report = dict(summary, fresh_reproduction=True, fresh_archive_extraction=False,
                          resumed=False, documented_commands_succeeded=True,
                          execution_environment={'platform': 'Linux', 'peak_rss_unit': 'KiB'})
            (output / 'summary.json').write_text(json.dumps(summary), encoding='utf-8')
            (output / 'reproduction.json').write_text(json.dumps(report), encoding='utf-8')
            with patch.object(verify_release, 'inspect_chunk_set', return_value={}):
                self.assertTrue(verify_release.inspect_campaign_output(output)['baseline_scientific_records_match'])
                del report['fresh_reproduction']
                report['fresh_archive_extraction'] = True
                (output / 'reproduction.json').write_text(json.dumps(report), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'fresh non-resumed'):
                    verify_release.inspect_campaign_output(output)

    def test_command_failure_retains_raw_output(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            directory = Path(temporary_name)
            prefix = directory / 'owned-failure'
            with self.assertRaises(subprocess.CalledProcessError):
                reproduce.run_logged(
                    [sys.executable, '-c', 'import sys; print("stdout fixture"); print("stderr fixture", file=sys.stderr); sys.exit(3)'],
                    cwd=directory, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
                    log_prefix=prefix, timeout=5,
                )
            self.assertEqual(prefix.with_suffix('.stdout.log').read_text().strip(), 'stdout fixture')
            self.assertEqual(prefix.with_suffix('.stderr.log').read_text().strip(), 'stderr fixture')
            report = json.loads(prefix.with_suffix('.json').read_text())
            self.assertEqual(report['exit_code'], 3)
            self.assertFalse(report['timed_out'])

    def test_command_success_retains_raw_output(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            directory = Path(temporary_name)
            prefix = directory / 'owned-success'
            completed = reproduce.run_logged(
                [sys.executable, '-c', 'print("owned success")'], cwd=directory,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), log_prefix=prefix, timeout=5,
            )
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(prefix.with_suffix('.stdout.log').read_text().strip(), 'owned success')

    def test_command_timeout_preserves_partial_logs(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            prefix = Path(temporary_name) / 'owned-timeout'
            error = subprocess.TimeoutExpired(['owned-fixture'], 1, output=b'partial stdout', stderr=b'partial stderr')
            with patch.object(reproduce.subprocess, 'run', side_effect=error):
                with self.assertRaises(subprocess.TimeoutExpired):
                    reproduce.run_logged(['owned-fixture'], cwd=Path(temporary_name),
                                         env={}, log_prefix=prefix, timeout=1)
            self.assertEqual(prefix.with_suffix('.stdout.log').read_text(), 'partial stdout')
            self.assertEqual(prefix.with_suffix('.stderr.log').read_text(), 'partial stderr')
            report = json.loads(prefix.with_suffix('.json').read_text())
            self.assertIsNone(report['exit_code'])
            self.assertTrue(report['timed_out'])

    def test_invalid_certificate_is_not_semantic_non_equivalence(self):
        with patch.object(checker, 'verify', side_effect=checker.Rejected('owned invalid certificate')):
            report = verify_release.semantic_example_replay()
        self.assertFalse(report['ok'])
        self.assertEqual(report['non_equivalent'], 0)
        self.assertEqual(len(report['errors']), 49)
        self.assertTrue(all('invalid' in error for error in report['errors']))

    def test_empty_word_example_is_replayed_from_initial_observations(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            example = root / 'results/examples/owned-initial-mismatch'
            example.mkdir(parents=True)
            policy = language.normalize({'principals': ['u'], 'resources': ['o'], 'actions': ['a'],
                                         'roles': [], 'members': [], 'state': [['b', False]],
                                         'aliases': [], 'rules': []})
            machine = compiler.compile_policy(policy)
            machine['initial'] = 0
            values = {'policy.json': policy, 'automaton.json': machine,
                      'certificate.json': compiler.certificate(machine),
                      'diagnostic.json': compiler.diagnose(policy, machine)}
            for name, value in values.items():
                (example / name).write_text(json.dumps(value), encoding='utf-8')
            (example / 'policy.cnl').write_text(language.pretty(policy), encoding='utf-8')
            with patch.object(verify_release, 'ROOT', root):
                report = verify_release.semantic_example_replay()
            self.assertEqual(report['errors'], [])
            self.assertEqual(report['non_equivalent'], 1)
            # A one-example fixture does not satisfy the frozen 49-example contract.
            self.assertFalse(report['ok'])

    def test_owned_generated_semantics_and_frozen_public_projection(self):
        from cases import generated
        from oracle import all_bindings, product_oracle
        from symbolic import check
        from public_inputs import MODELS, read_inputs, translate, projected_oracle, model_oracle
        for index in range(128):
            policy = generated(index)
            self.assertEqual(language.parse(language.pretty(policy)), policy)
            for binding in all_bindings(policy):
                for state in range(1 << len(policy['state'])):
                    for request in compiler.alphabet(policy):
                        self.assertEqual(compiler.step(policy, state, request, binding),
                                         checker.reference_step(policy, state, request, binding))
            machine = compiler.compile_policy(policy)
            diagnostic = compiler.diagnose(policy, machine)
            direct = product_oracle(policy, machine)
            symbolic = check(policy, machine)
            self.assertEqual(diagnostic['equivalent'], direct['equivalent'])
            self.assertEqual(symbolic['equivalent'], direct['equivalent'])
            if not direct['equivalent']:
                self.assertEqual(diagnostic['length'], direct['shortest']['length'])
                self.assertEqual(symbolic['length'], direct['shortest']['length'])
        inputs = verify_release.ROOT / 'external_inputs/casbin'
        requests = 0
        for name in MODELS:
            rows = read_inputs(inputs, name)
            policy = translate(name, rows)
            for request in compiler.alphabet(policy):
                self.assertEqual(checker.reference_step(policy, 0, request, {})[0],
                                 projected_oracle(name, rows, request))
                requests += 1
        self.assertEqual(requests, 516)
        assertions = json.loads((inputs / 'assertions.json').read_text(encoding='utf-8'))
        self.assertEqual(len(assertions), 40)
        for case in assertions:
            rows = read_inputs(inputs, case['model'])
            self.assertEqual(model_oracle(case['model'], rows, case['request']) == 'allow', case['allow'])


if __name__ == "__main__":
    unittest.main()
