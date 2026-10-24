"""Portable summary/strict-baseline regressions over owned campaign records."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import reference_check
import summarize


class SummarizeContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='owned-summary-')
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name) / 'campaign'
        baseline = ROOT / 'results'
        shutil.copytree(baseline / 'chunks', self.output / 'chunks')
        for relative in ('theory.json', 'extensions.json', 'adversarial.json',
                         'exhaustive.json', 'reference_verification.json', 'pilot/pilot.json'):
            destination = self.output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(baseline / relative, destination)

    def change_json(self, relative, change):
        path = self.output / relative
        value = json.loads(path.read_text(encoding='utf-8'))
        change(value)
        path.write_text(json.dumps(value) + '\n', encoding='utf-8')

    def change_first_row(self, change):
        path = self.output / 'chunks/00000-00249.jsonl'
        rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        change(rows[0])
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')

    def test_cli_consumes_current_reference_report_and_materializes_summary(self):
        # Exercise the actual producer schema, not a hand-written field alias.
        references = reference_check.validate(
            inventory_path=ROOT / 'reference_inventory.csv',
            audit_path=ROOT / 'reference_audit.csv',
        )
        (self.output / 'reference_verification.json').write_text(
            json.dumps(references) + '\n', encoding='utf-8')
        process = subprocess.run(
            [sys.executable, 'src/summarize.py', str(self.output), '--baseline', str(ROOT / 'results')],
            cwd=ROOT, capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        result = json.loads(process.stdout)
        self.assertTrue(result['baseline_scientific_records_match'])
        self.assertEqual(result['primary_cases'], 10000)
        self.assertEqual(result['reference_verification']['audit_access_dates'],
                         references['audit_access_dates'])
        self.assertNotIn('audit_access_date', result['reference_verification'])
        self.assertEqual(result, json.loads((self.output / 'summary.json').read_text(encoding='utf-8')))
        self.assertTrue((self.output / 'families.csv').is_file())
        self.assertTrue((self.output / 'width.csv').is_file())

    def test_missing_reference_dates_are_not_silently_defaulted(self):
        self.change_json('reference_verification.json', lambda value: value.pop('audit_access_dates'))
        with self.assertRaisesRegex(KeyError, 'audit_access_dates'):
            summarize.summarize(self.output, ROOT / 'results')
        self.assertFalse((self.output / 'summary.json').exists())

    def test_primary_scientific_change_still_rejects_comparison(self):
        self.change_first_row(lambda row: row.update(accepted=not row['accepted']))
        with self.assertRaisesRegex(ValueError, 'primary scientific records differ'):
            summarize.summarize(self.output, ROOT / 'results')
        self.assertFalse((self.output / 'summary.json').exists())

    def test_auxiliary_scientific_change_still_rejects_comparison(self):
        self.change_json('theory.json', lambda value: value.update(obligations=value['obligations'] + 1))
        with self.assertRaisesRegex(ValueError, 'auxiliary scientific records differ: theory.json'):
            summarize.summarize(self.output, ROOT / 'results')
        self.assertFalse((self.output / 'summary.json').exists())

    def test_reference_dates_remain_part_of_strict_baseline_comparison(self):
        self.change_json('reference_verification.json',
                         lambda value: value['audit_access_dates'].append('2099-01-01'))
        with self.assertRaisesRegex(ValueError, 'auxiliary scientific records differ: reference_verification.json'):
            summarize.summarize(self.output, ROOT / 'results')
        self.assertFalse((self.output / 'summary.json').exists())

    def test_only_existing_timing_exclusions_are_tolerated(self):
        self.change_first_row(lambda row: row.update(cpu_seconds=row['cpu_seconds'] + 1,
                                                     wall_seconds=row['wall_seconds'] + 1))
        self.change_json('theory.json', lambda value: value.update(cpu_seconds=value['cpu_seconds'] + 1,
                                                                 peak_rss_kib=value['peak_rss_kib'] + 1))
        result = summarize.summarize(self.output, ROOT / 'results')
        self.assertTrue(result['baseline_scientific_records_match'])


if __name__ == '__main__':
    unittest.main()
