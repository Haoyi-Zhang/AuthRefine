"""Check the current claim-support record against the bibliography inventory."""
import csv
from pathlib import Path
import re
import unittest


class ReferenceSnapshotTests(unittest.TestCase):
    def test_snapshot_years_match_inventory(self):
        root = Path(__file__).resolve().parents[1]
        with (root / 'reference_inventory.csv').open(encoding='utf-8', newline='') as stream:
            expected = {row['citation_key']: row['year'] for row in csv.DictReader(stream)}
        with (root / 'reference_audit.csv').open(encoding='utf-8', newline='') as stream:
            rows = list(csv.DictReader(stream))
        actual = {row['citation_key']: row['year'] for row in rows}
        self.assertEqual(len(rows), len(actual))
        self.assertTrue(all(len(year) == 4 and year.isdigit() for year in actual.values()))
        self.assertEqual(actual, expected)
        self.assertTrue(all(row['manuscript_locations'] and row['citation_context']
                            and row['supported_claim'] for row in rows))
        # The public ledger must consume these current locations, rather than
        # silently retaining chapter/line pointers from an earlier manuscript.
        support = {row['citation_key']: row for row in rows}
        with (root / 'claim_evidence_ledger.csv').open(encoding='utf-8', newline='') as stream:
            claims = list(csv.DictReader(stream))
        self.assertEqual(len(claims), len({row['claim'] for row in claims}))
        paper = root.parent / 'paper'
        artifact_only = {'resource-body', 'clean-reproduction', 'unit-regressions',
                         'reproduction-timeout', 'release-entry-contract'}
        for claim in claims:
            location = claim['manuscript_location']
            if claim['claim'] in artifact_only:
                self.assertIn('REPRODUCIBILITY.md', location)
                self.assertTrue((root / 'REPRODUCIBILITY.md').is_file())
                continue
            for anchor in location.split('; '):
                match = re.fullmatch(r'((?:sections|technical)/[\w-]+\.tex):([1-9]\d*)', anchor)
                self.assertIsNotNone(match, anchor)
                if paper.is_dir():
                    source = (paper / match[1]).read_text(encoding='utf-8').splitlines()
                    self.assertLessEqual(int(match[2]), len(source), anchor)
                    self.assertTrue(source[int(match[2])-1].strip(), anchor)
            if claim['claim'].startswith('literature-'):
                key = claim['claim'].removeprefix('literature-')
                self.assertEqual(location, support[key]['manuscript_locations'])


if __name__ == '__main__':
    unittest.main()
