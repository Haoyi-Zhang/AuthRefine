"""Check the current claim-support record against the bibliography inventory."""
import csv
from pathlib import Path
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
        for claim in claims:
            self.assertRegex(claim['manuscript_location'], r'(?:^| )sections/[\w-]+\.tex:[1-9]\d*')
            if claim['claim'].startswith('literature-'):
                key = claim['claim'].removeprefix('literature-')
                self.assertEqual(claim['manuscript_location'], support[key]['manuscript_locations'])


if __name__ == '__main__':
    unittest.main()
