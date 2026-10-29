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


if __name__ == '__main__':
    unittest.main()
