"""Check both citation snapshots against the actual bibliographic inventory."""
import csv
from pathlib import Path
import unittest


class ReferenceSnapshotTests(unittest.TestCase):
    def test_snapshot_years_match_inventory(self):
        root = Path(__file__).resolve().parents[1]
        with (root / 'reference_inventory.csv').open(encoding='utf-8', newline='') as stream:
            expected = {row['citation_key']: row['year'] for row in csv.DictReader(stream)}
        for name, key_field in (('reference_audit.csv', 'citation_key'),
                                ('reference-audit.csv', 'key')):
            with self.subTest(snapshot=name):
                with (root / name).open(encoding='utf-8', newline='') as stream:
                    rows = list(csv.DictReader(stream))
                actual = {row[key_field]: row['year'] for row in rows}
                self.assertEqual(len(rows), len(actual))
                self.assertTrue(all(len(year) == 4 and year.isdigit() for year in actual.values()))
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
