from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from checker import Rejected
from maintenance_case import decode, encode, export, inputs, policy, step, stores, study


class MaintenanceCaseTests(unittest.TestCase):
    def test_frozen_upstream_assertions_and_complete_comparisons(self):
        result = study()
        self.assertEqual(sum(r["assertions"] for r in result["source_assertions"]), 6)
        self.assertEqual([m["one_step_tuples"] for m in result["modes"].values()], [512, 512])
        self.assertEqual([m["reachable_states"] for m in result["modes"].values()], [1, 2])
        for row in result["comparisons"]:
            expected = row["specification"] == row["candidate"]
            for output in row["outputs"].values():
                self.assertEqual(output["profiles"][0]["equivalent"], expected)
                self.assertEqual(output["profiles"][0]["length"], None if expected else 1)

    def test_decoder_is_complete_and_order_independent(self):
        _, universe, _ = inputs()
        self.assertEqual(len({encode(s, universe) for s in stores(universe)}), 64)
        for s in stores(universe):
            self.assertEqual([v for v in decode(s, universe).values()], [r in s for r in universe])
            self.assertEqual(decode(frozenset(reversed(sorted(s))), universe), decode(s, universe))

    def test_unrepresented_row_not_silently_dropped(self):
        initial, universe, _ = inputs()
        with self.assertRaises(Rejected):
            decode(initial.union({("outside", "data9", "read")}), universe)

    def test_repeated_batch_returns_false_and_preserves_store(self):
        initial, universe, cases = inputs()
        changed, post = step(initial, "add-mixed", "ex", universe, cases)
        again, twice = step(post, "add-mixed", "ex", universe, cases)
        self.assertTrue(changed)
        self.assertFalse(again)
        self.assertEqual(post, twice)

    def test_export_does_not_mutate_source_inputs(self):
        initial, universe, cases = inputs()
        before = deepcopy((universe, cases))
        p = policy("ex", initial, universe, cases)
        export("ex", p, initial, universe, cases)
        self.assertEqual((universe, cases), before)


if __name__ == "__main__":
    unittest.main()
