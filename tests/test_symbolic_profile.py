from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from checker import Rejected
from diagnostic_example import example
from extensions import binding_profile
from stateful_review import examples, compare, signature
from symbolic_profile import profile


class SymbolicProfileTests(unittest.TestCase):
    def test_complete_two_stage_profile_not_first_counterexample(self):
        p, m = example()
        result = profile(p, m)
        self.assertEqual(signature(result), signature(binding_profile(p, m)))
        self.assertEqual(result["strata"], {"infinity": 1, "2": 1, "1": 2})

    def test_normative_models_and_state_loss(self):
        for _, p, m, _ in examples():
            outputs = compare(p, m)
            self.assertEqual(outputs["symbolic_profile"]["classification"], "some")
            for output in outputs.values():
                for row in output["profiles"]:
                    if not row["equivalent"]:
                        self.assertEqual(len(row["indices"]), row["length"])
                        self.assertTrue(all(step["compared_equal"] for step in row["trace"][:-1]))
                        self.assertFalse(row["trace"][-1]["compared_equal"])
            broken = deepcopy(m)
            for edge in broken["transitions"][broken["initial"]]:
                if edge[0] == "allow":
                    edge[1] = broken["initial"]
            self.assertEqual(compare(p, broken)["symbolic_profile"]["classification"], "none")

    def test_initial_observation_is_zero_for_every_binding(self):
        p, m = example()
        m["initial"] = next(q for q, s in enumerate(m["observations"]) if s == 1)
        result = profile(p, m)
        self.assertEqual(result["strata"], {"0": 4})
        self.assertTrue(all(r["trace"] == [] and r["indices"] == [] for r in result["profiles"]))

    def test_materialization_and_symbolic_caps_are_inconclusive(self):
        p, m = example()
        for kwargs in ({"family_limit": 2}, {"operation_limit": 0}, {"node_limit": 2}):
            with self.assertRaises(Rejected) as caught:
                profile(p, m, **kwargs)
            self.assertEqual(caught.exception.kind, "inconclusive")

    def test_inputs_unchanged(self):
        p, m = example()
        before = deepcopy((p, m))
        profile(p, m)
        self.assertEqual((p, m), before)


if __name__ == "__main__":
    unittest.main()
