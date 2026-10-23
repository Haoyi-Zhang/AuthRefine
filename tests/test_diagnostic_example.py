"""Cross-check the paper's four interpretation classes and fixed-binding replay."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from checker import Rejected, reference_step
from diagnostic_example import example, run
from extensions import binding_profile


class DiagnosticExampleTests(unittest.TestCase):
    def test_four_exact_lengths(self):
        report = run()
        self.assertTrue(report['all_lengths_agree'])
        self.assertEqual(report['strata'], {'infinity': 1, '2': 1, '1': 2})
        self.assertEqual(len(report['profiles']), 4)

    def test_one_binding_explains_each_whole_trace(self):
        report = run()
        for row in report['profiles']:
            if row['equivalent']:
                continue
            with self.subTest(binding=row['binding']):
                self.assertEqual(len(row['trace']), row['length'])
                self.assertTrue(all(step['binding'] == row['binding'] for step in row['trace']))
                self.assertTrue(all(step['compared_equal'] for step in row['trace'][:-1]))
                self.assertFalse(row['trace'][-1]['compared_equal'])

    def test_later_bad_cell_does_not_imply_source_reachability(self):
        policy, machine = example()
        binding = {'z_a': 't', 'z_b': 't'}
        state = 0
        for request in machine['alphabet'] * 3:
            decision, state = reference_step(policy, state, request, binding)
            self.assertEqual((decision, state), ('deny', 0))
        self.assertEqual(reference_step(policy, 1, ['u', 'o', 'b'], binding), ('deny', 1))
        row = next(row for row in binding_profile(policy, machine)['profiles']
                   if row['binding'] == binding)
        self.assertEqual(row['length'], 1)

    def test_initial_observation_precedes_transition_diagnosis(self):
        policy, machine = example()
        machine = deepcopy(machine)
        machine['initial'] = machine['observations'].index(1)
        report = binding_profile(policy, machine)
        self.assertTrue(all(row['length'] == 0 and row['trace'] == []
                            for row in report['profiles']))

    def test_work_exhaustion_is_not_a_semantic_result(self):
        policy, machine = example()
        with self.assertRaises(Rejected) as caught:
            binding_profile(policy, machine, budget=0)
        self.assertEqual(caught.exception.kind, 'inconclusive')


if __name__ == '__main__':
    unittest.main()
