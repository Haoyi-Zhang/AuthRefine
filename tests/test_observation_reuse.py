"""Same finite contract, actual edge checks, fixed-binding replay and local reuse."""
import copy
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import checker
import compiler
from cases import chain_case, CHAIN_LENGTHS, generated, width_case
from oracle import product_oracle
from reuse_cases import phase_lift
import reuse_benchmark
from test_prepared_checker import fixtures, literal_step


def semantic_report(report):
    return {name: value for name, value in report.items()
            if name not in ('work_operations', 'work_budget', 'work_breakdown',
                            'physical_binding_evaluations', 'reused_cells', 'reuse_entries')}


class ObservationReuseTests(unittest.TestCase):
    def test_cost_children_load_the_same_modules_and_return_the_same_information(self):
        p = width_case(1)
        m = phase_lift(p, compiler.compile_policy(p), 3)
        data = reuse_benchmark.encoded([{'policy': p, 'machine': m}])
        results = []
        for mode in ('before', 'reuse'):
            output = io.BytesIO()
            args = SimpleNamespace(baseline_checker=Path('owned-reviewed-checker.py'), child=mode, trace=False)
            with patch.object(reuse_benchmark, 'old_checker', return_value=checker) as loader, \
                 patch.object(reuse_benchmark, 'peak_working_set_bytes', return_value=1234), \
                 patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(data))), \
                 patch.object(sys, 'stdout', SimpleNamespace(buffer=output)):
                reuse_benchmark.child(args)
            loader.assert_called_once_with(args.baseline_checker)
            results.append(json.loads(output.getvalue()))
        self.assertEqual(results[0]['semantic_output_sha256'], results[1]['semantic_output_sha256'])
        self.assertGreater(results[0]['physical_binding_evaluations'], results[1]['physical_binding_evaluations'])

    def test_existing_cases_keep_complete_semantic_reports(self):
        pairs = [(p, compiler.compile_policy(p)) for _, p in fixtures()]
        pairs += [(generated(i), compiler.compile_policy(generated(i))) for i in range(128)]
        pairs += [chain_case(length) for length in CHAIN_LENGTHS]
        for p, m in pairs:
            before = checker.verify_reachable(p, m, details=True)
            after = checker.verify_reachable(p, m, details=True, reuse_observations=True)
            self.assertEqual(semantic_report(before), semantic_report(after))
            self.assertEqual(after['reused_cells'], 0)
            self.assertEqual(after['physical_binding_evaluations'], before['binding_evaluations'])

    def test_repeated_observations_reduce_real_calls_not_edge_checks(self):
        for aliases in (1, 4, 8):
            p = width_case(aliases)
            for phases in (1, 3, 9):
                m = phase_lift(p, compiler.compile_policy(p), phases)
                snapshot = copy.deepcopy((p, m))
                before = checker.verify_reachable(p, m, details=True)
                with patch.object(checker, '_reference_step_prepared',
                                  wraps=checker._reference_step_prepared) as step:
                    after = checker.verify_reachable(p, m, details=True, reuse_observations=True)
                self.assertEqual(semantic_report(before), semantic_report(after))
                self.assertEqual(step.call_count, after['physical_binding_evaluations'])
                self.assertEqual(step.call_count, 4 * aliases)
                self.assertEqual(after['binding_evaluations'], 4 * aliases * phases)
                self.assertEqual(after['work_breakdown']['graph_edges'], 2 * aliases * phases)
                self.assertEqual((p, m), snapshot)

    def test_incoherent_later_edge_fails_with_the_same_shortest_replay(self):
        p = width_case(1)
        for mutation in ('decision', 'post'):
            m = phase_lift(p, compiler.compile_policy(p), 3)
            q = next(q for q, path in compiler.reachable(m).items() if len(path) == 2)
            if mutation == 'decision':
                m['transitions'][q][0][0] = 'deny'
            else:
                m['transitions'][q][0][1] = q
            before = checker.verify_reachable(p, m, details=True)
            after = checker.verify_reachable(p, m, details=True, reuse_observations=True)
            self.assertEqual(semantic_report(before), semantic_report(after))
            self.assertEqual(after['length'], 3)
            self.assertGreater(after['reused_cells'], 0)
            self.assertEqual(after['length'], product_oracle(p, m)['shortest']['length'])
            source = 0
            for row, index in zip(after['trace'], after['indices']):
                decision, source = literal_step(p, source, m['alphabet'][index], after['binding'])
                self.assertEqual(row['source'], [decision, source])
            self.assertTrue(all(row['source'] == row['target'] for row in after['trace'][:-1]))
            self.assertNotEqual(after['trace'][-1]['source'], after['trace'][-1]['target'])

    def test_logical_cap_work_boundaries_and_inconclusive_replay(self):
        p = width_case(4)
        m = phase_lift(p, compiler.compile_policy(p), 9)
        report = checker.verify_reachable(p, m, reuse_observations=True)
        for reuse in (False, True):
            with self.assertRaises(checker.Rejected) as caught:
                checker.verify_reachable(p, m, budget=report['binding_evaluations'] - 1,
                                         reuse_observations=reuse)
            self.assertEqual(caught.exception.kind, 'inconclusive')
        exact = checker.verify_reachable(p, m, reuse_observations=True,
                                         work_budget=report['work_operations'])
        self.assertEqual(exact, dict(report, work_budget=report['work_operations']))
        for cap in (0, 1, report['work_operations'] - 1):
            with self.assertRaises(checker.Rejected) as caught:
                checker.verify_reachable(p, m, work_budget=cap, reuse_observations=True)
            self.assertEqual(caught.exception.kind, 'inconclusive')
            self.assertLessEqual(caught.exception.work_operations, cap)
        q = next(q for q, path in compiler.reachable(m).items() if len(path) == 2)
        m['transitions'][q][0][0] = 'deny'
        negative = checker.verify_reachable(p, m, reuse_observations=True)
        with self.assertRaises(checker.Rejected) as caught:
            checker.verify_reachable(p, m, reuse_observations=True,
                                     work_budget=negative['work_operations'] - 1)
        self.assertEqual(caught.exception.kind, 'inconclusive')
        self.assertFalse(hasattr(caught.exception, 'trace'))

    def test_no_cross_invocation_trust_or_input_mutation(self):
        p = width_case(1)
        m = phase_lift(p, compiler.compile_policy(p), 3)
        self.assertTrue(checker.verify_reachable(p, m, reuse_observations=True)['accepted'])
        p['rules'].pop()
        snapshot = copy.deepcopy((p, m))
        answer = checker.verify_reachable(p, m, reuse_observations=True)
        self.assertFalse(answer['accepted'])
        self.assertEqual(answer['length'], 1)
        self.assertEqual(answer['binding']['x00'], 's')
        self.assertEqual((p, m), snapshot)

    def test_initial_schema_and_flag_boundaries_are_unchanged(self):
        p = width_case(1)
        m = compiler.compile_policy(p)
        for value in (0, 1, None, 'yes'):
            with self.assertRaises(checker.Rejected):
                checker.verify_reachable(p, m, reuse_observations=value)
        broken = copy.deepcopy(m)
        broken['transitions'][0][0][1] = True
        with self.assertRaises(checker.Rejected) as caught:
            checker.verify_reachable(p, broken, reuse_observations=True)
        self.assertEqual(caught.exception.kind, 'invalid')
        m['observations'][m['initial']] ^= 1
        answer = checker.verify_reachable(p, m, budget=0, work_budget=0, reuse_observations=True)
        self.assertEqual(answer['length'], 0)
        self.assertEqual(answer['physical_binding_evaluations'], 0)


if __name__ == '__main__':
    unittest.main()
