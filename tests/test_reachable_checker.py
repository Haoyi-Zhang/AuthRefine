"""Portable list-free verifier regressions, including same-information controls."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import checker
import compiler
import language
from baseline_checks import ordinary_bfs, region_result, semantic_signature
from cases import blank, chain_case, CHAIN_LENGTHS, generated, negative_case, NEGATIVE_KINDS, width_case
from oracle import product_oracle
from test_prepared_checker import fixtures, literal_step, bindings

class ReachableCheckerTests(unittest.TestCase):
    def test_alias_kind_containers_and_nonstrings_have_typed_errors(self):
        machine = compiler.compile_policy(blank())
        for kind in ([], {}, True, False, None):
            with self.subTest(kind=kind):
                p = blank()
                p['aliases'] = [{'name': 'z', 'kind': kind, 'candidates': ['u']}]
                with self.assertRaises(language.PolicyError) as source_error:
                    language.validate(p)
                self.assertEqual(source_error.exception.category, 'TYPE')
                with self.assertRaises(checker.Rejected) as checker_error:
                    checker.verify_reachable(p, machine)
                self.assertEqual(checker_error.exception.kind, 'invalid')

    def test_valid_reference_kinds_boolean_state_and_integer_indices(self):
        for kind, domain, value in (
            ('principal', 'principals', 'u'),
            ('resource', 'resources', 'o'),
            ('action', 'actions', 'a'),
            ('role', 'roles', 'r'),
        ):
            with self.subTest(kind=kind):
                p = blank()
                if kind == 'role':
                    p[domain] = [value]
                p['aliases'] = [{'name': 'z', 'kind': kind, 'candidates': [value]}]
                p['state'] = [['b', False]]
                p['rules'] = [{'decision': 'allow',
                               'guard': [{'field': 'state', 'name': 'b', 'value': False}],
                               'updates': [{'name': 'b', 'value': True}]}]
                language.validate(p)
                checker.inspect_policy(p)
                machine = compiler.compile_policy(p)
                self.assertIs(type(machine['initial']), int)
                self.assertTrue(all(type(edge[1]) is int
                                    for row in machine['transitions'] for edge in row))
                self.assertTrue(checker.verify_reachable(p, machine)['equivalent'])

    def test_reports_verdicts_counts_lengths_and_independent_replay(self):
        for p in [p for _, p in fixtures()] + [generated(i) for i in range(128)]:
            m = compiler.compile_policy(p)
            snapshot = copy.deepcopy((p, m))
            ordinary = ordinary_bfs(p, m)
            report = checker.verify_reachable(p, m, details=True)
            region = region_result(p, m, compiler.certificate(m))
            direct = product_oracle(p, m)
            self.assertEqual(report['equivalent'], direct['equivalent'])
            self.assertEqual(report['equivalent'], region['equivalent'])
            self.assertEqual(report['length'], ordinary['length'])
            self.assertEqual(report['binding_evaluations'], ordinary['binding_evaluations'])
            self.assertEqual(report['binding_evaluations'], region['binding_evaluations'])
            if not report['equivalent']:
                self.assertEqual(report['length'], direct['shortest']['length'])
                s = language.initial(p)
                for row, index in zip(report['trace'], report['indices']):
                    d, s = literal_step(p, s, m['alphabet'][index], report['binding'])
                    self.assertEqual(row['source'], [d, s])
                self.assertTrue(all(row['source'] == row['target'] for row in report['trace'][:-1]))
                self.assertNotEqual(report['trace'][-1]['source'], report['trace'][-1]['target'])
            self.assertEqual((p, m), snapshot)

    def test_chain_bounds_and_empty_word(self):
        for length in CHAIN_LENGTHS:
            p, m = chain_case(length)
            answer = checker.verify_reachable(p, m)
            self.assertEqual(answer['length'], length)
            self.assertEqual(len(answer['trace']), length)
        p, m = chain_case(2)
        m['initial'] = next(q for q, s in enumerate(m['observations']) if s != language.initial(p))
        answer = checker.verify_reachable(p, m, budget=0, work_budget=0)
        self.assertEqual(answer['length'], 0)
        self.assertEqual(answer['trace'], [])
        self.assertEqual(answer['work_operations'], 0)

    def test_work_cap_preparation_support_replay_and_exact_boundary(self):
        for p, m in [(width_case(3), compiler.compile_policy(width_case(3))), chain_case(8)]:
            full = checker.verify_reachable(p, m)
            needed = full['work_operations']
            bounded = checker.verify_reachable(p, m, work_budget=needed)
            self.assertEqual(bounded, dict(full, work_budget=needed))
            for limit in (0, 1, needed - 1):
                with self.assertRaises(checker.Rejected) as caught:
                    checker.verify_reachable(p, m, work_budget=limit)
                self.assertEqual(caught.exception.kind, 'inconclusive')
                self.assertLessEqual(caught.exception.work_operations, limit)
            self.assertEqual(full['work_operations'], sum(full['work_breakdown'].values()))
        p = width_case(16)
        m = compiler.compile_policy(p)
        with patch.object(checker, '_reference_step_prepared') as semantic:
            with self.assertRaises(checker.Rejected):
                checker.verify_reachable(p, m, work_budget=0)
            semantic.assert_not_called()
        for value in (-1, True, False, 1.0, None):
            with self.assertRaises(checker.Rejected):
                checker.verify_reachable(p, m, work_budget=value)
        with self.assertRaises(checker.Rejected) as caught:
            checker.verify_reachable(p, m, budget=1)
        self.assertEqual(caught.exception.kind, 'inconclusive')

    def test_compact_output_context_reuse_and_mutation(self):
        p = width_case(3)
        m = compiler.compile_policy(p)
        compact = checker.verify_reachable(p, m)
        detailed = checker.verify_reachable(p, m, details=True)
        self.assertNotIn('cells', compact)
        self.assertEqual(len(detailed['cells']), 6)
        self.assertGreater(detailed['work_operations'], compact['work_operations'])
        p['members'].append(['u', 's'])
        p = language.normalize(p)
        self.assertTrue(checker.verify_reachable(p, compiler.compile_policy(p))['equivalent'])
        m['transitions'][m['initial']][0][0] = 'deny'
        self.assertFalse(checker.verify_reachable(p, m)['equivalent'])

    def test_unreachable_mismatch_and_invalid_input_stay_distinct(self):
        p = blank()
        p['state'] = [['b', False]]
        p['rules'] = [{'decision': 'allow', 'guard': [], 'updates': []}]
        p = language.normalize(p)
        m = compiler.compile_policy(p)
        m['transitions'][0][0][0] = 'deny'
        self.assertTrue(checker.verify_reachable(p, m)['equivalent'])
        with self.assertRaises(checker.Rejected):
            checker.verify(p, m, {'reachable': [0, 1]})
        for kind in NEGATIVE_KINDS:
            if kind in ('missing-initial', 'missing-successor', 'duplicate-state', 'invalid-state',
                        'extra-certificate-field', 'duplicate-json-key', 'wrong-initial-observation'):
                continue  # certificate faults do not exist in a list-free interface
            bad_p, bad_m, _ = negative_case(kind)
            with self.assertRaises(checker.Rejected) as caught:
                checker.verify_reachable(bad_p, bad_m)
            self.assertEqual(caught.exception.kind, 'invalid')

    def test_semantic_signature_retains_effects_initial_and_binding_domain(self):
        p = language.normalize(blank())
        same = copy.deepcopy(p)
        same['rules'].append({'decision': 'deny', 'guard': [], 'updates': []})
        self.assertEqual(semantic_signature(p)[0], semantic_signature(same)[0])
        p = width_case(1)
        changed = copy.deepcopy(p)
        changed['state'][0][1] = True
        self.assertNotEqual(semantic_signature(p)[0], semantic_signature(changed)[0])
        changed = copy.deepcopy(p)
        changed['aliases'][0]['candidates'] = ['r']
        self.assertNotEqual(semantic_signature(p)[0], semantic_signature(changed)[0])
        changed = copy.deepcopy(p)
        changed['rules'][0]['updates'][0] = {'name': 'b', 'value': False}
        self.assertNotEqual(semantic_signature(p)[0], semantic_signature(changed)[0])

    def test_cli_certificate_optional_and_statuses(self):
        folder = ROOT / 'results/examples/case-00000'
        def run(*args):
            done = subprocess.run([sys.executable, '-B', str(ROOT / 'src/checker.py'),
                                   str(folder / 'policy.json'), str(folder / 'automaton.json'), *args],
                                  capture_output=True, text=True, timeout=15)
            return done.returncode, json.loads(done.stdout)
        status, result = run()
        self.assertEqual(status, 0)
        self.assertTrue(result['equivalent'])
        status, result = run('--work-budget', '0')
        self.assertEqual(status, 2)
        self.assertEqual(result['status'], 'inconclusive')
        status, result = run(str(folder / 'certificate.json'))
        self.assertEqual(status, 0)
        self.assertTrue(result['accepted'])

if __name__ == '__main__':
    unittest.main()
