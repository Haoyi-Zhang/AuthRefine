import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import language
import compiler
import checker
import exhaustive_audit
import reference_check
from oracle import product_oracle, exhaustive_words, all_bindings
from cases import blank, curated, generated, width_case, chain_case, CHAIN_LENGTHS, NEGATIVE_KINDS, negative_case
from public_inputs import MODELS, read_inputs, translate, projected_oracle, model_oracle
from extensions import (binding_profile, normalize_family, observable_quotient, observation_cone,
                        project_machine, project_policy, project_state, switching_oracle, verify_family)

class CoreTests(unittest.TestCase):
    def test_sequence_envelope(self):
        from experiments import sequence
        for start, count in [(-250, 1), (1, 1), (0, 0), (0, 11), (9750, 2), (10000, 1), (False, 1), (0, True)]:
            with self.subTest(start=start, count=count):
                with self.assertRaises(ValueError):
                    sequence(start, count, "unused")

    def test_canonical_round_trip(self):
        for _, p in curated():
            self.assertEqual(language.parse(language.pretty(p)), p)
        for i in range(128):
            p = generated(i)
            self.assertEqual(language.parse(language.pretty(p)), p)
            self.assertEqual(language.pretty(language.parse(language.pretty(p))), language.pretty(p))

    def test_whitespace_and_trailing_input(self):
        p = blank(); text = language.pretty(p)
        self.assertEqual(language.parse(text.replace(' ', '\t').replace('\n', ' \n ')), language.normalize(p))
        with self.assertRaises(language.PolicyError): language.parse(text + 'surprise')
        with self.assertRaises(language.PolicyError): language.parse(text.replace('"u"', 'it'))

    def test_name_and_effect_rejections(self):
        p = blank(); p['principals'].append('u')
        with self.assertRaises(language.PolicyError): language.validate(p)
        p = width_case(1); p['aliases'][0]['kind'] = 'resource'; p['aliases'][0]['candidates'] = ['o']
        with self.assertRaises(language.PolicyError): language.validate(p)
        p = curated()[0][1]; p['rules'][0]['updates'].append(copy.deepcopy(p['rules'][0]['updates'][0]))
        with self.assertRaises(language.PolicyError): language.validate(p)
        p = blank(); p['principals'] = ['bad\nname']
        with self.assertRaises(language.PolicyError): language.validate(p)

    def test_json_duplicate_keys(self):
        with self.assertRaises(language.PolicyError): language.strict_json('{"x":0,"x":1}')
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'input.json'; path.write_text('{"x":0,"x":1}')
            with self.assertRaises(checker.Rejected): checker.load(path)

    def test_simultaneous_swap(self):
        p = dict(curated())['simultaneous-swap']
        self.assertEqual(language.initial(p), 2)
        self.assertEqual(compiler.step(p, 2, ['u', 'o', 'a'], {}), ('allow', 1))
        self.assertEqual(checker.reference_step(p, 1, ['u', 'o', 'a'], {}), ('allow', 2))

    def test_priority_is_not_deny_overrides(self):
        for name, expected in [('deny-before-allow', 'deny'), ('allow-before-deny', 'allow')]:
            p = dict(curated())[name]
            self.assertEqual(compiler.step(p, 0, ['u', 'o', 'a'], {})[0], expected)

    def test_compiler_against_reference_all_small_states(self):
        for i in range(64):
            p = generated(i)
            for valuation in all_bindings(p):
                m = compiler.compile_policy(p, valuation)
                for q, state in enumerate(m['observations']):
                    for j, request in enumerate(m['alphabet']):
                        d, nq = m['transitions'][q][j]
                        self.assertEqual((d, m['observations'][nq]), checker.reference_step(p, state, request, valuation))

    def test_checker_against_product_and_diagnostic(self):
        for i in range(96):
            p = generated(i); m = compiler.compile_policy(p); c = compiler.certificate(m)
            try: checker.verify(p, m, c); accepted = True
            except checker.Rejected: accepted = False
            oracle = product_oracle(p, m); diagnosis = compiler.diagnose(p, m)
            self.assertEqual(accepted, oracle['equivalent'])
            self.assertEqual(accepted, diagnosis['equivalent'])
            if not accepted:
                self.assertEqual(oracle['shortest']['length'], diagnosis['length'])

    def test_harmless_and_meaningful_choices(self):
        p = width_case(5); m = compiler.compile_policy(p)
        result = checker.verify(p, m, compiler.certificate(m))
        self.assertEqual(result['maximum_width'], 1)
        self.assertEqual(result['binding_evaluations'], 20)
        p = dict(curated())['meaningful-reference-choice']; m = compiler.compile_policy(p)
        with self.assertRaises(checker.Rejected): checker.verify(p, m, compiler.certificate(m))
        self.assertEqual(compiler.diagnose(p, m)['length'], 1)

    def test_support_sufficiency(self):
        for i in range(32):
            p = generated(i)
            for state in range(1 << len(p['state'])):
                for request in compiler.alphabet(p):
                    support = checker.support(p, state, request)
                    answers = {}
                    for valuation in all_bindings(p):
                        key = tuple(valuation[name] for name in support)
                        result = checker.reference_step(p, state, request, valuation)
                        if key in answers: self.assertEqual(answers[key], result)
                        answers[key] = result

    def test_reification(self):
        for i in range(32):
            p = generated(i); m = compiler.compile_policy(p)
            reified = compiler.decompile(m, p)
            self.assertEqual(language.parse(language.pretty(reified)), reified)
            self.assertTrue(product_oracle(reified, m)['equivalent'])

    def test_reification_with_redundant_hidden_states(self):
        p = blank(); p['rules'] = [{'decision': 'allow', 'guard': [], 'updates': []}]
        p = language.normalize(p); m = compiler.compile_policy(p)
        m['observations'].append(0); m['transitions'] = [[['allow', 1]], [['allow', 0]]]
        checker.verify(p, m, compiler.certificate(m))
        q = compiler.decompile(m, p)
        self.assertTrue(product_oracle(q, m)['equivalent'])
        m['transitions'][1][0][0] = 'deny'
        with self.assertRaises(language.PolicyError): compiler.decompile(m, p)

    def test_shortest_witness_bound_and_tightness(self):
        for length in CHAIN_LENGTHS:
            p, m = chain_case(length)
            diagnosis = compiler.diagnose(p, m)
            oracle = product_oracle(p, m)
            self.assertEqual(diagnosis['length'], length)
            self.assertEqual(oracle['shortest']['length'], length)
            self.assertEqual(len(compiler.reachable(m)), length)
            if length <= 8:
                self.assertEqual(exhaustive_words(p, m)['length'], length)

    def test_decision_only_observation_is_insufficient(self):
        p = dict(curated())['one-use-state']
        # The weakened local test sees allow at the target's sole observed state.
        m = {'state_names': ['used'], 'alphabet': [['u', 'o', 'a']],
             'observations': [0], 'initial': 0, 'transitions': [[['allow', 0]]]}
        self.assertEqual(checker.reference_step(p, 0, ['u', 'o', 'a'], {})[0], 'allow')
        self.assertEqual(product_oracle(p, m, decisions_only=True)['shortest']['length'], 2)
        with self.assertRaises(checker.Rejected): checker.verify(p, m, {'reachable': [0]})

    def test_equal_decisions_do_not_imply_equal_updates(self):
        p = blank(); p['state'] = [['b', False]]
        p['rules'] = [{'decision': 'allow', 'guard': [], 'updates': [{'name': 'b', 'from': 'b', 'negated': True}]}]
        p = language.normalize(p)
        m = {'state_names': ['b'], 'alphabet': [['u', 'o', 'a']], 'observations': [0], 'initial': 0,
             'transitions': [[['allow', 0]]]}
        self.assertTrue(product_oracle(p, m, decisions_only=True)['equivalent'])
        self.assertFalse(product_oracle(p, m)['equivalent'])

    def test_structural_negatives_fail_closed(self):
        for kind in NEGATIVE_KINDS:
            p, m, c = negative_case(kind)
            if isinstance(c, str):
                with tempfile.TemporaryDirectory() as d:
                    path = Path(d) / 'certificate.json'; path.write_text(c)
                    with self.assertRaises(checker.Rejected): checker.load(path)
            else:
                with self.assertRaises(checker.Rejected): checker.verify(p, m, c)

    def test_public_adapter_against_model_oracle(self):
        directory = Path(__file__).resolve().parents[1] / 'external_inputs/casbin'
        for name in MODELS:
            rows = read_inputs(directory, name); p = translate(name, rows)
            for request in compiler.alphabet(p):
                self.assertEqual(checker.reference_step(p, 0, request, {})[0], projected_oracle(name, rows, request))
        for case in json.loads((directory / 'assertions.json').read_text()):
            rows = read_inputs(directory, case['model'])
            self.assertEqual(model_oracle(case['model'], rows, case['request']) == 'allow', case['allow'])

    def test_unsupported_public_matcher_is_rejected(self):
        directory = Path(__file__).resolve().parents[1] / 'external_inputs/casbin'
        with tempfile.TemporaryDirectory() as d:
            for suffix in ('model.conf', 'policy.csv'):
                text = (directory / ('basic_' + suffix)).read_text()
                if suffix == 'model.conf': text = text.replace('r.obj == p.obj', 'keyMatch(r.obj, p.obj)')
                (Path(d) / ('basic_' + suffix)).write_text(text)
            with self.assertRaises(language.PolicyError): read_inputs(d, 'basic')


    def test_unreachable_inconsistency_is_not_global_mismatch(self):
        p = blank(); p['state'] = [['b', False]]
        p['rules'] = [{'decision': 'allow', 'guard': [], 'updates': []}]
        p = language.normalize(p); m = compiler.compile_policy(p)
        m['transitions'][0][0][0] = 'deny'
        self.assertEqual(m['observations'][0], 1)
        self.assertTrue(product_oracle(p, m)['equivalent'])
        checker.verify(p, m, compiler.certificate(m))
        with self.assertRaises(checker.Rejected): checker.verify(p, m, {'reachable': [0, 1]})
        reified = compiler.decompile(m, p)
        self.assertTrue(product_oracle(reified, m)['equivalent'])

    def test_budget_is_inconclusive(self):
        p = width_case(2); m = compiler.compile_policy(p)
        with self.assertRaises(checker.Rejected) as caught:
            checker.verify(p, m, compiler.certificate(m), budget=0)
        self.assertEqual(caught.exception.kind, 'inconclusive')

    def test_initial_mismatch_has_empty_witness(self):
        p = blank(); p['state'] = [['b', False]]
        p = language.normalize(p); m = compiler.compile_policy(p)
        m['initial'] = 0
        result = product_oracle(p, m)
        self.assertFalse(result['equivalent'])
        self.assertEqual(result['shortest']['length'], 0)
        self.assertEqual(result['shortest']['indices'], [])
        with self.assertRaises(checker.Rejected) as caught:
            checker.verify(p, m, compiler.certificate(m))
        self.assertEqual(caught.exception.kind, 'mismatch')

    def test_unicode_scalar_identifiers(self):
        p = blank(); p['principals'] = ['person \U0001f9ea']
        p = language.normalize(p)
        self.assertEqual(language.parse(language.pretty(p)), p)
        for field in ('principals', 'resources', 'actions', 'roles'):
            bad = blank(); bad[field] = ['\ud800']
            with self.assertRaises(language.PolicyError): language.validate(bad)
            with self.assertRaises(checker.Rejected): checker.inspect_policy(bad)
        bad = blank(); bad['state'] = [['\ud800', False]]
        with self.assertRaises(checker.Rejected): checker.inspect_policy(bad)

    def test_control_and_format_identifiers_are_rejected(self):
        # DEL and C1 controls were the historical gap; bidi/zero-width format
        # controls are rejected by the same explicit identifier contract.
        for bad_name in ('bad\x7fname', 'bad\u0085name', 'bad\u200ename'):
            self.assertFalse(language.named(bad_name))

            domain = blank(); domain['principals'] = [bad_name]
            with self.assertRaises(language.PolicyError):
                language.validate(domain)
            with self.assertRaises(checker.Rejected):
                checker.inspect_policy(domain)

            state = blank(); state['state'] = [[bad_name, False]]
            with self.assertRaises(language.PolicyError):
                language.validate(state)
            with self.assertRaises(checker.Rejected):
                checker.inspect_policy(state)

            alias = blank(); alias['roles'] = ['r']
            alias['aliases'] = [{'name': bad_name, 'kind': 'role', 'candidates': ['r']}]
            with self.assertRaises(language.PolicyError):
                language.validate(alias)
            with self.assertRaises(checker.Rejected):
                checker.inspect_policy(alias)

    def test_diagnostic_replay_contract(self):
        for length in CHAIN_LENGTHS:
            with self.subTest(length=length):
                policy, machine = chain_case(length)
                result = compiler.diagnose(policy, machine)
                self.assertFalse(result['equivalent'])
                self.assertEqual(result['length'], length)
                self.assertEqual(len(result['indices']), length)
                self.assertEqual(len(result['trace']), length)
                self.assertTrue(all(row['source'] == row['target'] for row in result['trace'][:-1]))
                self.assertNotEqual(result['trace'][-1]['source'], result['trace'][-1]['target'])

    def test_uniformity_is_not_union_refinement(self):
        p = dict(curated())['meaningful-reference-choice']
        m = compiler.compile_policy(p)
        fixed = copy.deepcopy(p)
        for alias in fixed['aliases']:
            alias['candidates'] = alias['candidates'][:1]
        self.assertTrue(product_oracle(fixed, m)['equivalent'])
        self.assertFalse(product_oracle(p, m)['equivalent'])


    def test_large_valid_identifiers_preserve_round_trip(self):
        def names(prefix, count):
            return [(prefix + str(i)).ljust(256, '\U0001f9ea') for i in range(count)]
        p = blank()
        for field, prefix, count in [('principals', 'u', 16), ('resources', 'o', 32),
                                     ('actions', 'a', 32), ('roles', 'r', 16)]:
            p[field] = names(prefix, count)
        p['members'] = [[u, r] for u in p['principals'] for r in p['roles']]
        bits = names('b', 7); p['state'] = [[b, False] for b in bits]
        p['aliases'] = [{'name': a, 'kind': 'resource', 'candidates': list(p['resources'])} for a in names('x', 16)]
        p['rules'] = [{'decision': 'allow', 'guard': [{'field': 'principal', 'name': p['principals'][i % 16], 'negated': False}],
                       'updates': [{'name': bits[j], 'from': bits[j + 3], 'negated': False} for j in range(3)]}
                      for i in range(48)]
        p = language.normalize(p); text = language.pretty(p)
        self.assertGreater(len(text.encode('utf-8')), 1024 * 1024)
        self.assertLess(len(text.encode('utf-8')), 2 * 1024 * 1024)
        self.assertEqual(language.parse(text), p)
        checker.inspect_policy(p)

    def test_bounded_cli_output_and_roundtrip(self):
        import policy as cli
        import subprocess
        import os
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            with self.assertRaises(language.PolicyError) as caught:
                cli.output(d / "limited.json", {"field": "x" * 80}, byte_limit=32)
            self.assertEqual(caught.exception.category, "LIMIT")
            self.assertEqual(list(d.iterdir()), [])
            cli.output(d / "one.json", {"a": 1})
            with self.assertRaises(FileExistsError):
                cli.output(d / "one.json", {"a": 2})
            self.assertEqual(checker.load(d / "one.json"), {"a": 1})
            p = dict(curated())["one-use-state"]
            cli.output(d / "source.json", p)
            executable = Path(__file__).resolve().parents[1] / "src/policy.py"
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            def run(*arguments):
                done = subprocess.run([sys.executable, str(executable), *map(str, arguments)],
                                      capture_output=True, text=True, env=env, timeout=20)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                return json.loads(done.stdout)
            run("normalize", d / "source.json", d / "normal.cnl")
            run("compile", d / "normal.cnl", d / "compiled")
            m = checker.load(d / "compiled/automaton.json")
            checker.verify(p, m, checker.load(d / "compiled/certificate.json"))
            run("diagnose", d / "source.json", d / "compiled/automaton.json", d / "answer.json")
            self.assertTrue(checker.load(d / "answer.json")["equivalent"])
            run("reify", d / "source.json", d / "compiled/automaton.json", d / "reified.cnl")
            self.assertTrue(product_oracle(language.read_policy(d / "reified.cnl"), m)["equivalent"])

    def test_decision_only_has_no_target_size_bound(self):
        # Source counter denies only on its last state; target always allows.
        for length in (1, 2, 4, 8, 16, 32, 64, 128):
            p, _ = chain_case(length)
            terminal = length - 1
            guard = [{"field": "state", "name": name, "value": bool((terminal >> i) & 1)}
                     for i, (name, _) in enumerate(p["state"])]
            p["rules"].insert(0, {"decision": "deny", "guard": guard, "updates": []})
            p = language.normalize(p)
            state = language.initial(p)
            for index in range(1, length + 1):
                decision, state = checker.reference_step(p, state, ["u", "o", "a"], {})
                self.assertEqual(decision == "deny", index == length)

    def test_symbolic_cells_against_truth_tables(self):
        from symbolic import Diagram, cell, check
        for i in range(64):
            p = generated(i); d = Diagram(p["aliases"])
            for state in range(1 << len(p["state"])):
                for request in compiler.alphabet(p):
                    root = cell(d, p, state, request)
                    for binding in all_bindings(p):
                        self.assertEqual(d.evaluate(root, binding), checker.reference_step(p, state, request, binding))
            m = compiler.compile_policy(p)
            symbolic = check(p, m)
            explicit = product_oracle(p, m)
            self.assertEqual(symbolic["equivalent"], explicit["equivalent"])
            if not symbolic["equivalent"]:
                self.assertEqual(symbolic["length"], explicit["shortest"]["length"])
                rows = compiler.replay(p, m, symbolic["indices"], symbolic["binding"])
                self.assertEqual(len(rows), symbolic["length"])
                self.assertNotEqual(rows[-1]["source"], rows[-1]["target"])

    def test_symbolic_width_family(self):
        from symbolic import Diagram, cell, check
        for m in range(1, 17):
            p = width_case(m); machine = compiler.compile_policy(p)
            result = check(p, machine)
            self.assertTrue(result["equivalent"])
            self.assertEqual(result["cells"], 2 * m)
            d = Diagram(p["aliases"])
            for state in (0, 1):
                for request in compiler.alphabet(p):
                    root = cell(d, p, state, request)
                    self.assertIsNone(d.nodes[root][0])


    def test_binding_profiles_match_single_binding_products(self):
        for i in range(48):
            p = generated(i); m = compiler.compile_policy(p)
            profile = binding_profile(p, m)
            self.assertEqual(profile['bindings'], len(list(all_bindings(p))))
            for row in profile['profiles']:
                fixed = copy.deepcopy(p)
                for alias in fixed['aliases']:
                    alias['candidates'] = [row['binding'][alias['name']]]
                direct = product_oracle(language.normalize(fixed), m)
                self.assertEqual(row['equivalent'], direct['equivalent'])
                if not row['equivalent']:
                    self.assertEqual(row['length'], direct['shortest']['length'])
                    self.assertTrue(all(step['source'] == step['target'] for step in row['trace'][:-1]))
                    self.assertNotEqual(row['trace'][-1]['source'], row['trace'][-1]['target'])

        meaningful = dict(curated())['meaningful-reference-choice']
        self.assertEqual(binding_profile(meaningful, compiler.compile_policy(meaningful))['classification'], 'some')
        uniform = width_case(1)
        self.assertEqual(binding_profile(uniform, compiler.compile_policy(uniform))['classification'], 'all')
        wrong = compiler.compile_policy(uniform)
        wrong['transitions'][wrong['initial']][0][0] = 'deny'
        self.assertEqual(binding_profile(uniform, wrong)['classification'], 'none')

    def test_explicit_restricted_binding_family(self):
        p = blank(); p['roles'] = ['r', 't']; p['members'] = [['u', 'r']]
        p['aliases'] = [
            {'name': 'z1', 'kind': 'role', 'candidates': ['r', 't']},
            {'name': 'z2', 'kind': 'role', 'candidates': ['r', 't']},
        ]
        p['rules'] = [
            {'decision': 'allow', 'guard': [
                {'field': 'role', 'alias': 'z1', 'negated': False},
                {'field': 'role', 'alias': 'z2', 'negated': False}], 'updates': []},
            {'decision': 'allow', 'guard': [
                {'field': 'role', 'alias': 'z1', 'negated': True},
                {'field': 'role', 'alias': 'z2', 'negated': True}], 'updates': []},
        ]
        p = language.normalize(p)
        m = {'state_names': [], 'alphabet': [['u', 'o', 'a']], 'observations': [0],
             'initial': 0, 'transitions': [[['allow', 0]]]}
        correlated = [{'z1': 'r', 'z2': 'r'}, {'z1': 't', 'z2': 't'}]
        cross = [{'z1': 'r', 'z2': 't'}, {'z1': 't', 'z2': 'r'}]
        result = verify_family(p, m, {'reachable': [0]}, correlated)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['binding_evaluations'], 2)
        with self.assertRaises(checker.Rejected) as caught:
            verify_family(p, m, {'reachable': [0]}, cross)
        self.assertIn(caught.exception.binding, cross)
        with self.assertRaises(checker.Rejected):
            checker.verify(p, m, {'reachable': [0]})
        self.assertEqual(binding_profile(p, m)['matching_bindings'], 2)
        self.assertEqual(len(normalize_family(p, correlated + correlated)), 2)

    def test_observable_quotient_collapses_only_coherent_fibers(self):
        p = blank(); p['rules'] = [{'decision': 'allow', 'guard': [], 'updates': []}]
        p = language.normalize(p)
        m = {'state_names': [], 'alphabet': [['u', 'o', 'a']], 'observations': [0, 0],
             'initial': 0, 'transitions': [[['allow', 1]], [['allow', 0]]]}
        result = observable_quotient(p, m)
        quotient = result['machine']
        self.assertEqual(result['collapsed_states'], 1)
        self.assertEqual(len(quotient['observations']), 1)
        self.assertTrue(product_oracle(p, m)['equivalent'])
        self.assertTrue(product_oracle(p, quotient)['equivalent'])
        inconsistent = copy.deepcopy(m); inconsistent['transitions'][1][0][0] = 'deny'
        with self.assertRaises(checker.Rejected) as caught:
            observable_quotient(p, inconsistent)
        self.assertEqual(caught.exception.kind, 'mismatch')

    def test_dependence_closed_projection_commutes_with_steps(self):
        p = blank(); p['state'] = [['audit', False], ['source', True], ['used', False]]
        p['rules'] = [
            {'decision': 'allow', 'guard': [{'field': 'state', 'name': 'used', 'value': False}],
             'updates': [{'name': 'audit', 'from': 'audit', 'negated': True},
                         {'name': 'used', 'from': 'source', 'negated': False}]},
            {'decision': 'allow', 'guard': [],
             'updates': [{'name': 'audit', 'from': 'audit', 'negated': True}]},
        ]
        p = language.normalize(p)
        cone = observation_cone(p, [])
        self.assertEqual(cone['retained'], ['source', 'used'])
        self.assertEqual(cone['discarded'], ['audit'])
        projected = project_policy(p, [])
        reduced = projected['policy']; retained = projected['cone']['retained']
        for state in range(1 << len(p['state'])):
            reduced_state = project_state(p, retained, state)
            full = checker.reference_step(p, state, ['u', 'o', 'a'], {})
            small = checker.reference_step(reduced, reduced_state, ['u', 'o', 'a'], {})
            self.assertEqual(small, (full[0], project_state(p, retained, full[1])))
        machine = compiler.compile_policy(p)
        reduced_machine = project_machine(p, machine, retained)
        checker.verify(reduced, reduced_machine, compiler.certificate(reduced_machine))
        quotient = observable_quotient(reduced, reduced_machine)
        self.assertLessEqual(quotient['reachable_observations'], quotient['reachable_original_states'])

    def test_switching_closure_and_decision_only_separation(self):
        for i in range(48):
            p = generated(i); m = compiler.compile_policy(p)
            try:
                checker.verify(p, m, compiler.certificate(m)); uniform = True
            except checker.Rejected as error:
                self.assertEqual(error.kind, 'mismatch'); uniform = False
            self.assertEqual(switching_oracle(p, m)['equivalent'], uniform)

        p = blank(); p['roles'] = ['r', 's']; p['members'] = [['u', 'r']]
        p['state'] = [['b', False]]
        p['aliases'] = [{'name': 'z', 'kind': 'role', 'candidates': ['r', 's']}]
        p['rules'] = [
            {'decision': 'allow', 'guard': [{'field': 'role', 'alias': 'z', 'negated': False}],
             'updates': [{'name': 'b', 'value': True}]},
            {'decision': 'allow', 'guard': [
                {'field': 'role', 'alias': 'z', 'negated': True},
                {'field': 'state', 'name': 'b', 'value': False}], 'updates': []},
        ]
        p = language.normalize(p)
        m = {'state_names': ['b'], 'alphabet': [['u', 'o', 'a']], 'observations': [0],
             'initial': 0, 'transitions': [[['allow', 0]]]}
        self.assertTrue(product_oracle(p, m, decisions_only=True)['equivalent'])
        switched = switching_oracle(p, m, decisions_only=True)
        self.assertFalse(switched['equivalent'])
        self.assertEqual(switched['length'], 2)
        self.assertEqual(switched['bindings'], [{'z': 'r'}, {'z': 's'}])


    def test_diagnose_reports_initial_mismatch_at_length_zero(self):
        p = blank(); p['state'] = [['b', False]]; p = language.normalize(p)
        m = compiler.compile_policy(p)
        m['initial'] = next(q for q, observed in enumerate(m['observations'])
                            if observed != language.initial(p))
        result = compiler.diagnose(p, m)
        self.assertFalse(result['equivalent'])
        self.assertEqual(result['length'], 0)
        self.assertEqual(result['indices'], [])
        self.assertEqual(result['trace'], [])
        self.assertEqual(result['local_evaluations'], 0)
        self.assertEqual(result['reason'], 'initial observation')

    def test_negative_work_budgets_are_inconclusive(self):
        p = language.normalize(blank()); m = compiler.compile_policy(p)
        with self.assertRaises(checker.Rejected) as caught:
            checker.verify(p, m, compiler.certificate(m), budget=-1)
        self.assertEqual(caught.exception.kind, 'inconclusive')
        with self.assertRaises(checker.Rejected) as caught:
            product_oracle(p, m, budget=-1)
        self.assertEqual(caught.exception.kind, 'inconclusive')
        with self.assertRaises(language.PolicyError) as caught:
            compiler.diagnose(p, m, limit=-1)
        self.assertEqual(caught.exception.category, 'LIMIT')
        with self.assertRaises(checker.Rejected) as caught:
            observable_quotient(p, m, budget=-1)
        self.assertEqual(caught.exception.kind, 'inconclusive')

    def test_wide_binding_family_fails_before_materialization(self):
        p = blank(); p['roles'] = ['r', 's']; p['members'] = [['u', 'r']]
        p['aliases'] = [
            {'name': f'z{i:02d}', 'kind': 'role', 'candidates': ['r', 's']}
            for i in range(16)
        ]
        p = language.normalize(p)
        with self.assertRaises(checker.Rejected) as caught:
            normalize_family(p, family_limit=1024)
        self.assertEqual(caught.exception.kind, 'inconclusive')
        self.assertIn('cardinality', str(caught.exception))

    def test_unbounded_binding_iterable_is_stopped_by_family_limit(self):
        p = blank(); p['roles'] = ['r']; p['members'] = [['u', 'r']]
        p['aliases'] = [{'name': 'z', 'kind': 'role', 'candidates': ['r']}]
        p = language.normalize(p)
        def duplicates():
            while True:
                yield {'z': 'r'}
        with self.assertRaises(checker.Rejected) as caught:
            normalize_family(p, duplicates(), budget=128, family_limit=32)
        self.assertEqual(caught.exception.kind, 'inconclusive')
        self.assertIn('cardinality', str(caught.exception))

    def test_derived_budgets_cover_preparation_and_graph_work(self):
        p = language.normalize(blank()); m = compiler.compile_policy(p)
        with self.assertRaises(checker.Rejected) as caught:
            observable_quotient(p, m, budget=0)
        self.assertEqual(caught.exception.kind, 'inconclusive')
        with self.assertRaises(checker.Rejected) as caught:
            verify_family(p, m, compiler.certificate(m), [{}], budget=0)
        self.assertEqual(caught.exception.kind, 'inconclusive')
        with self.assertRaises(checker.Rejected) as caught:
            binding_profile(p, m, budget=0)
        self.assertEqual(caught.exception.kind, 'inconclusive')
        with self.assertRaises(checker.Rejected) as caught:
            switching_oracle(p, m, budget=0)
        self.assertEqual(caught.exception.kind, 'inconclusive')

    def test_decision_only_replay_marks_the_compared_observation(self):
        p = blank(); p['roles'] = ['r', 's']; p['members'] = [['u', 'r']]
        p['state'] = [['b', False]]
        p['aliases'] = [{'name': 'z', 'kind': 'role', 'candidates': ['r', 's']}]
        p['rules'] = [
            {'decision': 'allow', 'guard': [{'field': 'role', 'alias': 'z', 'negated': False}],
             'updates': [{'name': 'b', 'value': True}]},
            {'decision': 'allow', 'guard': [
                {'field': 'role', 'alias': 'z', 'negated': True},
                {'field': 'state', 'name': 'b', 'value': False}], 'updates': []},
        ]
        p = language.normalize(p)
        m = {'state_names': ['b'], 'alphabet': [['u', 'o', 'a']], 'observations': [0],
             'initial': 0, 'transitions': [[['allow', 0]]]}
        result = switching_oracle(p, m, decisions_only=True)
        self.assertFalse(result['equivalent'])
        self.assertEqual(result['length'], 2)
        self.assertTrue(result['trace'][0]['decision_equal'])
        self.assertFalse(result['trace'][0]['state_equal'])
        self.assertTrue(result['trace'][0]['compared_equal'])
        self.assertFalse(result['trace'][-1]['compared_equal'])

    def test_action_aliases_participate_in_profiles_and_support(self):
        p = blank(); p['actions'] = ['a', 'b']
        p['aliases'] = [{'name': 'act', 'kind': 'action', 'candidates': ['a', 'b']}]
        p['rules'] = [{'decision': 'allow',
                       'guard': [{'field': 'action', 'alias': 'act', 'negated': False}],
                       'updates': []}]
        p = language.normalize(p)
        m = compiler.compile_policy(p, {'act': 'a'})
        report = binding_profile(p, m)
        self.assertEqual(report['classification'], 'some')
        self.assertEqual(report['matching_bindings'], 1)
        self.assertEqual(report['failing_bindings'], 1)
        self.assertEqual({tuple(row['binding'].items()) for row in report['profiles']},
                         {(('act', 'a'),), (('act', 'b'),)})
        self.assertEqual(checker.support(p, 0, ['u', 'o', 'a']), ['act'])
        for row in report['profiles']:
            fixed = copy.deepcopy(p)
            fixed['aliases'][0]['candidates'] = [row['binding']['act']]
            direct = product_oracle(language.normalize(fixed), m)
            self.assertEqual(row['equivalent'], direct['equivalent'])

    def test_reference_inventory_integrity(self):
        root = Path(__file__).resolve().parents[1]
        report = reference_check.validate(
            inventory_path=root / "reference_inventory.csv",
            audit_path=root / "reference_audit.csv",
        )
        self.assertEqual(report["references"], 58)
        self.assertEqual(report["identifier_distribution"],
                         {"doi": 55, "arxiv": 2, "technical_report": 1})
        self.assertEqual(report["unique_publication_identifiers"], 58)
        self.assertTrue(report["all_references_cited"])
        parsed = reference_check.parse_bibtex(
            "@article{x, title={{Nested} Title}, author={A and B}, year={2026}, doi={10.1000/example}}\n"
        )
        self.assertEqual(parsed["x"]["fields"]["title"], "{Nested} Title")


    def test_complete_tiny_domain_audit_generators(self):
        policies = exhaustive_audit.policy_representatives()
        machines = list(exhaustive_audit.target_machines())
        self.assertEqual(len(policies), 180)
        self.assertEqual(len(machines), 128)
        self.assertEqual(len({exhaustive_audit.semantic_signature(policy) for policy in policies}), 180)
        counts = {1: 0, 2: 0}
        for policy in policies:
            bindings = list(exhaustive_audit.complete_bindings(policy))
            counts[len(bindings)] += 1
            for binding in bindings:
                for state in (0, 1):
                    expected = exhaustive_audit.direct_step(policy, state, exhaustive_audit.REQUEST, binding)
                    self.assertEqual(expected, compiler.step(policy, state, exhaustive_audit.REQUEST, binding))
                    self.assertEqual(expected, checker.reference_step(policy, state, exhaustive_audit.REQUEST, binding))
        self.assertEqual(counts, {1: 18, 2: 162})

if __name__ == '__main__':
    unittest.main()
