"""Owned finite guard-shape regressions; no campaign or external service."""
import copy
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import checker
import compiler
import language


def base_policy():
    return {'principals': ['u', 'v'], 'resources': ['o', 'p'],
            'actions': ['a', 'b'], 'roles': ['r', 's'],
            'members': [['u', 'r']], 'state': [['flag', False]],
            'aliases': [], 'rules': []}


def valid_policies():
    result = []
    for field, candidates in (('principal', ['u', 'v']), ('resource', ['o', 'p']),
                              ('action', ['a', 'b']), ('role', ['r', 's'])):
        for form in ('literal', 'alias'):
            policy = base_policy()
            reference = {'name': candidates[0]}
            if form == 'alias':
                policy['aliases'] = [{'name': 'choice', 'kind': field,
                                      'candidates': candidates}]
                reference = {'alias': 'choice'}
            # Complementary alias guards have identical effects, so both admitted
            # bindings agree. Literal cases instead deny when their test is false.
            for negated in ((False, True) if form == 'alias' else (False,)):
                policy['rules'].append({'decision': 'allow', 'guard': [
                    {'field': field, **reference, 'negated': negated}],
                    'updates': [{'name': 'flag', 'value': True}]})
            result.append((form + '-' + field, language.normalize(policy)))
    for combined in (False, True):
        policy = base_policy()
        guard = [{'field': 'state', 'name': 'flag', 'value': False}]
        if combined:
            guard.insert(0, {'field': 'principal', 'name': 'u', 'negated': False})
        policy['rules'] = [{'decision': 'allow', 'guard': guard,
                            'updates': [{'name': 'flag', 'value': True}]}]
        result.append(('literal-state' if combined else 'state', language.normalize(policy)))
    return result


class GuardFieldTypesTests(unittest.TestCase):
    def test_invalid_fields_raise_invalid_rejected_in_all_three_apis(self):
        _, policy = valid_policies()[0]
        machine = compiler.compile_policy(policy)
        certificate = compiler.certificate(machine)
        for value in ([], {}, None, 'unknown'):
            malformed = copy.deepcopy(policy)
            malformed['rules'][0]['guard'][0]['field'] = value
            snapshot = copy.deepcopy((malformed, machine, certificate))
            for api, call in (
                ('inspect_policy', lambda: checker.inspect_policy(malformed)),
                ('verify_reachable', lambda: checker.verify_reachable(malformed, machine)),
                ('verify', lambda: checker.verify(malformed, machine, certificate)),
            ):
                with self.subTest(field=value, api=api):
                    with self.assertRaises(checker.Rejected) as caught:
                        call()
                    self.assertEqual(caught.exception.kind, 'invalid')
                    self.assertEqual((malformed, machine, certificate), snapshot)

    def test_invalid_fields_cli_fail_closed_in_each_mode(self):
        _, policy = valid_policies()[0]
        machine = compiler.compile_policy(policy)
        with tempfile.TemporaryDirectory(prefix='owned-guard-field-') as directory:
            folder = Path(directory)
            paths = {name: folder / (name + '.json') for name in ('policy', 'machine', 'certificate')}
            paths['machine'].write_text(json.dumps(machine), encoding='utf-8')
            paths['certificate'].write_text(json.dumps(compiler.certificate(machine)), encoding='utf-8')
            for value in ([], {}, None, 'unknown'):
                malformed = copy.deepcopy(policy)
                malformed['rules'][0]['guard'][0]['field'] = value
                paths['policy'].write_text(json.dumps(malformed), encoding='utf-8')
                for mode, extra in (('reachable', []), ('reuse', ['--reuse-observations']),
                                    ('region', [str(paths['certificate'])])):
                    with self.subTest(field=value, mode=mode):
                        done = subprocess.run([sys.executable, '-B', str(ROOT / 'src/checker.py'),
                            str(paths['policy']), str(paths['machine']), *extra],
                            capture_output=True, text=True, encoding='utf-8', timeout=5)
                        self.assertEqual(done.returncode, 1)
                        report = json.loads(done.stdout)
                        self.assertEqual(report['status'], 'invalid')
                        self.assertIs(report['accepted'], False)
                        self.assertEqual(done.stderr, '')

    def check_valid(self, policy):
        snapshot = copy.deepcopy(policy)
        aliases = checker.inspect_policy(policy)
        self.assertEqual(set(aliases), {row['name'] for row in policy['aliases']})
        machine = compiler.compile_policy(policy)
        self.assertTrue(checker.verify(policy, machine, compiler.certificate(machine))['accepted'])
        for reuse in (False, True):
            self.assertTrue(checker.verify_reachable(policy, machine,
                details=True, reuse_observations=reuse)['equivalent'])
        self.assertEqual(policy, snapshot)

    def test_valid_literal_and_state_guards_keep_expected_steps(self):
        for name, policy in valid_policies():
            if name.startswith('alias-'):
                continue
            with self.subTest(policy=name):
                self.check_valid(policy)
                atom = policy['rules'][0]['guard'][0]
                for state, request in itertools.product((0, 1), compiler.alphabet(policy)):
                    if name == 'literal-state':
                        allow = request[0] == 'u' and state == 0
                    elif atom['field'] == 'state':
                        allow = state == 0
                    elif atom['field'] == 'role':
                        allow = request[0] == 'u'
                    else:
                        allow = request[('principal', 'resource', 'action').index(atom['field'])] == atom['name']
                    expected = ('allow', 1) if allow else ('deny', state)
                    self.assertEqual(checker.reference_step(policy, state, request, {}), expected)
                    self.assertEqual(compiler.step(policy, state, request, {}), expected)

    def test_all_four_alias_sorts_preserve_both_admitted_bindings(self):
        for name, policy in valid_policies():
            if not name.startswith('alias-'):
                continue
            with self.subTest(policy=name):
                self.check_valid(policy)
                alias = policy['aliases'][0]
                for value, state, request in itertools.product(alias['candidates'], (0, 1), compiler.alphabet(policy)):
                    binding = {alias['name']: value}
                    self.assertEqual(checker.reference_step(policy, state, request, binding), ('allow', 1))
                    self.assertEqual(compiler.step(policy, state, request, binding), ('allow', 1))


if __name__ == '__main__':
    unittest.main()
