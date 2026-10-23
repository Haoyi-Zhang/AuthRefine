"""Executable two-stage mathematical example, separate from the measured cohorts."""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path

from baseline_checks import ordinary_bfs
from checker import verify_reachable
from compiler import compile_policy
from extensions import binding_profile
from language import normalize
from oracle import product_oracle


def example():
    policy = {
        'principals': ['u'], 'resources': ['o'], 'actions': ['a', 'b'],
        'roles': ['r', 't'], 'members': [['u', 'r']], 'state': [['p', False]],
        'aliases': [{'name': name, 'kind': 'role', 'candidates': ['r', 't']}
                    for name in ('z_a', 'z_b')],
        'rules': [],
    }
    for action, before, after in (('a', False, True), ('b', True, False)):
        policy['rules'].append({
            'decision': 'allow',
            'guard': [{'field': 'action', 'name': action, 'negated': False},
                      {'field': 'state', 'name': 'p', 'value': before},
                      {'field': 'role', 'alias': 'z_' + action, 'negated': False}],
            'updates': [{'name': 'p', 'value': after}],
        })
    policy = normalize(policy)
    return policy, compile_policy(policy, {'z_a': 'r', 'z_b': 'r'})


def run():
    policy, machine = example()
    profile = binding_profile(policy, machine)
    expected = {('r', 'r'): None, ('r', 't'): 2, ('t', 'r'): 1, ('t', 't'): 1}
    rows = []
    for row in profile['profiles']:
        fixed = deepcopy(policy)
        for alias in fixed['aliases']:
            alias['candidates'] = [row['binding'][alias['name']]]
        fixed = normalize(fixed)
        bfs = ordinary_bfs(fixed, machine)
        product = product_oracle(fixed, machine)
        checked = verify_reachable(fixed, machine)
        product_length = None if product['equivalent'] else product['shortest']['length']
        key = tuple(row['binding'][name] for name in ('z_a', 'z_b'))
        if not row['length'] == bfs['length'] == product_length == checked['length'] == expected[key]:
            raise ValueError('Two-stage shortest-length disagreement')
        rows.append({'binding': row['binding'], 'length': row['length'],
                     'equivalent': row['equivalent'], 'trace': row['trace'],
                     'bfs_length': bfs['length'], 'product_length': product_length,
                     'checked_length': checked['length']})
    return {'scope': 'Mathematical example, not a new measured campaign or deployment',
            'policy': policy, 'machine': machine, 'profiles': rows,
            'strata': profile['strata'], 'all_lengths_agree': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = json.dumps(run(), indent=2) + '\n'
    if args.output:
        # Never replace retained data or reuse another measurement destination.
        with args.output.open('x', encoding='utf-8') as stream:
            stream.write(result)
    else:
        print(result, end='')
