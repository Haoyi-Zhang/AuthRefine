"""Deterministic primary cases and small semantic boundary examples."""
from __future__ import annotations
from copy import deepcopy
from language import normalize
from compiler import compile_policy, certificate, reachable
from public_inputs import MODELS, read_inputs, translate, extend

class Generator:
    def __init__(self, seed):
        self.value = seed
    def choose(self, n):
        self.value = (1103515245 * self.value + 12345) % (2 ** 31)
        return (self.value // 256) % n

def blank():
    return {'principals': ['u'], 'resources': ['o'], 'actions': ['a'], 'roles': [],
            'members': [], 'state': [], 'aliases': [], 'rules': []}

def generated(index):
    g = Generator(index + 17)
    p = blank(); p['principals'] = ['u', 'v']; p['resources'] = ['o', 'p']; p['roles'] = ['r', 's']
    p['members'] = [[u, r] for u in p['principals'] for r in p['roles'] if g.choose(2)]
    if g.choose(2):
        p['state'] = [['b', bool(g.choose(2))]]
    for j in range(g.choose(3)):
        kind = ['role', 'principal', 'resource'][g.choose(3)]
        candidates = p[{'role': 'roles', 'principal': 'principals', 'resource': 'resources'}[kind]]
        p['aliases'].append({'name': 'x' + str(j), 'kind': kind, 'candidates': candidates[:]})
    for _ in range(1 + g.choose(6)):
        r = {'decision': 'allow' if g.choose(4) else 'deny', 'guard': [], 'updates': []}
        for _ in range(g.choose(4)):
            fields = ['principal', 'resource', 'action', 'role'] + (['state'] if p['state'] else [])
            field = fields[g.choose(len(fields))]
            if field == 'state':
                r['guard'].append({'field': field, 'name': 'b', 'value': bool(g.choose(2))})
            else:
                candidates = [a for a in p['aliases'] if a['kind'] == field]
                if candidates and g.choose(2):
                    ref = {'alias': candidates[g.choose(len(candidates))]['name']}
                else:
                    values = p[{'principal': 'principals', 'resource': 'resources', 'action': 'actions', 'role': 'roles'}[field]]
                    ref = {'name': values[g.choose(len(values))]}
                r['guard'].append({'field': field, **ref, 'negated': bool(g.choose(3) == 0)})
        if p['state'] and r['decision'] == 'allow' and g.choose(3):
            choice = g.choose(4)
            r['updates'] = [{'name': 'b', 'value': bool(choice)}] if choice < 2 else [{'name': 'b', 'from': 'b', 'negated': choice == 3}]
        p['rules'].append(r)
    return normalize(p)

def width_case(m):
    p = blank(); p['roles'] = ['r', 's']; p['members'] = [['u', 'r']]
    p['actions'] = [f'a{i:02d}' for i in range(m)]
    p['state'] = [['b', False]]
    for i, action in enumerate(p['actions']):
        alias = f'x{i:02d}'
        p['aliases'].append({'name': alias, 'kind': 'role', 'candidates': ['r', 's']})
        for negated in (False, True):
            p['rules'].append({'decision': 'allow', 'guard': [
                {'field': 'action', 'name': action, 'negated': False},
                {'field': 'role', 'alias': alias, 'negated': negated}],
                'updates': [{'name': 'b', 'from': 'b', 'negated': True}]})
    return normalize(p)

CHAIN_LENGTHS = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 32, 64, 128)

def chain_case(length):
    p = blank(); bits = (length - 1).bit_length()
    p['state'] = [[f'b{i}', False] for i in range(bits)]
    if length & (length - 1) == 0:
        # Binary increment: the first zero bit becomes one and its lower bits clear.
        for i in range(bits):
            guard = [{'field': 'state', 'name': f'b{j}', 'value': True} for j in range(i)]
            guard.append({'field': 'state', 'name': f'b{i}', 'value': False})
            updates = [{'name': f'b{j}', 'value': False} for j in range(i)] + [{'name': f'b{i}', 'value': True}]
            p['rules'].append({'decision': 'allow', 'guard': guard, 'updates': updates})
        p['rules'].append({'decision': 'allow', 'guard': [], 'updates': [{'name': f'b{i}', 'value': False} for i in range(bits)]})
    else:
        for state in range(length):
            guard = [{'field': 'state', 'name': f'b{i}', 'value': bool((state >> i) & 1)} for i in range(bits)]
            nxt = min(state + 1, length - 1)
            updates = [{'name': f'b{i}', 'value': bool((nxt >> i) & 1)} for i in range(bits)]
            p['rules'].append({'decision': 'allow', 'guard': guard, 'updates': updates})
    p = normalize(p); m = compile_policy(p)
    terminal = m['observations'].index(length - 1)
    m['transitions'][terminal][0] = ['deny', terminal]
    return p, m

NEGATIVE_KINDS = ('missing-initial', 'missing-successor', 'duplicate-state', 'invalid-state', 'extra-certificate-field',
                  'missing-input', 'reordered-inputs', 'duplicate-input', 'incomplete-row', 'invalid-decision',
                  'boolean-destination', 'invalid-observation', 'wrong-initial-observation', 'duplicate-json-key', 'deny-effect')

def negative_case(kind):
    p = width_case(2); p['aliases'] = []
    for r in p['rules']:
        r['guard'][1] = {'field': 'role', 'name': 'r', 'negated': r['guard'][1]['negated']}
    p = normalize(p); m = compile_policy(p); c = certificate(m)
    if kind == 'missing-initial': c['reachable'] = []
    elif kind == 'missing-successor': c['reachable'] = [m['initial']]
    elif kind == 'duplicate-state': c['reachable'].append(c['reachable'][0])
    elif kind == 'invalid-state': c['reachable'].append(10000)
    elif kind == 'extra-certificate-field': c['trusted'] = True
    elif kind == 'missing-input': m['alphabet'].pop()
    elif kind == 'reordered-inputs': m['alphabet'].reverse()
    elif kind == 'duplicate-input': m['alphabet'][1] = m['alphabet'][0]
    elif kind == 'incomplete-row': m['transitions'][0].pop()
    elif kind == 'invalid-decision': m['transitions'][0][0][0] = 'permit'
    elif kind == 'boolean-destination': m['transitions'][0][0][1] = True
    elif kind == 'invalid-observation': m['observations'][0] = 10000
    elif kind == 'wrong-initial-observation': m['observations'][m['initial']] ^= 1
    elif kind == 'duplicate-json-key': c = '{"reachable": [0, 1], "reachable": []}'
    elif kind == 'deny-effect': p['rules'][0]['decision'] = 'deny'
    else: raise ValueError(kind)
    return p, m, c

def curated():
    cases = []
    p = blank(); p['state'] = [['left', False], ['right', True]]
    p['rules'] = [{'decision': 'allow', 'guard': [], 'updates': [
        {'name': 'left', 'from': 'right', 'negated': False}, {'name': 'right', 'from': 'left', 'negated': False}]}]
    cases.append(('simultaneous-swap', normalize(p)))
    p = blank(); p['rules'] = [{'decision': 'deny', 'guard': [], 'updates': []}, {'decision': 'allow', 'guard': [], 'updates': []}]
    cases.append(('deny-before-allow', normalize(p)))
    p = blank(); p['rules'] = [{'decision': 'allow', 'guard': [], 'updates': []}, {'decision': 'deny', 'guard': [], 'updates': []}]
    cases.append(('allow-before-deny', normalize(p)))
    p = width_case(2); cases.append(('harmless-reference-choice', p))
    p = width_case(1); p['rules'] = p['rules'][:1]; cases.append(('meaningful-reference-choice', normalize(p)))
    p = blank(); p['state'] = [['used', False]]
    p['rules'] = [{'decision': 'allow', 'guard': [{'field': 'state', 'name': 'used', 'value': False}], 'updates': [{'name': 'used', 'value': True}]}]
    cases.append(('one-use-state', normalize(p)))
    p = blank(); p['rules'] = []
    cases.append(('empty-policy', normalize(p)))
    p = blank(); p['principals'] = ['name "with" quotes', '名字']; p['resources'] = ['path\\item']; p['actions'] = ['inspect']
    p['rules'] = [{'decision': 'allow', 'guard': [{'field': 'principal', 'name': '名字', 'negated': False}], 'updates': []}]
    cases.append(('escaped-names', normalize(p)))
    return cases

def primary(index, directory):
    if not 0 <= index < 10000:
        raise ValueError('primary case index')
    if index < 18:
        name = MODELS[index // 3]; mode = ('base', 'one-use', 'toggle')[index % 3]
        rows = read_inputs(directory, name)
        return {'kind': 'public', 'source': name, 'mode': mode, 'policy': extend(translate(name, rows), mode)}
    if index < 18 + 9936:
        i = index - 18
        return {'kind': 'generated', 'generator_index': i, 'policy': generated(i)}
    index -= 18 + 9936
    if index < 16:
        return {'kind': 'width', 'aliases': index + 1, 'policy': width_case(index + 1)}
    index -= 16
    if index < 15:
        length = CHAIN_LENGTHS[index]; p, m = chain_case(length)
        return {'kind': 'chain', 'expected_length': length, 'policy': p, 'machine': m}
    index -= 15
    name = NEGATIVE_KINDS[index]; p, m, cert = negative_case(name)
    return {'kind': 'schema-negative', 'fault': name, 'policy': p, 'machine': m, 'certificate': cert}
