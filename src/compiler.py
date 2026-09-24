"""Compiler and certificate producer. The checker does not import this module."""
from __future__ import annotations
from collections import deque
from itertools import product
from typing import Any
from language import normalize, initial, require, PolicyError

def alphabet(p):
    return [list(r) for r in product(p['principals'], p['resources'], p['actions'])]

def default_binding(p):
    return {a['name']: a['candidates'][0] for a in p['aliases']}

def check_binding(p, binding):
    require(set(binding) == {a['name'] for a in p['aliases']}, 'NAME', 'incomplete binding')
    for a in p['aliases']:
        require(binding[a['name']] in a['candidates'], 'NAME', 'binding candidate')

def atom_value(p, a, state, request, binding):
    field = a['field']
    if field == 'state':
        i = next(i for i, (name, _) in enumerate(p['state']) if name == a['name'])
        return bool((state >> i) & 1) == a['value']
    value = binding[a['alias']] if 'alias' in a else a['name']
    if field == 'role':
        truth = [request[0], value] in p['members']
    else:
        truth = request[{'principal': 0, 'resource': 1, 'action': 2}[field]] == value
    return truth != a['negated']

def step(p, state, request, binding):
    for r in p['rules']:
        if all(atom_value(p, a, state, request, binding) for a in r['guard']):
            new_state = state
            positions = {b: i for i, (b, _) in enumerate(p['state'])}
            for e in r['updates']:
                value = e['value'] if 'value' in e else bool((state >> positions[e['from']]) & 1) != e['negated']
                mask = 1 << positions[e['name']]
                new_state = (new_state | mask) if value else (new_state & ~mask)
            return r['decision'], new_state
    return 'deny', state

def active_support(p, state, request):
    used = set()
    for r in p['rules']:
        concrete = [a for a in r['guard'] if 'alias' not in a]
        if all(atom_value(p, a, state, request, {}) for a in concrete):
            used.update(a['alias'] for a in r['guard'] if 'alias' in a)
    return sorted(used)

def compile_policy(p, binding=None):
    p = normalize(p)
    binding = default_binding(p) if binding is None else dict(binding)
    check_binding(p, binding)
    inputs = alphabet(p)
    # Deliberately use a different numeric representation from the source state.
    observations = list(reversed(range(1 << len(p['state']))))
    index = {s: q for q, s in enumerate(observations)}
    table = []
    for state in observations:
        row = []
        for request in inputs:
            decision, target_state = step(p, state, request, binding)
            row.append([decision, index[target_state]])
        table.append(row)
    return {'state_names': [b for b, _ in p['state']], 'alphabet': inputs,
            'observations': observations, 'initial': index[initial(p)], 'transitions': table}

def reachable(machine):
    first = machine['initial']
    paths = {first: []}
    queue = deque([first])
    while queue:
        q = queue.popleft()
        for i, (_, dst) in enumerate(machine['transitions'][q]):
            if dst not in paths:
                paths[dst] = paths[q] + [i]
                queue.append(dst)
    return paths

def certificate(machine):
    return {'reachable': list(reachable(machine))}

def replay(p, machine, indices, binding):
    source = initial(p); q = machine['initial']; rows = []
    for index in indices:
        request = machine['alphabet'][index]
        d, nxt = step(p, source, request, binding)
        md, mq = machine['transitions'][q][index]
        observed = machine['observations'][mq]
        rows.append({'request': request, 'source': [d, nxt], 'target': [md, observed]})
        source = nxt; q = mq
        if (d, nxt) != (md, observed):
            break
    return rows

def diagnose(p, machine, limit=2_000_000):
    """Search in breadth-first target-state order; return a shortest uniform witness."""
    require(type(limit) is int and limit >= 0, 'LIMIT', 'diagnostic obligation budget')
    source_initial = initial(p)
    target_initial = machine['observations'][machine['initial']]
    if source_initial != target_initial:
        return {'equivalent': False, 'binding': default_binding(p), 'indices': [],
                'trace': [], 'length': 0, 'reason': 'initial observation',
                'local_evaluations': 0, 'maximum_width': 0}
    choices = {a['name']: a['candidates'] for a in p['aliases']}
    count = 0; maximum_width = 0
    for q, prefix in reachable(machine).items():
        state = machine['observations'][q]
        for i, request in enumerate(machine['alphabet']):
            support = active_support(p, state, request)
            maximum_width = max(maximum_width, len(support))
            for values in product(*(choices[a] for a in support)):
                count += 1
                require(count <= limit, 'LIMIT', 'diagnostic obligations')
                binding = default_binding(p)
                binding.update(zip(support, values))
                decision, post = step(p, state, request, binding)
                md, mq = machine['transitions'][q][i]
                if (decision, post) != (md, machine['observations'][mq]):
                    path = prefix + [i]
                    rows = replay(p, machine, path, binding)
                    require(len(rows) == len(path), 'INTERNAL', 'diagnostic replay ended before selected cell')
                    require(all(row['source'] == row['target'] for row in rows[:-1]),
                            'INTERNAL', 'diagnostic replay diverged before selected cell')
                    require(rows[-1]['source'] != rows[-1]['target'],
                            'INTERNAL', 'diagnostic replay did not diverge at selected cell')
                    return {'equivalent': False, 'binding': binding, 'indices': path,
                            'trace': rows, 'length': len(path), 'local_evaluations': count,
                            'maximum_width': maximum_width}
    return {'equivalent': True, 'local_evaluations': count, 'maximum_width': maximum_width}

def decompile(machine, interface, limits=True):
    """Reify a reachable-observation-consistent, deny-stuttering machine as literal rules.

    This is a semantic reification, not recovery of the original text or rule order.
    The caller supplies the finite names and static role table as the interface.
    """
    p = normalize(interface)
    require(machine['alphabet'] == alphabet(p), 'INTERFACE', 'reification alphabet')
    require(machine['state_names'] == [b for b, _ in p['state']], 'INTERFACE', 'reification state names')
    representatives = {}
    nstates = 1 << len(p['state'])
    for q in reachable(machine):
        state = machine['observations'][q]
        require(type(state) is int and 0 <= state < nstates, 'TYPE', 'observation')
        outputs = []
        for decision, dst in machine['transitions'][q]:
            post = machine['observations'][dst]
            require(decision != 'deny' or post == state, 'EFFECT', 'denying machine changes state')
            outputs.append((decision, post))
        if state in representatives:
            require(representatives[state][1] == outputs, 'TYPE', 'hidden state changes observable behavior')
        else:
            representatives[state] = (q, outputs)
    p['aliases'] = []
    start = machine['observations'][machine['initial']]
    p['state'] = [[b, bool((start >> i) & 1)] for i, (b, _) in enumerate(p['state'])]
    p['rules'] = []
    for state, (_, outputs) in sorted(representatives.items()):
        for request, (decision, post) in zip(machine['alphabet'], outputs):
            if decision == 'deny':
                continue
            guard = [{'field': field, 'name': name, 'negated': False}
                     for field, name in zip(('principal', 'resource', 'action'), request)]
            guard += [{'field': 'state', 'name': b, 'value': bool((state >> j) & 1)} for j, (b, _) in enumerate(p['state'])]
            updates = [{'name': b, 'value': bool((post >> j) & 1)} for j, (b, _) in enumerate(p['state'])]
            p['rules'].append({'decision': 'allow', 'guard': guard, 'updates': updates})
    return normalize(p, limits)
