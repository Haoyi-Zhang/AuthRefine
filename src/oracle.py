"""Explicit fixed-binding product oracle; does not use the local-support reduction."""
from collections import deque
from itertools import product
from checker import inspect_policy, inspect_machine, reference_step, Rejected, integer

def all_bindings(p):
    names = [a['name'] for a in p['aliases']]
    for xs in product(*(a['candidates'] for a in p['aliases'])):
        yield dict(zip(names, xs))

def product_oracle(p, machine, decisions_only=False, budget=2_000_000):
    if not integer(budget) or budget < 0:
        raise Rejected('product oracle obligation budget', 'inconclusive')
    inspect_policy(p); inspect_machine(p, machine, compare_initial=False)
    start = sum(2 ** i for i, (_, value) in enumerate(p['state']) if value)
    if not decisions_only and start != machine['observations'][machine['initial']]:
        return {'equivalent': False, 'shortest': {'binding': next(all_bindings(p)), 'indices': [], 'length': 0},
                'transition_evaluations': 0, 'visited_pairs': 0, 'bindings_examined': 1}
    count = 0; total_pairs = 0; resolutions = 0; shortest = None
    for binding in all_bindings(p):
        resolutions += 1
        initial_pair = (start, machine['initial'])
        seen = {initial_pair}; queue = deque([(initial_pair, [])]); local_witness = None
        while queue:
            (source, target), prefix = queue.popleft()
            total_pairs += 1
            for i, request in enumerate(machine['alphabet']):
                count += 1
                if count > budget:
                    raise Rejected('product oracle obligation budget', 'inconclusive')
                decision, source_next = reference_step(p, source, request, binding)
                md, target_next = machine['transitions'][target][i]
                different = decision != md
                if not decisions_only:
                    different = different or source_next != machine['observations'][target_next]
                if different:
                    local_witness = {'binding': binding, 'indices': prefix + [i], 'length': len(prefix) + 1}
                    queue.clear(); break
                pair = (source_next, target_next)
                if pair not in seen:
                    seen.add(pair); queue.append((pair, prefix + [i]))
        if local_witness is not None:
            if shortest is None or local_witness['length'] < shortest['length']:
                shortest = local_witness
            # One request is the smallest possible mismatch after equal initial observations.
            if shortest['length'] == 1:
                break
    return {'equivalent': shortest is None, 'shortest': shortest, 'transition_evaluations': count,
            'visited_pairs': total_pairs, 'bindings_examined': resolutions}

def exhaustive_words(p, machine, maximum_depth=8, decisions_only=False, budget=100_000):
    """Small independent depth oracle; enumerates complete words, not a state graph."""
    start = sum(2 ** i for i, (_, value) in enumerate(p['state']) if value)
    if not decisions_only and start != machine['observations'][machine['initial']]:
        return {'found': True, 'length': 0, 'evaluations': 0}
    count = 0
    for depth in range(1, maximum_depth + 1):
        for word in product(range(len(machine['alphabet'])), repeat=depth):
            for binding in all_bindings(p):
                state = start; q = machine['initial']
                for i in word:
                    count += 1
                    if count > budget:
                        raise Rejected('word oracle obligation budget', 'inconclusive')
                    d, state = reference_step(p, state, machine['alphabet'][i], binding)
                    md, q = machine['transitions'][q][i]
                    if d != md or (not decisions_only and state != machine['observations'][q]):
                        return {'found': True, 'length': depth, 'evaluations': count}
    return {'found': False, 'length': None, 'evaluations': count, 'checked_depth': maximum_depth}
