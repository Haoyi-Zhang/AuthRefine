"""Standalone local checker and direct reference semantics.

No imports from the sentence parser, compiler, certificate producer, or adapter.
All comparisons below concern the supplied finite data, not a live policy service.
"""
from __future__ import annotations
from collections import deque
from itertools import product
import json
import unicodedata
from pathlib import Path

class Rejected(ValueError):
    def __init__(self, message, kind="invalid"):
        super().__init__(message)
        self.kind = kind

def ensure(ok, message, kind="invalid"):
    if not ok:
        raise Rejected(message, kind)

def integer(x):
    return type(x) is int

def named(value):
    # Kept local so the checker does not depend on the parser/compiler module.
    return (
        isinstance(value, str)
        and 0 < len(value) <= 256
        and all(unicodedata.category(c) not in {'Cc', 'Cf', 'Cs'} for c in value)
    )

def inspect_policy(p):
    domains = ('principals', 'resources', 'actions', 'roles')
    ensure(isinstance(p, dict) and set(p) == set(domains) | {'members', 'state', 'aliases', 'rules'}, 'policy shape')
    for domain in domains:
        values = p[domain]
        ensure(isinstance(values, list) and len(values) <= (16 if domain in ('principals', 'roles') else 32), 'domain bound')
        ensure(all(named(v) for v in values), 'domain names')
        ensure(values == sorted(set(values)), 'canonical domain')
        ensure(domain == 'roles' or len(values) > 0, 'empty input domain')
    ensure(isinstance(p['state'], list) and len(p['state']) <= 7, 'state bound')
    for declaration in p['state']:
        ensure(isinstance(declaration, list) and len(declaration) == 2 and named(declaration[0])
               and type(declaration[1]) is bool, 'state declaration')
    names = [b for b, _ in p['state']]
    ensure(names == sorted(set(names)), 'canonical state names')
    ensure(isinstance(p['members'], list), 'member list')
    for membership in p['members']:
        ensure(isinstance(membership, list) and len(membership) == 2
               and membership[0] in p['principals'] and membership[1] in p['roles'], 'membership')
    ensure(p['members'] == sorted([list(t) for t in set(tuple(x) for x in p['members'])]), 'canonical members')
    ensure(isinstance(p['aliases'], list) and len(p['aliases']) <= 16, 'alias bound')
    sorts = {'principal': 'principals', 'resource': 'resources', 'action': 'actions', 'role': 'roles'}
    aliases = {}
    for a in p['aliases']:
        ensure(isinstance(a, dict) and set(a) == {'name', 'kind', 'candidates'}, 'alias fields')
        ensure(named(a['name'])
               and a['kind'] in sorts and a['name'] not in aliases, 'alias identity')
        cs = a['candidates']
        ensure(isinstance(cs, list) and cs and all(isinstance(c, str) and c in p[sorts[a['kind']]] for c in cs), 'alias candidates')
        ensure(cs == sorted(set(cs)), 'canonical candidates')
        aliases[a['name']] = a
    ensure(list(aliases) == sorted(aliases), 'canonical aliases')
    ensure(isinstance(p['rules'], list), 'rule list')
    nodes = 0
    for rule in p['rules']:
        ensure(isinstance(rule, dict) and set(rule) == {'decision', 'guard', 'updates'}, 'rule fields')
        ensure(rule['decision'] in ('allow', 'deny') and isinstance(rule['guard'], list) and isinstance(rule['updates'], list), 'rule values')
        nodes += 1 + len(rule['guard']) + len(rule['updates'])
        for test in rule['guard']:
            ensure(isinstance(test, dict) and 'field' in test, 'guard shape')
            sort = test['field']
            if sort == 'state':
                ensure(set(test) == {'field', 'name', 'value'} and test['name'] in names and type(test['value']) is bool, 'state guard')
            else:
                ensure(sort in sorts and type(test.get('negated')) is bool, 'reference sort')
                if 'alias' in test:
                    ensure(set(test) == {'field', 'alias', 'negated'} and test['alias'] in aliases and aliases[test['alias']]['kind'] == sort, 'typed alias')
                else:
                    ensure(set(test) == {'field', 'name', 'negated'} and test['name'] in p[sorts[sort]], 'typed literal')
        ensure(rule['decision'] == 'allow' or not rule['updates'], 'deny effect')
        destinations = []
        for effect in rule['updates']:
            ensure(isinstance(effect, dict) and effect.get('name') in names and effect['name'] not in destinations, 'effect destination')
            destinations.append(effect['name'])
            if 'value' in effect:
                ensure(set(effect) == {'name', 'value'} and type(effect['value']) is bool, 'constant effect')
            else:
                ensure(set(effect) == {'name', 'from', 'negated'} and effect['from'] in names and type(effect['negated']) is bool, 'copy effect')
        ensure(destinations == sorted(destinations), 'canonical assignments')
    ensure(nodes <= 256, 'AST bound')
    return aliases

def inspect_machine(p, m, compare_initial=True):
    ensure(isinstance(m, dict) and set(m) == {'state_names', 'alphabet', 'observations', 'initial', 'transitions'}, 'machine fields')
    inputs = [[u, o, a] for u in p['principals'] for o in p['resources'] for a in p['actions']]
    ensure(m['alphabet'] == inputs and m['state_names'] == [b for b, _ in p['state']], 'machine interface')
    obs = m['observations']
    ensure(isinstance(obs, list) and 0 < len(obs) <= 512, 'machine state bound')
    ensure(all(integer(s) and 0 <= s < 2 ** len(p['state']) for s in obs), 'machine observation')
    ensure(integer(m['initial']) and 0 <= m['initial'] < len(obs), 'machine initial')
    ensure(isinstance(m['transitions'], list) and len(m['transitions']) == len(obs), 'table rows')
    for row in m['transitions']:
        ensure(isinstance(row, list) and len(row) == len(inputs), 'total input coverage')
        for edge in row:
            ensure(isinstance(edge, list) and len(edge) == 2 and edge[0] in ('allow', 'deny')
                   and integer(edge[1]) and 0 <= edge[1] < len(obs), 'edge fields')
    source_initial = sum((2 ** i) for i, (_, value) in enumerate(p['state']) if value)
    if compare_initial:
        ensure(obs[m['initial']] == source_initial, 'initial observation mismatch', 'mismatch')

def reference_step(p, state, request, valuation):
    # Named Boolean environments and simultaneous comprehensions, rather than
    # the compiler's bit-level guard traversal and in-place destination mask.
    old = {name: ((state // (2 ** i)) % 2 == 1) for i, (name, _) in enumerate(p['state'])}
    membership = {tuple(pair) for pair in p['members']}
    request_fields = dict(zip(('principal', 'resource', 'action'), request))
    return _reference_step_prepared(p, state, request, valuation, old, membership, request_fields)

def _reference_step_prepared(p, state, request, valuation, old, membership, request_fields):
    # Checker-owned, invocation/cell-local preparation; never cache verdicts.
    decisions = []
    for position, rule in enumerate(p['rules']):
        truth_values = []
        for term in rule['guard']:
            sort = term['field']
            if sort == 'state':
                ok = old[term['name']] == term['value']
            else:
                referent = term['name'] if 'name' in term else valuation[term['alias']]
                ok = (request[0], referent) in membership if sort == 'role' else request_fields[sort] == referent
                if term['negated']:
                    ok = not ok
            truth_values.append(ok)
        if all(truth_values):
            decisions.append((position, rule))
    if not decisions:
        return 'deny', state
    chosen = min(decisions, key=lambda pair: pair[0])[1]
    changes = {e['name']: (e['value'] if 'value' in e else (not old[e['from']] if e['negated'] else old[e['from']]))
               for e in chosen['updates']}
    after = {name: changes.get(name, value) for name, value in old.items()}
    encoded = sum(2 ** i for i, (name, _) in enumerate(p['state']) if after[name])
    return chosen['decision'], encoded

def support(p, state, request):
    # Prune a rule by concrete tests only. Priority is deliberately not used as
    # a pruning assumption; the resulting support may over-approximate relevance.
    values = {name: ((state // (2 ** i)) % 2 == 1) for i, (name, _) in enumerate(p['state'])}
    fields = dict(zip(('principal', 'resource', 'action'), request))
    dependencies = []
    for r in p['rules']:
        viable = True; names = []
        for atom in r['guard']:
            if 'alias' in atom:
                names.append(atom['alias']); continue
            if atom['field'] == 'state':
                truth = values[atom['name']] == atom['value']
            elif atom['field'] == 'role':
                truth = [request[0], atom['name']] in p['members']
                truth = not truth if atom['negated'] else truth
            else:
                truth = fields[atom['field']] == atom['name']
                truth = not truth if atom['negated'] else truth
            viable = viable and truth
        if viable:
            dependencies.extend(names)
    return sorted(set(dependencies))

def verify(p, m, cert, budget=2_000_000):
    """Legacy closed-region check; budget counts binding evaluations only."""
    ensure(integer(budget) and budget >= 0, 'checker obligation budget', 'inconclusive')
    aliases = inspect_policy(p)
    inspect_machine(p, m)
    ensure(isinstance(cert, dict) and set(cert) == {'reachable'}, 'certificate fields')
    states = cert['reachable']
    ensure(isinstance(states, list) and all(integer(q) and 0 <= q < len(m['observations']) for q in states), 'certificate states')
    ensure(len(states) == len(set(states)) and m['initial'] in states, 'certificate initial or duplicate')
    region = set(states)
    for q in states:
        ensure(all(edge[1] in region for edge in m['transitions'][q]), 'certificate closure')
    count = 0; maximum_width = 0; cells = []
    filler = {name: item['candidates'][0] for name, item in aliases.items()}
    membership = frozenset(tuple(pair) for pair in p['members'])
    for q in states:
        state = m['observations'][q]
        for index, request in enumerate(m['alphabet']):
            deps = support(p, state, request)
            maximum_width = max(maximum_width, len(deps))
            cases = 1
            for name in deps:
                cases *= len(aliases[name]['candidates'])
            ensure(count + cases <= budget, 'checker obligation budget', 'inconclusive')
            old = {name: ((state // (2 ** i)) % 2 == 1) for i, (name, _) in enumerate(p['state'])}
            request_fields = dict(zip(('principal', 'resource', 'action'), request))
            for assignment in product(*(aliases[name]['candidates'] for name in deps)):
                count += 1
                valuation = dict(filler); valuation.update(zip(deps, assignment))
                actual = _reference_step_prepared(p, state, request, valuation, old, membership, request_fields)
                edge = m['transitions'][q][index]
                expected = (edge[0], m['observations'][edge[1]])
                if actual != expected:
                    error = Rejected(f'refinement mismatch at state {q}, request {index}', 'mismatch')
                    error.evaluations = count
                    error.maximum_width = maximum_width
                    raise error
            cells.append({'state': q, 'request': index, 'support': deps, 'bindings': cases})
    return {'accepted': True, 'states': len(states), 'local_cells': len(cells),
            'binding_evaluations': count, 'maximum_width': maximum_width, 'cells': cells}

class _ReachableWork:
    """Declared traversal/preparation/node charges, not CPU instructions.

    Schema validation is separately bounded by the existing input envelopes.
    Semantic node charges conservatively include all effects, even unselected ones.
    """
    def __init__(self, limit):
        ensure(integer(limit) and limit >= 0, 'reachable work budget', 'inconclusive')
        self.limit = limit
        self.total = 0
        self.parts = {}

    def charge(self, amount, category):
        if self.total + amount > self.limit:
            error = Rejected('reachable work budget', 'inconclusive')
            error.work_operations = self.total
            error.work_breakdown = dict(self.parts)
            raise error
        self.total += amount
        self.parts[category] = self.parts.get(category, 0) + amount

def _reachable_support(p, old, request_fields, membership):
    dependencies = set()
    for rule in p['rules']:
        viable = True
        for atom in rule['guard']:
            if 'alias' in atom:
                continue
            field = atom['field']
            if field == 'state':
                truth = old[atom['name']] == atom['value']
            else:
                truth = ((request_fields['principal'], atom['name']) in membership
                         if field == 'role' else request_fields[field] == atom['name'])
                truth = truth != atom['negated']
            viable = viable and truth
        if viable:
            dependencies.update(atom['alias'] for atom in rule['guard'] if 'alias' in atom)
    return sorted(dependencies)

def verify_reachable(p, m, budget=2_000_000, work_budget=2_000_000, details=False,
                     reuse_observations=False):
    """Verify and diagnose by FIFO BFS, without a producer-supplied state list.

    Same full-state/Cartesian criterion as verify with the exact reachable region.
    Store one predecessor per discovered target state; reconstruct only a failed
    path. Invalid data and exhausted caps raise Rejected; completed comparisons
    return accepted/equivalent plus a shortest fixed-binding witness if negative.
    The legacy budget remains a binding-evaluation cap. work_budget additionally
    bounds declared preparation, traversal, support, evaluation and replay work.
    Optional reuse stores only universally checked source-cell outputs within
    this invocation. Every target edge is still compared and traversed. The
    binding cap counts the same logical obligations; physical calls are separate.
    """
    ensure(integer(budget) and budget >= 0, 'checker obligation budget', 'inconclusive')
    ensure(type(details) is bool, 'reachable details flag')
    ensure(type(reuse_observations) is bool, 'reachable reuse flag')
    work = _ReachableWork(work_budget)
    aliases = inspect_policy(p)
    inspect_machine(p, m, compare_initial=False)
    first = m['initial']
    start = sum(2 ** i for i, (_, value) in enumerate(p['state']) if value)
    count = maximum_width = cells_checked = 0
    parents = {first: None}
    cells = [] if details else None
    proved_cells = {} if reuse_observations else None
    physical_evaluations = reuse_hits = 0

    def result(accepted, **witness):
        report = {'accepted': accepted, 'equivalent': accepted,
                  'status': 'equivalent' if accepted else 'mismatch',
                  'states_discovered': len(parents), 'local_cells': cells_checked,
                  'binding_evaluations': count, 'maximum_width': maximum_width,
                  'work_operations': work.total, 'work_budget': work.limit,
                  'work_breakdown': dict(sorted(work.parts.items())), **witness}
        if details:
            report['cells'] = cells
        if reuse_observations:
            report.update(physical_binding_evaluations=physical_evaluations,
                          reused_cells=reuse_hits, reuse_entries=len(proved_cells))
        return report

    if m['observations'][first] != start:
        return result(False, length=0, indices=[], trace=[],
                      binding={name: a['candidates'][0] for name, a in aliases.items()},
                      reason='initial observation')
    work.charge(1 + len(p['members']) + len(aliases), 'invocation_preparation')
    membership = frozenset(tuple(pair) for pair in p['members'])
    filler = {name: a['candidates'][0] for name, a in aliases.items()}
    support_nodes = sum(1 + len(r['guard']) for r in p['rules'])
    semantic_nodes = sum(1 + len(r['guard']) + len(r['updates']) for r in p['rules'])
    queue = deque([first])
    while queue:
        q = queue.popleft()
        state = m['observations'][q]
        work.charge(1 + len(p['state']), 'state_preparation')
        old = {name: bool((state >> i) & 1) for i, (name, _) in enumerate(p['state'])}
        for index, request in enumerate(m['alphabet']):
            cached = None
            if reuse_observations:
                work.charge(1, 'reuse_lookup')
                cached = proved_cells.get((state, index))
            if cached is None:
                work.charge(4 + 2 * support_nodes, 'cell_support')
                request_fields = dict(zip(('principal', 'resource', 'action'), request))
                deps = _reachable_support(p, old, request_fields, membership)
            else:
                deps = cached[1]
                reuse_hits += 1
            maximum_width = max(maximum_width, len(deps))
            cases = 1
            for name in deps:
                cases *= len(aliases[name]['candidates'])
            ensure(count + cases <= budget, 'checker obligation budget', 'inconclusive')
            decision, successor = m['transitions'][q][index]
            expected = (decision, m['observations'][successor])
            cells_checked += 1
            # A stored output was checked for every admitted binding at this
            # complete observation/request, not just a producer-selected binding.
            # A different target output still fails at this exact BFS cell.
            values_to_check = (() if cached is not None and cached[0] == expected else
                               product(*(aliases[name]['candidates'] for name in deps)))
            if cached is not None and cached[0] == expected:
                count += cases
            for values in values_to_check:
                if cached is None:
                    work.charge(1 + len(aliases) + len(deps) + semantic_nodes + len(p['state']),
                                'binding_semantics')
                else:
                    work.charge(1 + len(aliases) + len(deps), 'reuse_witness_binding')
                binding = dict(filler)
                binding.update(zip(deps, values))
                count += 1
                if cached is None:
                    physical_evaluations += 1
                    actual = _reference_step_prepared(p, state, request, binding, old, membership, request_fields)
                else:
                    actual = cached[0]
                if actual != expected:
                    prefix = []
                    cursor = q
                    while parents[cursor] is not None:
                        work.charge(1, 'path_reconstruction')
                        cursor, edge_index = parents[cursor]
                        prefix.append(edge_index)
                    indices = list(reversed(prefix)) + [index]
                    source, target, trace = start, first, []
                    for edge_index in indices:
                        work.charge(1 + len(p['members']) + 2 * len(p['state']) + semantic_nodes,
                                    'witness_replay')
                        d, post = reference_step(p, source, m['alphabet'][edge_index], binding)
                        md, target = m['transitions'][target][edge_index]
                        trace.append({'request': m['alphabet'][edge_index], 'source': [d, post],
                                      'target': [md, m['observations'][target]]})
                        source = post
                    ensure(all(row['source'] == row['target'] for row in trace[:-1])
                           and trace[-1]['source'] != trace[-1]['target'], 'reachable replay invariant')
                    return result(False, length=len(indices), indices=indices, binding=binding, trace=trace)
            if reuse_observations and cached is None:
                work.charge(1 + len(deps), 'reuse_storage')
                proved_cells[(state, index)] = (expected, deps)
            if details:
                work.charge(1 + len(deps), 'cell_reporting')
                cells.append({'state': q, 'request': index, 'support': deps, 'bindings': cases})
            work.charge(1, 'graph_edges')
            if successor not in parents:
                parents[successor] = (q, index)
                queue.append(successor)
    return result(True, length=None)

def load(path):
    bound = 32 * 1024 * 1024
    with Path(path).open('rb') as stream:
        raw = stream.read(bound + 1)
    ensure(len(raw) <= bound, 'input byte envelope', 'inconclusive')
    text = raw.decode('utf-8')
    def object_pairs(pairs):
        obj = {}
        for key, value in pairs:
            ensure(key not in obj, 'duplicate JSON key')
            obj[key] = value
        return obj
    def reject_constant(value):
        raise Rejected('nonfinite JSON constant')
    return json.loads(text, object_pairs_hook=object_pairs, parse_constant=reject_constant)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Check finite full-state refinement; a closed-state certificate is optional.')
    parser.add_argument('policy'); parser.add_argument('machine'); parser.add_argument('certificate', nargs='?')
    parser.add_argument('--work-budget', type=int, default=2_000_000,
                        help='declared work cap for list-free mode (legacy certificate mode counts only binding evaluations)')
    parser.add_argument('--reuse-observations', action='store_true',
                        help='list-free only: reuse universally checked cells within this invocation')
    args = parser.parse_args()
    try:
        if args.certificate is None:
            result = verify_reachable(load(args.policy), load(args.machine), work_budget=args.work_budget,
                                      reuse_observations=args.reuse_observations)
        else:
            ensure(not args.reuse_observations, 'reuse requires list-free mode')
            result = verify(load(args.policy), load(args.machine), load(args.certificate))
            result.pop('cells')
        print(json.dumps(result, indent=2))
        if not result['accepted']:
            raise SystemExit(1)
    except (Rejected, ValueError, TypeError, KeyError, OverflowError, RecursionError, OSError) as error:
        kind = error.kind if isinstance(error, Rejected) else 'invalid'
        print(json.dumps({'accepted': None if kind == 'inconclusive' else False, 'status': kind, 'reason': str(error)}))
        raise SystemExit(2 if kind == 'inconclusive' else 1)
