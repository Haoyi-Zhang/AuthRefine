"""Exact small oracles for the stated reductions and observation hypotheses."""
from __future__ import annotations
import argparse
import copy
import itertools
import json
import resource
import time
from pathlib import Path
from cases import blank
from language import normalize, initial
from compiler import compile_policy, certificate, diagnose, decompile
from checker import verify, Rejected, reference_step
from oracle import product_oracle


def rule(decision, guard, updates=()):
    return {'decision': decision, 'guard': list(guard), 'updates': list(updates)}


def cnf_policy(clauses, variables=2):
    """Allow iff some CNF clause is false under the fixed role binding."""
    p = blank(); p['principals'] = ['u']; p['resources'] = ['o']; p['actions'] = ['a']
    p['roles'] = ['false', 'true']; p['members'] = [['u', 'true']]
    p['aliases'] = [{'name': 'x' + str(i), 'kind': 'role', 'candidates': ['false', 'true']}
                    for i in range(variables)]
    for clause in clauses:
        # Positive literal is false when membership is false; a negative literal
        # is false when membership is true. Clause conjunction is falsity.
        guard = [{'field': 'role', 'alias': 'x' + str(i), 'negated': positive}
                 for i, positive in clause]
        p['rules'].append(rule('allow', guard))
    return normalize(p)


def formula_satisfiable(clauses, variables=2):
    return any(all(any(values[i] == positive for i, positive in clause) for clause in clauses)
               for values in itertools.product((False, True), repeat=variables))


def cnf_family():
    clauses = []
    for signs in itertools.product((-1, 0, 1), repeat=2):
        if signs == (0, 0):
            continue
        clauses.append([(i, sign > 0) for i, sign in enumerate(signs) if sign])
    formulas = [[clause for i, clause in enumerate(clauses) if (mask >> i) & 1] for mask in range(256)]
    formulas.append([[]])
    records = []; obligations = 0
    for index, formula in enumerate(formulas):
        p = cnf_policy(formula)
        m = compile_policy(p); m['transitions'] = [[['allow', 0]]]
        try:
            result = verify(p, m, certificate(m)); accepted = True; checks = result['binding_evaluations']
        except Rejected as error:
            if error.kind != 'mismatch':
                raise
            accepted = False; checks = error.evaluations
        satisfiable = formula_satisfiable(formula)
        if accepted == satisfiable:
            raise RuntimeError('CNF reduction disagreement')
        diag = diagnose(p, m)
        if diag['equivalent'] != accepted or (not accepted and diag['length'] != 1):
            raise RuntimeError('CNF witness disagreement')
        records.append({'formula': index, 'clauses': formula, 'satisfiable': satisfiable, 'uniform': accepted,
                        'local_evaluations': checks})
        # Four truth assignments, direct clause/literal decisions, plus checker/producer evaluations.
        obligations += 4 * (1 + sum(1 + len(c) for c in formula)) + checks + diag['local_evaluations']
    return {'count': len(records), 'satisfiable': sum(r['satisfiable'] for r in records),
            'unsatisfiable': sum(not r['satisfiable'] for r in records), 'records': records, 'obligations': obligations}


def source_table(choices, start):
    p = blank(); p['principals'] = ['u']; p['resources'] = ['o']; p['actions'] = ['a']
    p['state'] = [['b', bool(start)]]
    for state, choice in enumerate(choices):
        if choice:
            p['rules'].append(rule('allow', [{'field': 'state', 'name': 'b', 'value': bool(state)}],
                                   [{'name': 'b', 'value': choice == 2}]))
    return normalize(p)


def machine_family():
    rows = []; obligations = 0
    # 3 choices per source state: deny/stutter, allow/false, allow/true.
    edge_choices = list(itertools.product(('allow', 'deny'), range(2)))
    for choices in itertools.product(range(3), repeat=2):
        for start in range(2):
            p = source_table(choices, start)
            for observations in itertools.product(range(2), repeat=2):
                for edges in itertools.product(edge_choices, repeat=2):
                    for mstart in range(2):
                        m = {'state_names': ['b'], 'alphabet': [['u', 'o', 'a']],
                             'observations': list(observations), 'initial': mstart,
                             'transitions': [[list(edge)] for edge in edges]}
                        same_initial = observations[mstart] == start
                        try:
                            checked = verify(p, m, certificate(m)); accepted = True
                            checks = checked['binding_evaluations']
                        except Rejected as error:
                            if error.kind != 'mismatch':
                                raise
                            accepted = False; checks = getattr(error, 'evaluations', 0)
                        oracle = product_oracle(p, m)
                        if accepted != oracle['equivalent']:
                            raise RuntimeError('exhaustive machine comparison disagrees')
                        length = None if accepted else oracle['shortest']['length']
                        if not same_initial and length != 0:
                            raise RuntimeError('initial-observation mismatch must have an empty witness')
                        if same_initial:
                            diag = diagnose(p, m)
                            if diag['equivalent'] != accepted or (not accepted and diag['length'] != length):
                                raise RuntimeError('exhaustive shortest witness disagrees')
                            obligations += diag['local_evaluations']
                            if not accepted and length > len(certificate(m)['reachable']):
                                raise RuntimeError('short-witness bound violated')
                        rows.append({'source': list(choices), 'source_initial': start, 'observations': list(observations),
                                     'edges': [list(e) for e in edges], 'target_initial': mstart,
                                     'uniform': accepted, 'witness_length': length})
                        obligations += checks + oracle['transition_evaluations'] + 2
    return {'count': len(rows), 'equivalent': sum(r['uniform'] for r in rows),
            'initial_mismatches': sum(r['witness_length'] == 0 for r in rows),
            'noninjective_observation_pairs': sum(len(set(r['observations'])) == 1 for r in rows),
            'records': rows, 'obligations': obligations}


def alias_family():
    records = []; obligations = 0
    for choices in itertools.product(range(4), repeat=4):
        for start in range(2):
            p = blank(); p['principals'] = ['u']; p['resources'] = ['o']; p['actions'] = ['a']
            p['roles'] = ['r', 's']; p['members'] = [['u', 'r']]; p['state'] = [['b', bool(start)]]
            p['aliases'] = [{'name': 'x', 'kind': 'role', 'candidates': ['r', 's']}]
            for index, choice in enumerate(choices):
                if choice == 0:
                    continue
                state, alias_true = divmod(index, 2)
                guard = [{'field': 'state', 'name': 'b', 'value': bool(state)},
                         {'field': 'role', 'alias': 'x', 'negated': not bool(alias_true)}]
                updates = [] if choice == 1 else [{'name': 'b', 'value': choice == 3}]
                p['rules'].append(rule('deny' if choice == 1 else 'allow', guard, updates))
            p = normalize(p); m = compile_policy(p)
            try:
                checked = verify(p, m, certificate(m)); accepted = True; checks = checked['binding_evaluations']
            except Rejected as error:
                if error.kind != 'mismatch': raise
                accepted = False; checks = error.evaluations
            diag = diagnose(p, m); oracle = product_oracle(p, m)
            if accepted != oracle['equivalent'] or accepted != diag['equivalent']:
                raise RuntimeError('one-alias exhaustive verdict disagreement')
            length = None if accepted else diag['length']
            if not accepted and oracle['shortest']['length'] != length:
                raise RuntimeError('one-alias exhaustive shortest witness disagreement')
            records.append({'choices': list(choices), 'initial': start, 'uniform': accepted, 'witness_length': length})
            obligations += checks + diag['local_evaluations'] + oracle['transition_evaluations'] + 2
    return {'count': len(records), 'uniform': sum(r['uniform'] for r in records),
            'records': records, 'obligations': obligations}



def relevance_family():
    clauses = []
    for signs in itertools.product((-1, 0, 1), repeat=2):
        if signs != (0, 0):
            clauses.append([(i, sign > 0) for i, sign in enumerate(signs) if sign])
    formulas = [[clause for i, clause in enumerate(clauses) if (mask >> i) & 1] for mask in range(256)] + [[[]]]
    records = []; obligations = 0
    for index, formula in enumerate(formulas):
        p = cnf_policy(formula)
        for r in p['rules']:
            r['decision'] = 'deny'
        p['aliases'].append({'name': 'z', 'kind': 'role', 'candidates': ['false', 'true']})
        p['rules'].append(rule('allow', [{'field': 'role', 'alias': 'z', 'negated': False}]))
        p = normalize(p)
        essential = False; table = []
        for values in itertools.product((False, True), repeat=2):
            outputs = []
            for z in (False, True):
                binding = {'x' + str(i): 'true' if v else 'false' for i, v in enumerate(values)}
                binding['z'] = 'true' if z else 'false'
                out = reference_step(p, 0, ['u', 'o', 'a'], binding)[0]
                expected = 'allow' if z and all(any(values[i] == positive for i, positive in c) for c in formula) else 'deny'
                if out != expected:
                    raise RuntimeError('relevance reduction denotation mismatch')
                outputs.append(out)
                table.append({'variables': list(values), 'control': z, 'decision': out})
            essential |= outputs[0] != outputs[1]
        sat = formula_satisfiable(formula)
        if essential != sat:
            raise RuntimeError('semantic relevance reduction disagreement')
        records.append({'formula': index, 'essential': essential, 'satisfiable': sat, 'table': table})
        obligations += 8 * (2 + sum(1 + len(c) for c in formula)) + 4
    return {'count': len(records), 'essential': sum(r['essential'] for r in records),
            'records': records, 'obligations': obligations}

def run(destination):
    begin = time.process_time(); wall = time.perf_counter()
    report = {'cnf': cnf_family(), 'machines': machine_family(), 'aliases': alias_family(), 'relevance': relevance_family()}
    report['count'] = sum(report[name]['count'] for name in ('cnf', 'machines', 'aliases', 'relevance'))
    report['obligations'] = sum(report[name]['obligations'] for name in ('cnf', 'machines', 'aliases', 'relevance'))
    report['cpu_seconds'] = time.process_time() - begin
    report['wall_seconds'] = time.perf_counter() - wall
    report['peak_rss_kib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    path = Path(destination); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key not in ('cnf', 'machines', 'aliases', 'relevance')}, indent=2))
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', required=True)
    run(parser.parse_args().output)
