"""Portable same-information BFS comparison and finite semantic diversity audit.

No native policy engine, network, or Linux resource module. The ordinary BFS uses
the same full observations, local support and reference evaluator as the region
checker: it isolates the cost/necessity of the state list, not semantic independence.
Retained historical records are read for comparison and never overwritten.
"""
from __future__ import annotations
import argparse
from collections import Counter, deque
from itertools import product
import json
from pathlib import Path
import platform
import statistics
import time

import checker
from cases import primary, width_case
from compiler import alphabet, certificate, compile_policy, diagnose, step
from language import initial, pretty
from oracle import all_bindings, product_oracle
from public_inputs import MODELS, model_oracle, projected_oracle, read_inputs, translate

ROOT = Path(__file__).resolve().parents[1]

def ordinary_bfs(p, m):
    """Straight FIFO target BFS, no certificate, no producer reachability call."""
    aliases = checker.inspect_policy(p)
    checker.inspect_machine(p, m, compare_initial=False)
    filler = {name: a['candidates'][0] for name, a in aliases.items()}
    if initial(p) != m['observations'][m['initial']]:
        return {'equivalent': False, 'length': 0, 'binding_evaluations': 0}
    paths = {m['initial']: []}
    waiting = deque([m['initial']])
    evaluations = 0
    while waiting:
        q = waiting.popleft()
        for index, request in enumerate(m['alphabet']):
            dependencies = checker.support(p, m['observations'][q], request)
            for values in product(*(aliases[name]['candidates'] for name in dependencies)):
                binding = dict(filler)
                binding.update(zip(dependencies, values))
                evaluations += 1
                actual = checker.reference_step(p, m['observations'][q], request, binding)
                decision, successor = m['transitions'][q][index]
                if actual != (decision, m['observations'][successor]):
                    return {'equivalent': False, 'length': len(paths[q]) + 1,
                            'binding_evaluations': evaluations}
            successor = m['transitions'][q][index][1]
            if successor not in paths:
                paths[successor] = paths[q] + [index]
                waiting.append(successor)
    return {'equivalent': True, 'length': None, 'binding_evaluations': evaluations}

def region_result(p, m, c):
    try:
        answer = checker.verify(p, m, c)
        return {'equivalent': True, 'binding_evaluations': answer['binding_evaluations']}
    except checker.Rejected as error:
        if error.kind != 'mismatch':
            raise
        return {'equivalent': False, 'binding_evaluations': getattr(error, 'evaluations', 0)}

def semantic_signature(p):
    """Exact named initialized one-step table, including every admitted binding.

    Includes source state names, request domain and alias names/sorts/candidates.
    Excludes irrelevant role declarations/membership once their effects are in
    the table. Unreachable valuations remain included: this is not trace-language
    minimization. Compare compiler and reference outputs on every table tuple.
    """
    outputs = []
    comparisons = 0
    for binding in all_bindings(p):
        table = []
        for state in range(1 << len(p['state'])):
            for request in alphabet(p):
                actual = step(p, state, request, binding)
                expected = checker.reference_step(p, state, request, binding)
                if actual != expected:
                    raise RuntimeError('diversity source-step disagreement')
                table.append(actual)
                comparisons += 1
        outputs.append(tuple(table))
    signature = (tuple(name for name, _ in p['state']), initial(p),
                 tuple(tuple(x) for x in alphabet(p)),
                 tuple((a['name'], a['kind'], tuple(a['candidates'])) for a in p['aliases']),
                 tuple(outputs))
    return signature, comparisons

def public_boundary():
    requests = 0
    inputs = ROOT / 'external_inputs/casbin'
    for name in MODELS:
        rows = read_inputs(inputs, name)
        p = translate(name, rows)
        for request in alphabet(p):
            if checker.reference_step(p, 0, request, {})[0] != projected_oracle(name, rows, request):
                raise RuntimeError('public finite interpretation mismatch')
            requests += 1
    assertions = json.loads((inputs / 'assertions.json').read_text(encoding='utf-8'))
    for record in assertions:
        if (model_oracle(record['model'], read_inputs(inputs, record['model']), record['request']) == 'allow') != record['allow']:
            raise RuntimeError('public retained assertion mismatch')
    return {'finite_requests': requests, 'retained_assertions': len(assertions),
            'native_engine_executed': False, 'all_agree': True}

def timed_cohort(cohort, repeats):
    methods = ('region_with_production', 'ordinary_bfs', 'reachable_compact', 'reachable_detailed')
    samples = {method: [] for method in methods}
    for repeat in range(repeats):
        # Rotate execution order to reduce a fixed-order warm-up bias.
        order = methods[repeat % len(methods):] + methods[:repeat % len(methods)]
        for method in order:
            start = time.perf_counter()
            for p, m in cohort:
                if method == 'region_with_production':
                    region_result(p, m, certificate(m))
                elif method == 'ordinary_bfs':
                    ordinary_bfs(p, m)
                else:
                    checker.verify_reachable(p, m, details=method == 'reachable_detailed')
            samples[method].append(time.perf_counter() - start)
    return {method: {'seconds': values, 'median_seconds': statistics.median(values)}
            for method, values in samples.items()}

def run(output, repeats=5):
    begin = time.perf_counter()
    records = []
    generated_signatures, texts = Counter(), Counter()
    source_steps = 0
    totals = Counter()
    for index in range(10000):
        spec = primary(index, ROOT / 'external_inputs/casbin')
        if spec['kind'] == 'schema-negative':
            records.append({'case': f'case-{index:05d}', 'scope': 'legacy invalid-evidence branch retained'})
            continue
        p = spec['policy']
        m = spec.get('machine') or compile_policy(p)
        # Enumerating every width-family binding would repeat the omitted large
        # product workload. Audit diversity in the generated cohort separately;
        # do not invent semantic signatures for the eight unenumerated widths.
        if spec['kind'] == 'generated':
            signature, comparisons = semantic_signature(p)
            source_steps += comparisons
            generated_signatures[signature] += 1
            texts[pretty(p)] += 1
        legacy = region_result(p, m, certificate(m))
        baseline = ordinary_bfs(p, m)
        repaired = checker.verify_reachable(p, m)
        diagnostic = diagnose(p, m)
        expected = (diagnostic['equivalent'], diagnostic.get('length'))
        if (baseline['equivalent'], baseline['length']) != expected or (repaired['equivalent'], repaired['length']) != expected:
            raise RuntimeError(f'BFS verdict/shortest length disagreement: {index}')
        if legacy['equivalent'] != repaired['equivalent'] or legacy['binding_evaluations'] != repaired['binding_evaluations'] or baseline['binding_evaluations'] != repaired['binding_evaluations']:
            raise RuntimeError(f'BFS semantic evaluation count disagreement: {index}')
        product_run = spec['kind'] != 'width' or spec['aliases'] <= 8
        if product_run:
            product = product_oracle(p, m)
            actual = (product['equivalent'], None if product['equivalent'] else product['shortest']['length'])
            if actual != expected:
                raise RuntimeError(f'product disagreement: {index}')
            totals['product_cases'] += 1
        totals['completed_cases'] += 1
        totals['equivalent'] += repaired['equivalent']
        totals['binding_evaluations_per_method'] += repaired['binding_evaluations']
        totals['reachable_charged_work'] += repaired['work_operations']
        records.append({'case': f'case-{index:05d}', 'equivalent': repaired['equivalent'],
                        'length': repaired['length'], 'binding_evaluations_each': repaired['binding_evaluations'],
                        'reachable_work': repaired['work_operations'], 'product_executed': product_run})
    examples = []
    cohort = []
    for folder in sorted((ROOT / 'results/examples').iterdir()):
        if not folder.is_dir():
            continue
        p = checker.load(folder / 'policy.json')
        m = checker.load(folder / 'automaton.json')
        legacy = region_result(p, m, checker.load(folder / 'certificate.json'))
        baseline = ordinary_bfs(p, m)
        repaired = checker.verify_reachable(p, m)
        stored = checker.load(folder / 'diagnostic.json')
        if not (legacy['equivalent'] == baseline['equivalent'] == repaired['equivalent'] == stored['equivalent']):
            raise RuntimeError('retained example verdict disagreement')
        if baseline['length'] != stored.get('length') or repaired['length'] != stored.get('length'):
            raise RuntimeError('retained example shortest length disagreement')
        examples.append({'example': folder.name, 'equivalent': repaired['equivalent'], 'length': repaired['length']})
        cohort.append((p, m))
    widths = []
    for count in range(1, 17):
        p = width_case(count)
        m = compile_policy(p)
        c = certificate(m)
        compact = checker.verify_reachable(p, m)
        detailed = checker.verify_reachable(p, m, details=True)
        widths.append({'aliases': count, 'evaluations_each_bfs': compact['binding_evaluations'],
                       'compact_charged_work': compact['work_operations'],
                       'detailed_charged_work': detailed['work_operations'],
                       'certificate_bytes_utf8': len(json.dumps(c, separators=(',', ':')).encode()),
                       'legacy_report_bytes_utf8': len(json.dumps(checker.verify(p, m, c)).encode()),
                       'compact_report_bytes_utf8': len(json.dumps(compact).encode()),
                       'detailed_report_bytes_utf8': len(json.dumps(detailed).encode())})
    report = {'status': 'pass', 'platform': platform.platform(), 'python': platform.python_version(),
              'totals': dict(totals), 'negative_evidence_records_retained': 15,
              'examples': examples, 'public': public_boundary(),
              'diversity': {'definition': semantic_signature.__doc__,
                            'scope': 'All 9,936 generated policies, not malformed records or the separate width/public/chain families.',
                            'generated_records': sum(generated_signatures.values()),
                            'generated_distinct_initialized_one_step_tables': len(generated_signatures),
                            'generated_distinct_canonical_asts': len(texts),
                            'generated_max_semantic_multiplicity': max(generated_signatures.values()),
                            'compiler_reference_step_comparisons': source_steps},
              'width': widths, 'timing_49_examples': timed_cohort(cohort, repeats),
              'timing_scope': 'Local in-process wall samples, both validators included; region producer included only in region_with_production; no compiler, file I/O, native engine, RSS or historical campaign timings. Output contracts differ: ordinary BFS returns a verdict and length but no replayed witness; list-free negatives include replay; the legacy checker creates cell reports; detailed mode adds cell reports to list-free checking. These samples do not isolate traversal speed.',
              'records': records, 'wall_seconds': time.perf_counter() - begin}
    output = Path(output)
    if output.exists():
        raise FileExistsError('choose a new comparison output')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in report.items() if k not in ('records', 'examples', 'width')}, indent=2))
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20:
        parser.error('repeats must be in 1..20')
    run(args.output, args.repeats)
