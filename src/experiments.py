"""Bounded deterministic evidence runs. No network or external service is used."""
from __future__ import annotations
import argparse
import copy
import json
import resource
import tempfile
import time
from pathlib import Path
from language import parse, pretty, normalize, initial, PolicyError
from compiler import compile_policy, certificate, default_binding, diagnose, reachable, decompile
from checker import verify, Rejected, reference_step, load
from oracle import product_oracle, exhaustive_words
from symbolic import check as symbolic_check
from compiler import replay as producer_replay
from cases import primary, curated, generated
from public_inputs import MODELS, read_inputs, translate, extend, projected_oracle, model_oracle, request_embedding

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / 'external_inputs/casbin'

def write_json(path, data):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')

def check_trace(p, m, diagnosis):
    state = initial(p); q = m['initial']; first_failure = None
    rows = []
    for depth, index in enumerate(diagnosis['indices'], 1):
        request = m['alphabet'][index]
        d, state = reference_step(p, state, request, diagnosis['binding'])
        md, q = m['transitions'][q][index]
        row = {'request': request, 'source': [d, state], 'target': [md, m['observations'][q]]}
        rows.append(row)
        if row['source'] != row['target']:
            first_failure = depth; break
    if first_failure != diagnosis['length'] or rows != diagnosis['trace']:
        raise RuntimeError('independent witness replay mismatch')
    return len(rows)

def analyze(spec, case_id, example_directory=None, auxiliary_mutation=False):
    start_cpu = time.process_time(); start_wall = time.perf_counter()
    p = spec['policy']
    info = {key: value for key, value in spec.items() if key not in ('policy', 'machine', 'certificate')}
    result = {'case': case_id, **info}
    if spec['kind'] == 'schema-negative':
        try:
            c = spec['certificate']
            if isinstance(c, str):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'certificate.json'; path.write_text(c)
                    c = load(path)
            verify(p, spec['machine'], c)
        except (Rejected, ValueError, TypeError, KeyError, OverflowError, RecursionError) as error:
            result.update({'accepted': False, 'rejection': str(error), 'expected_rejection': True, 'obligations': 1})
        else:
            raise RuntimeError('malformed certificate accepted: ' + spec['fault'])
    else:
        text = pretty(p); recovered = parse(text)
        if recovered != p or pretty(recovered) != text:
            raise RuntimeError('canonical round-trip mismatch')
        compiled = compile_policy(p)
        fixed_steps = 0
        for q, state in enumerate(compiled['observations']):
            for i, request in enumerate(compiled['alphabet']):
                d, nq = compiled['transitions'][q][i]
                if (d, compiled['observations'][nq]) != reference_step(p, state, request, default_binding(p)):
                    raise RuntimeError('compiler/reference disagreement')
                fixed_steps += 1
        machine = spec.get('machine', compiled); cert = certificate(machine)
        diagnostic = diagnose(p, machine)
        try:
            checked = verify(p, machine, cert)
            checker_accepted = True; checker_steps = checked['binding_evaluations']
            max_width = checked['maximum_width']; rejection = None
        except Rejected as error:
            if error.kind != 'mismatch':
                raise
            checker_accepted = False; checker_steps = getattr(error, 'evaluations', 0)
            max_width = getattr(error, 'maximum_width', diagnostic['maximum_width']); rejection = str(error)
        if checker_accepted != diagnostic['equivalent']:
            raise RuntimeError('producer/checker verdict disagreement')
        run_global = spec['kind'] != 'width' or spec['aliases'] <= 8
        oracle = product_oracle(p, machine) if run_global else None
        if oracle is not None and oracle['equivalent'] != checker_accepted:
            raise RuntimeError('checker/product verdict disagreement')
        replay_steps = 0
        if not checker_accepted:
            replay_steps = check_trace(p, machine, diagnostic)
            if oracle is not None and diagnostic['length'] != oracle['shortest']['length']:
                raise RuntimeError('shortest uniform witness disagreement')
        if spec['kind'] == 'chain' and diagnostic['length'] != spec['expected_length']:
            raise RuntimeError('chain witness did not meet tight bound')
        symbolic_start = time.process_time()
        symbolic = symbolic_check(p, machine)
        symbolic['cpu_seconds'] = time.process_time() - symbolic_start
        if symbolic['equivalent'] != checker_accepted:
            raise RuntimeError('symbolic/checker disagreement')
        symbolic_replay = 0
        if not symbolic['equivalent']:
            if symbolic['length'] != diagnostic['length']:
                raise RuntimeError('symbolic minimum witness disagreement')
            symbolic['trace'] = producer_replay(p, machine, symbolic['indices'], symbolic['binding'])
            symbolic_replay = check_trace(p, machine, symbolic)
        result['symbolic'] = symbolic
        word_oracle = None
        if spec['kind'] == 'chain' and spec['expected_length'] <= 8:
            word_oracle = exhaustive_words(p, machine, maximum_depth=8)
            if word_oracle['length'] != spec['expected_length']:
                raise RuntimeError('word enumeration minimum disagrees')
        bindings = 1
        for a in p['aliases']: bindings *= len(a['candidates'])
        reached = len(cert['reachable']); ninputs = len(machine['alphabet'])
        result.update({'accepted': checker_accepted, 'syntax_unique': bindings == 1, 'total_bindings': bindings,
                       'state_variables': len(p['state']), 'machine_states': len(machine['observations']), 'reachable_states': reached,
                       'requests': ninputs, 'rules': len(p['rules']),
                       'ast_nodes': sum(1 + len(r['guard']) + len(r['updates']) for r in p['rules']),
                       'roundtrip': True, 'fixed_binding_transitions': fixed_steps,
                       'local_binding_evaluations': checker_steps, 'diagnostic_evaluations': diagnostic['local_evaluations'],
                       'maximum_width': max_width, 'global_evaluations': oracle['transition_evaluations'] if oracle else None,
                       'global_bindings_examined': oracle['bindings_examined'] if oracle else None,
                       'global_complete_work_bound': reached * ninputs * bindings,
                       'global_oracle_executed': run_global,
                       'witness_length': diagnostic.get('length'), 'replay_steps': replay_steps,
                       'word_enumeration_evaluations': word_oracle['evaluations'] if word_oracle else 0})
        # Count parser/round-trip, compilation, direct comparison, local checking,
        # closure/schema transitions, diagnostic steps, product and replay obligations.
        result['obligations'] = (2 + 2 * fixed_steps + 2 * reached * ninputs + checker_steps + diagnostic['local_evaluations']
                                 + (oracle['transition_evaluations'] if oracle else 0) + 2 * replay_steps
                                 + (word_oracle['evaluations'] if word_oracle else 0) + symbolic['operations'] + 2 * symbolic_replay)
        if rejection:
            result['rejection'] = rejection
            result['witness'] = {'binding': diagnostic['binding'], 'indices': diagnostic['indices'], 'trace': diagnostic['trace']}
        if auxiliary_mutation and checker_accepted:
            mutant = copy.deepcopy(machine)
            q = cert['reachable'][-1]; index = len(mutant['alphabet']) - 1
            mutant['transitions'][q][index][0] = 'deny' if mutant['transitions'][q][index][0] == 'allow' else 'allow'
            try:
                verify(p, mutant, certificate(mutant))
            except Rejected as error:
                if error.kind != 'mismatch':
                    raise
                mutation_steps = getattr(error, 'evaluations', 0)
            else:
                raise RuntimeError('reachable decision mutation accepted')
            md = diagnose(p, mutant)
            replay_count = check_trace(p, mutant, md)
            mo = product_oracle(p, mutant)
            if mo['equivalent'] or mo['shortest']['length'] != md['length']:
                raise RuntimeError('mutation oracle disagreement')
            result['mutation'] = {'detected': True, 'witness_length': md['length'], 'checker_evaluations': mutation_steps,
                                  'diagnostic_evaluations': md['local_evaluations'], 'global_evaluations': mo['transition_evaluations']}
            result['obligations'] += mutation_steps + md['local_evaluations'] + mo['transition_evaluations'] + 2 * replay_count + 2 * reached * ninputs
        if spec['kind'] in ('public', 'width') or (spec['kind'] == 'generated' and spec['generator_index'] < 32):
            try:
                reified = decompile(machine, p)
            except PolicyError as error:
                if error.category != 'LIMIT': raise
                result['reification'] = 'outside AST cap'
            else:
                if parse(pretty(reified)) != reified:
                    raise RuntimeError('reified syntax round-trip')
                ro = product_oracle(reified, machine)
                if not ro['equivalent']:
                    raise RuntimeError('semantic reification disagreement')
                result['reification'] = 'checked'
                result['obligations'] += 2 + ro['transition_evaluations']
        if example_directory is not None:
            folder = Path(example_directory) / case_id
            write_json(folder / 'policy.json', p); (folder / 'policy.cnl').write_text(text, encoding='utf-8')
            write_json(folder / 'automaton.json', machine); write_json(folder / 'certificate.json', cert)
            write_json(folder / 'diagnostic.json', diagnostic)
    result['cpu_seconds'] = time.process_time() - start_cpu
    result['wall_seconds'] = time.perf_counter() - start_wall
    return result

def public_checks():
    records = []; count = 0
    for name in MODELS:
        rows = read_inputs(INPUTS, name); p = translate(name, rows); m = compile_policy(p)
        for request in m['alphabet']:
            actual = reference_step(p, 0, request, {})[0]
            expected = projected_oracle(name, rows, request)
            if actual != expected:
                raise RuntimeError('finite public adapter mismatch')
            count += 1
        records.append({'model': name, 'requests': len(m['alphabet']), 'matched': True, 'rules': len(p['rules']),
                        'principals': len(p['principals']), 'resources': len(p['resources']), 'actions': len(p['actions']),
                        'roles': len(p['roles'])})
    assertions = json.loads((INPUTS / 'assertions.json').read_text())
    for assertion in assertions:
        name = assertion['model']; rows = read_inputs(INPUTS, name); p = translate(name, rows)
        source = model_oracle(name, rows, assertion['request'])
        compiled = reference_step(p, 0, request_embedding(name, assertion['request']), {})[0]
        if (source == 'allow') != assertion['allow'] or source != compiled:
            raise RuntimeError('frozen original assertion mismatch')
    return {'models': records, 'projected_requests': count, 'original_assertions': len(assertions),
            'all_agree': True, 'obligations': count * 2 + len(assertions) * 2}

def controls(example_directory):
    records = []
    for i, (name, p) in enumerate(curated()):
        records.append(analyze({'kind': 'curated', 'name': name, 'policy': p}, 'control-' + str(i), example_directory))
    # Decision-only ablation: all local decisions at the supplied observation agree,
    # but a fixed source run changes its hidden state and disagrees on request two.
    p = dict(curated())['one-use-state']
    m = {'state_names': ['used'], 'alphabet': [['u', 'o', 'a']], 'observations': [0], 'initial': 0, 'transitions': [[['allow', 0]]]}
    weak_local = all(reference_step(p, m['observations'][q], req, {})[0] == m['transitions'][q][i][0]
                     for q in range(len(m['observations'])) for i, req in enumerate(m['alphabet']))
    oracle = product_oracle(p, m, decisions_only=True)
    if not weak_local or oracle['shortest']['length'] != 2:
        raise RuntimeError('observation ablation did not discriminate')
    return {'curated': records, 'decision_only_ablation': {'weakened_local_accepts': weak_local,
            'actual_decision_witness_length': oracle['shortest']['length'], 'oracle_evaluations': oracle['transition_evaluations']},
            'obligations': sum(r['obligations'] for r in records) + oracle['transition_evaluations'] + 1}

def pilot(output):
    begin = time.process_time(); wall = time.perf_counter(); output = Path(output)
    results = []
    for name in MODELS:
        rows = read_inputs(INPUTS, name)
        for mode in ('base', 'one-use'):
            results.append(analyze({'kind': 'public', 'source': name, 'mode': mode,
                                    'policy': extend(translate(name, rows), mode)}, name + '-' + mode, output / 'examples'))
    ctr = controls(output / 'examples')
    for i in range(32):
        results.append(analyze({'kind': 'generated', 'generator_index': i, 'policy': generated(i)}, 'generated-' + str(i), auxiliary_mutation=True))
    pc = public_checks()
    report = {'case_count': len(results) + len(ctr['curated']), 'cpu_seconds': time.process_time() - begin,
              'wall_seconds': time.perf_counter() - wall, 'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
              'obligations': sum(r['obligations'] for r in results) + ctr['obligations'] + pc['obligations'],
              'all_internal_comparisons_agree': True, 'public': pc, 'controls': ctr, 'cases': results}
    write_json(output / 'pilot.json', report)
    if report['cpu_seconds'] >= 30 or report['peak_rss_kib'] >= 256 * 1024:
        raise RuntimeError('pilot exceeded its gate')
    print(json.dumps({k: v for k, v in report.items() if k not in ('cases', 'public', 'controls')}, indent=2))

def batch(start, count, output):
    if start < 0 or count < 1 or start + count > 10000:
        raise ValueError('batch bounds')
    output = Path(output); begin = time.process_time(); wall = time.perf_counter()
    rows = []
    for i in range(start, start + count):
        spec = primary(i, INPUTS)
        keep = output / 'examples' if spec['kind'] in ('public', 'width', 'chain') else None
        row = analyze(spec, f'case-{i:05d}', keep, auxiliary_mutation=(spec['kind'] == 'generated' and spec['generator_index'] % 10 == 0))
        rows.append(row)
        if time.process_time() - begin > 110:
            raise RuntimeError('batch reached CPU timeout guard')
    chunk = output / 'chunks' / f'{start:05d}-{start + count - 1:05d}.jsonl'
    chunk.parent.mkdir(parents=True, exist_ok=True)
    if chunk.exists():
        raise FileExistsError('refusing to overwrite existing evidence chunk')
    chunk.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')
    metrics = {'start': start, 'count': count, 'cpu_seconds': time.process_time() - begin,
               'wall_seconds': time.perf_counter() - wall, 'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
               'obligations': sum(r['obligations'] for r in rows)}
    write_json(output / 'chunks' / (chunk.stem + '.metrics.json'), metrics)
    print(json.dumps(metrics))

def sequence(start, chunks, output):
    """Run at most ten sequential 250-case chunks in one worker process."""
    if type(start) is not int or type(chunks) is not int or start < 0 or start % 250 or not 1 <= chunks <= 10 or start + 250 * chunks > 10000:
        raise ValueError('sequence bounds')
    begin = time.process_time()
    for offset in range(chunks):
        batch(start + 250 * offset, 250, output)
        if time.process_time() - begin > 110:
            raise RuntimeError('sequence reached CPU timeout guard')

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='command', required=True)
    pp = sub.add_parser('pilot'); pp.add_argument('--output', default=str(ROOT / 'results/pilot'))
    bp = sub.add_parser('batch'); bp.add_argument('--start', type=int, required=True); bp.add_argument('--count', type=int, default=250)
    bp.add_argument('--output', required=True)
    sp = sub.add_parser('sequence'); sp.add_argument('--start', type=int, required=True)
    sp.add_argument('--chunks', type=int, required=True); sp.add_argument('--output', required=True)
    args = ap.parse_args()
    if args.command == 'pilot': pilot(args.output)
    elif args.command == 'batch': batch(args.start, args.count, args.output)
    else: sequence(args.start, args.chunks, args.output)
