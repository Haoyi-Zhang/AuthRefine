"""Fresh-process same-backend, same-output finite verification-cost comparison."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
import tracemalloc

import checker
from compiler import certificate
from reuse_cases import lab_cases

ROOT = Path(__file__).resolve().parents[1]
ACCOUNTING = {'work_operations', 'work_budget', 'work_breakdown',
              'physical_binding_evaluations', 'reused_cells', 'reuse_entries'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def semantic(report):
    return {name: value for name, value in report.items() if name not in ACCOUNTING}


def old_checker(path):
    # The caller must fully review this supplied baseline before executing it.
    spec = importlib.util.spec_from_file_location('frozen_checker', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def peak_working_set_bytes():
    """OS high-water resident working set of this owned process, including input."""
    if sys.platform == 'win32':
        size = ctypes.c_size_t
        class Counters(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                        ('PeakWorkingSetSize', size), ('WorkingSetSize', size),
                        ('QuotaPeakPagedPoolUsage', size), ('QuotaPagedPoolUsage', size),
                        ('QuotaPeakNonPagedPoolUsage', size), ('QuotaNonPagedPoolUsage', size),
                        ('PagefileUsage', size), ('PeakPagefileUsage', size)]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        api = ctypes.WinDLL('psapi', use_last_error=True)
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        api.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        api.GetProcessMemoryInfo.restype = wintypes.BOOL
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not api.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return counters.PeakWorkingSetSize
    if sys.platform.startswith('linux'):
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    raise RuntimeError('peak resident accounting supported on Windows/Linux only')


def child(args):
    # Equal import work/resident modules in both cold processes. Otherwise the
    # frozen-module load would masquerade as a reuse startup/memory saving.
    frozen = old_checker(args.baseline_checker)
    backend = frozen if args.child == 'before' else checker
    raw = sys.stdin.buffer.read()
    if args.trace:
        tracemalloc.start()
    begin_wall, begin_cpu = time.perf_counter_ns(), time.process_time_ns()
    decode_start = time.perf_counter_ns()
    cases = json.loads(raw)
    decode_ns = time.perf_counter_ns() - decode_start
    check_start, check_cpu = time.perf_counter_ns(), time.process_time_ns()
    reports = [backend.verify_reachable(row['policy'], row['machine'],
               **({'reuse_observations': True} if args.child == 'reuse' else {})) for row in cases]
    check_cpu_ns = time.process_time_ns() - check_cpu
    check_ns = time.perf_counter_ns() - check_start
    encode_start = time.perf_counter_ns()
    payload = encoded([semantic(report) for report in reports])
    encode_ns = time.perf_counter_ns() - encode_start
    total_cpu_ns = time.process_time_ns() - begin_cpu
    total_ns = time.perf_counter_ns() - begin_wall
    allocation_peak = tracemalloc.get_traced_memory()[1] if args.trace else None
    if args.trace:
        tracemalloc.stop()
    result = {'mode': args.child, 'traced': args.trace, 'reports': reports,
              'input_bytes': len(raw), 'semantic_output_bytes': len(payload),
              'semantic_output_sha256': hashlib.sha256(payload).hexdigest(),
              'decode_wall_ns': decode_ns, 'verification_wall_ns': check_ns,
              'verification_cpu_ns': check_cpu_ns, 'serialization_wall_ns': encode_ns,
              'pipeline_wall_ns': total_ns, 'pipeline_cpu_ns': total_cpu_ns,
              'peak_working_set_bytes': peak_working_set_bytes(),
              'pipeline_python_allocation_peak_bytes': allocation_peak,
              'logical_binding_obligations': sum(report['binding_evaluations'] for report in reports),
              'physical_binding_evaluations': sum(report.get('physical_binding_evaluations',
                  report['binding_evaluations']) for report in reports),
              'reused_cells': sum(report.get('reused_cells', 0) for report in reports),
              'max_reuse_entries_per_check': max(report.get('reuse_entries', 0) for report in reports),
              'completed_verdicts': len(reports)}
    sys.stdout.buffer.write(encoded(result))


def run_child(mode, data, baseline, trace=False):
    command = [sys.executable, '-B', str(Path(__file__).resolve()), '--child', mode,
               '--baseline-checker', str(baseline)] + (['--trace'] if trace else [])
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    start = time.perf_counter_ns()
    completed = subprocess.run(command, input=data, capture_output=True, timeout=60, env=env)
    elapsed = time.perf_counter_ns() - start
    if completed.returncode:
        raise RuntimeError('owned cost child failed: ' + completed.stderr.decode('utf-8', errors='replace'))
    result = json.loads(completed.stdout)
    result.update(cold_process_wall_ns=elapsed, command=command,
                  child_exit_code=completed.returncode, child_stderr=completed.stderr.decode('utf-8'),
                  actual_diagnostic_output_bytes=len(completed.stdout))
    return result


def run(args):
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError('fresh owned output required')
    started = time.perf_counter_ns()
    setup_start, setup_cpu = time.perf_counter_ns(), time.process_time_ns()
    groups = {'retained-49': []}
    for folder in sorted((ROOT / 'results/examples').iterdir()):
        if folder.is_dir():
            groups['retained-49'].append({'case': folder.name, 'policy': checker.load(folder / 'policy.json'),
                                         'machine': checker.load(folder / 'automaton.json')})
    if len(groups['retained-49']) != 49:
        raise ValueError('retained cohort must contain exactly 49 examples')
    for name, policy, machine in lab_cases(ROOT / 'external_inputs/casbin'):
        phase = name.rsplit('-', 1)[-1]
        groups.setdefault('phase-' + phase, []).append({'case': name, 'policy': policy, 'machine': machine})
    setup_ns = time.perf_counter_ns() - setup_start
    setup_cpu_ns = time.process_time_ns() - setup_cpu
    before = old_checker(args.baseline_checker)
    current_default_identical = True
    for cases in groups.values():
        for case in cases:
            old = before.verify_reachable(case['policy'], case['machine'])
            current = checker.verify_reachable(case['policy'], case['machine'])
            reused = checker.verify_reachable(case['policy'], case['machine'], reuse_observations=True)
            if old != current or semantic(old) != semantic(reused):
                raise RuntimeError('same-output/default regression: ' + case['case'])
    output.mkdir(parents=True)
    trials, traced, summary = {}, {}, {}
    setup = {'input_construction_wall_ns': setup_ns, 'input_construction_cpu_ns': setup_cpu_ns,
             'current_default_reports_identical_to_frozen_before': current_default_identical,
             'optional_region_transport': {}}
    for group, cases in groups.items():
        t0, c0 = time.perf_counter_ns(), time.process_time_ns()
        regions = [certificate(case['machine']) for case in cases]
        production_ns, production_cpu_ns = time.perf_counter_ns() - t0, time.process_time_ns() - c0
        setup['optional_region_transport'][group] = {
            'region_production_wall_ns': production_ns, 'region_production_cpu_ns': production_cpu_ns,
            'complete_region_list_bytes': len(encoded(regions)),
            'scope': 'Optional state-list materialization, separate from both list-free methods.'}
        data = encoded(cases)
        (output / (group + '-inputs.json')).write_bytes(data)
        results = {'before': [], 'reuse': []}
        for repeat in range(args.repeats):
            for mode in (('before', 'reuse') if repeat % 2 == 0 else ('reuse', 'before')):
                result = run_child(mode, data, args.baseline_checker)
                result['trial'] = repeat
                results[mode].append(result)
        expected = results['before'][0]['semantic_output_sha256']
        if any(result['semantic_output_sha256'] != expected for rows in results.values() for result in rows):
            raise RuntimeError('cold-process semantic output disagreement')
        trials[group] = results
        traced[group] = {mode: run_child(mode, data, args.baseline_checker, trace=True)
                         for mode in ('before', 'reuse')}
        if any(result['semantic_output_sha256'] != expected for result in traced[group].values()):
            raise RuntimeError('traced-process semantic output disagreement')
        entry = {'cases': len(cases), 'input_bytes': len(data), 'semantic_output_bytes': results['before'][0]['semantic_output_bytes'],
                 'all_semantic_outputs_identical': True}
        for mode, rows in results.items():
            entry[mode] = {key: statistics.median(row[key] for row in rows) for key in
                          ('cold_process_wall_ns', 'decode_wall_ns', 'verification_wall_ns',
                           'verification_cpu_ns', 'serialization_wall_ns', 'pipeline_wall_ns',
                           'pipeline_cpu_ns', 'peak_working_set_bytes')}
            for key in ('logical_binding_obligations', 'physical_binding_evaluations', 'reused_cells',
                        'max_reuse_entries_per_check'):
                if len({row[key] for row in rows}) != 1:
                    raise RuntimeError('nondeterministic operation counts')
                entry[mode][key] = rows[0][key]
            entry[mode]['pipeline_python_allocation_peak_bytes'] = traced[group][mode]['pipeline_python_allocation_peak_bytes']
        summary[group] = entry
    report = {'groups': summary, 'repeats_per_method': args.repeats,
              'before_checker_sha256': hashlib.sha256(args.baseline_checker.read_bytes()).hexdigest(),
              'environment': {'python': sys.version, 'executable': sys.executable, 'platform': platform.platform(),
                              'bytecode_disabled': sys.dont_write_bytecode},
              'limits': ['Same decoded policies/machines and identical complete replay-bearing semantic output; accounting fields differ.',
                         'Both child modes load the same frozen/current modules before decoding.',
                         'Every target state/edge is still validated/traversed; no supplied region required.',
                         'Peak working set is OS process high-water including imports and decoded inputs, not total system/commit memory.',
                         'Python allocation tracing is separate and includes decoding but starts after imports.',
                         'Cold process time includes startup, imports, pipe transfer, encoding diagnostic metadata and exit.',
                         'Seven alternating single-host cold trials are not hardware-normalized throughput.',
                         'Construction and optional state-list materialization are recorded separately, not summed as fabricated end-to-end medians.',
                         'Phase lifts are explicit finite representations, not native-engine or privacy evidence.'],
              'experiment_wall_ns': time.perf_counter_ns() - started}
    for name, value in (('trials.json', {'untraced': trials, 'traced': traced}), ('setup.json', setup), ('summary.json', report)):
        (output / name).write_bytes(encoded(value))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline-checker', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--repeats', type=int, default=7)
    parser.add_argument('--child', choices=('before', 'reuse'))
    parser.add_argument('--trace', action='store_true')
    args = parser.parse_args()
    if args.child:
        child(args)
    else:
        if args.output is None or not 1 <= args.repeats <= 20:
            parser.error('fresh --output and repeats in 1..20 required')
        run(args)
