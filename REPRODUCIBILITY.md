# Reproducibility Contract

The list-free verifier distinguishes verified equivalent, verified non-equivalent with a replayable witness, invalid input, and inconclusive because a declared work limit was exhausted. The legacy region verifier can also reject evidence at an unreachable cell; use actual-reachability diagnosis before interpreting that as non-equivalence. Inconclusive is never converted to semantic rejection.

The portable list-free tests and `src/baseline_checks.py` run on native Windows without `resource`. The new report `results/same_information.json` is a separate Windows semantic/interface comparison, not a Linux full reproduction or a replacement for historical timing/RSS. It preserves all original campaign files and the omission of eight wide complete-binding products. The 2,215-table diversity count applies to the generated 9,936-case cohort with the exact signature documented in that script. The ordinary BFS shares checker semantics and is not an independent evaluator. Full Linux reproduction below remains a separate obligation.

## Supported environment

The full reproducibility entry points are supported on CPython running on Linux with the POSIX `resource` module. The retained earlier release-entry record was produced with CPython 3.13 on Linux. The four retained runs in `results/current` cover the 56-method suite recorded in those runs and whole campaign on CPython 3.13 Linux; they precede checker preparation reuse. Portable checks have a narrower scope. Native Windows does not support the full campaign because `resource` is absent from that standard library build. A Windows user can enter the supported environment through a Linux distribution under WSL or a Linux container with the repository mounted as the working directory. The self-contained `test_prepared_checker.py` regression is portable and separately documented in the README; passing it does not complete Linux reproduction or refresh any retained timing.

A minimal preflight is:

```bash
python -c "import resource, sys; assert sys.platform.startswith('linux')"
```

On Linux, `peak_rss_kib` is `resource.getrusage(...).ru_maxrss` in KiB. CPU-time and wall-time fields are seconds. Timing and RSS are environmental measurements, not semantic verdict fields.

## Quick verification

Install the selected dependencies into an isolated Linux environment, then
disable bytecode for the verifier and its child test processes:

```bash
export PYTHONDONTWRITEBYTECODE=1
python -m venv /tmp/authrefine-checks
/tmp/authrefine-checks/bin/python -m pip install -r requirements-test.txt
source /tmp/authrefine-checks/bin/activate
python verify_release.py
```

This checks the supported platform; required scientific files; the frozen external-input path and byte-count inventory; JSON readability; exact coverage of the forty delivered primary chunks and 10,000 ordered records; consistency of the retained CNL, typed policies, automata, certificates, and diagnostics through actual semantic replay; and the unit suite in ordinary and optimized modes.

## Full deterministic campaign matrix

```bash
python verify_release.py --campaign
```

The command copies the artifact to an isolated temporary directory. It then runs four fresh outputs, covering the Cartesian product:

| Python hash seed | Time zone |
|---|---|
| 1729 | UTC |
| 1729 | America/Los_Angeles |
| 2718 | UTC |
| 2718 | America/Los_Angeles |

For every configuration the verifier invokes:

```bash
python reproduce.py --output <new-temporary-output> --compare <copied-artifact>/results
```

Acceptance is based on the generated evidence, not merely the subprocess return code. The verifier requires exactly forty JSONL chunks, forty metrics files, 10,000 ordered primary records, a fresh non-resumed reconstruction, successful replay of the documented commands, and explicit scientific-field agreement in both `summary.json` and `reproduction.json`. The comparison removes only the declared environmental timing and Linux RSS fields.

Freshness is recorded as `fresh_reproduction`; this directory-based entry point does not extract an archive and records `fresh_archive_extraction` as false. Existing historical records are preserved with their original metadata. Each child invocation retains full stdout, stderr, exit status and timeout information under the new output's `raw-logs/`, even if reproduction stops before a summary is produced. Timeouts and failed configurations remain failures in the matrix report.

The Linux workflow permits up to four parallel matrix workers. Inside each
worker, the quick verifier (180-second enclosing limit), whole deterministic
campaign (300-second enclosing limit, 120 seconds per child), and same-information
comparison run sequentially. An always-run upload preserves complete or partial
output and logs. A local `--campaign` invocation instead runs its four
configurations sequentially. Configuration alone is not execution evidence:
current CI results and the retained historical measurements have separate roles.
The earlier retained Linux entry record covers 47 methods; `results/current`
retains four 56-method runs, seven documented commands and 10,000 primary records
per configuration. Each reports scientific-field agreement and fresh output.
Current verification discovers the expanded suite; it does not rewrite those
historical method counts or timings.

For a single configuration, run `reproduce.py` directly with a new output directory and the delivered `results` baseline. `results/clean_reproduction.json` is an earlier retained reconstruction record and is not accepted as evidence that a current invocation succeeded.

## Trusted computing base

The mathematical statements rely on the definitions and proofs in the paper. Executable evidence relies on CPython, Linux process and filesystem behavior, JSON and Unicode behavior in the standard library, and the delivered checker and semantic implementations. Product search shares the reference interpreter and is therefore an algorithmic cross-check rather than a fully independent formalization. This reproducibility protocol does not establish novelty, venue compliance, production deployment security, or a mechanically verified implementation.
