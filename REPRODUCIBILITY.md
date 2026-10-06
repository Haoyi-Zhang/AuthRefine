# Reproducibility Contract

The artifact distinguishes four outcomes: verified equivalent, verified non-equivalent with a replayable witness, invalid input, and inconclusive because a declared work limit was exhausted. Inconclusive is never converted to semantic rejection.

## Supported environment

The reproducibility entry points are supported on CPython running on Linux with the POSIX `resource` module. The retained earlier release-entry record was produced with CPython 3.13 on Linux; the current repairs have only portable Windows validation until the current Linux suite and campaign run. Native Windows is not supported because `resource` is absent from that standard library build. A Windows user can enter the supported environment through a Linux distribution under WSL or a Linux container with the repository mounted as the working directory.

A minimal preflight is:

```bash
python -c "import resource, sys; assert sys.platform.startswith('linux')"
```

On Linux, `peak_rss_kib` is `resource.getrusage(...).ru_maxrss` in KiB. CPU-time and wall-time fields are seconds. Timing and RSS are environmental measurements, not semantic verdict fields.

## Quick verification

```bash
python verify_release.py
```

This checks the supported platform; required scientific files; the frozen external-input path and byte-count inventory; JSON readability; exact coverage of the forty delivered primary chunks and 10,000 ordered records; consistency of the retained CNL, typed policies, automata, certificates, and diagnostics through actual semantic replay; and the unit suite in ordinary and optimized modes.

The quick verifier does not read or require a whole-tree checksum manifest. No claim of complete source-snapshot fingerprint verification is made. The absence of an optional `.gitignore` or of reviewer/figure handoff files is not a scientific failure.

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

The Linux workflow executes all four configurations with one matrix worker at a time. Each runs the quick verifier (180-second enclosing limit) and the whole deterministic campaign (300-second enclosing limit, 120 seconds per child). An always-run upload preserves complete or partial output and logs. This prepared workflow is not evidence of a successful run. The current suite has 56 methods; the retained Linux entry record covers 47 methods, while the nine newer regressions have only portable local validation until the current Linux suite runs.

For a single configuration, run `reproduce.py` directly with a new output directory and the delivered `results` baseline. `results/clean_reproduction.json` is an earlier retained reconstruction record and is not accepted as evidence that a current invocation succeeded.

## Trusted computing base

The mathematical statements rely on the definitions and proofs in the paper. Executable evidence relies on CPython, Linux process and filesystem behavior, JSON and Unicode behavior in the standard library, and the delivered checker and semantic implementations. Product search shares the reference interpreter and is therefore an algorithmic cross-check rather than a fully independent formalization. This reproducibility protocol does not establish novelty, venue compliance, production deployment security, or a mechanically verified implementation.
