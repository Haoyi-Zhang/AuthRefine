"""Run the frozen single-worker campaign into a fresh directory."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import time

try:
    import resource
except ImportError:  # Native Windows does not provide this POSIX module.
    resource = None

ROOT = Path(__file__).resolve().parent


def run_logged(command, *, cwd, env, log_prefix, timeout=120):
    """Retain complete child output even when a bounded command fails."""
    prefix = Path(log_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    metadata = {"command": command, "timeout_seconds": timeout}
    started = time.perf_counter()
    stdout = stderr = ""
    try:
        completed = subprocess.run(
            command, cwd=cwd, env=env, check=False, timeout=timeout,
            capture_output=True, text=True,
        )
        stdout, stderr = completed.stdout, completed.stderr
        metadata.update(exit_code=completed.returncode, timed_out=False)
        completed.check_returncode()
        return completed
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        metadata.update(exit_code=None, timed_out=True)
        raise
    finally:
        metadata["wall_seconds"] = time.perf_counter() - started
        prefix.with_suffix(".stdout.log").write_text(stdout, encoding="utf-8")
        prefix.with_suffix(".stderr.log").write_text(stderr, encoding="utf-8")
        prefix.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


def require_supported_environment():
    if not sys.platform.startswith("linux") or resource is None:
        raise SystemExit(
            "This reproduction entry point is supported on Linux CPython with the POSIX "
            "resource module. Native Windows is not a supported execution environment."
        )



def main():
    require_supported_environment()
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and not args.resume:
        raise SystemExit("Choose a new output directory, or resume the same deterministic campaign explicitly.")
    output.mkdir(parents=True, exist_ok=args.resume)
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    begin = time.perf_counter()
    documented = []
    logs = output / "raw-logs"
    logs.mkdir(exist_ok=args.resume)
    command_index = len(list(logs.glob("*.json")))

    def run(arguments, *, record=None):
        nonlocal command_index
        command_index += 1
        started = time.perf_counter()
        completed = run_logged(
            [sys.executable, *arguments], cwd=ROOT, env=env,
            log_prefix=logs / f"command-{command_index:03d}", timeout=120,
        )
        if record is not None:
            documented.append({
                "command": ["python", *(record if record is not True else arguments)],
                "exit_code": completed.returncode,
                "wall_seconds": time.perf_counter() - started,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            })
        return completed

    unit = run(["-m", "unittest", "discover", "-s", "tests", "-v"], record=True)
    match = re.search(r"Ran (\d+) tests?", unit.stdout + unit.stderr)
    if match is None:
        raise ValueError("unit-test method count was not reported")
    unit_test_methods = int(match.group(1))

    if not (output / "reference_verification.json").exists():
        run(["src/reference_check.py", "--output", str(output / "reference_verification.json")])
    if not (output / "pilot/pilot.json").exists():
        run(["src/experiments.py", "pilot", "--output", str(output / "pilot")])
    if not (output / "theory.json").exists():
        run(["src/theory_checks.py", "--output", str(output / "theory.json")])
    if not (output / "extensions.json").exists():
        run(["src/extension_checks.py", "--output", str(output / "extensions.json")])
    if not (output / "adversarial.json").exists():
        run(["src/adversarial_checks.py", "--output", str(output / "adversarial.json")])
    if not (output / "exhaustive.json").exists():
        run(["src/exhaustive_audit.py", "--output", str(output / "exhaustive.json")])

    pending = []
    for start in range(0, 10000, 250):
        chunk = output / "chunks" / f"{start:05d}-{start+249:05d}.jsonl"
        metric = chunk.with_suffix(".metrics.json")
        if chunk.exists() and metric.exists():
            rows = [json.loads(line) for line in chunk.read_text().splitlines()]
            if [row["case"] for row in rows] != [f"case-{i:05d}" for i in range(start, start + 250)]:
                raise ValueError("resume chunk coverage differs")
            continue
        if chunk.exists() or metric.exists():
            raise ValueError("incomplete chunk pair; retain it and use a new output directory")
        pending.append(start)

    # Retain the same evidence chunks without paying for a new interpreter on
    # every 250-case chunk. Each bounded worker receives at most ten chunks.
    while pending:
        start = pending.pop(0)
        count = 1
        while pending and count < 10 and pending[0] == start + 250 * count:
            pending.pop(0)
            count += 1
        run(["src/experiments.py", "sequence", "--start", str(start),
             "--chunks", str(count), "--output", str(output)])

    with tempfile.TemporaryDirectory() as temporary_name:
        temporary = Path(temporary_name)
        example = ROOT / "results/examples/case-00000"
        run([
            "src/checker.py", str(example / "policy.json"), str(example / "automaton.json"),
            str(example / "certificate.json"),
        ], record=[
            "src/checker.py", "results/examples/case-00000/policy.json",
            "results/examples/case-00000/automaton.json",
            "results/examples/case-00000/certificate.json",
        ])
        normalized = temporary / "normalized.cnl"
        compiled = temporary / "compiled-policy"
        diagnosis = temporary / "diagnosis.json"
        reified = temporary / "reified.cnl"
        run([
            "src/policy.py", "normalize", str(example / "policy.cnl"), str(normalized),
        ], record=[
            "src/policy.py", "normalize", "results/examples/case-00000/policy.cnl",
            "temporary/normalized.cnl",
        ])
        run([
            "src/policy.py", "compile", str(normalized), str(compiled),
        ], record=[
            "src/policy.py", "compile", "temporary/normalized.cnl", "temporary/compiled-policy",
        ])
        run([
            "src/policy.py", "diagnose", str(compiled / "policy.json"),
            str(compiled / "automaton.json"), str(diagnosis),
        ], record=[
            "src/policy.py", "diagnose", "temporary/compiled-policy/policy.json",
            "temporary/compiled-policy/automaton.json", "temporary/diagnosis.json",
        ])
        run([
            "src/policy.py", "reify", str(compiled / "policy.json"),
            str(compiled / "automaton.json"), str(reified),
        ], record=[
            "src/policy.py", "reify", "temporary/compiled-policy/policy.json",
            "temporary/compiled-policy/automaton.json", "temporary/reified.cnl",
        ])

    command = ["src/summarize.py", str(output)]
    record = ["src/summarize.py", "reproduction-output"]
    if args.compare:
        command += ["--baseline", str(args.compare.resolve())]
        record += ["--baseline", "results"]
    summary_process = run(command, record=record)
    summary = json.loads(summary_process.stdout)
    summary["documented_commands_succeeded"] = all(row["exit_code"] == 0 for row in documented)
    summary["documented_command_count"] = len(documented)
    summary["unit_test_methods"] = unit_test_methods
    summary["reproduction_wall_seconds"] = time.perf_counter() - begin
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    summary["invocation_child_cpu_seconds"] = usage.ru_utime + usage.ru_stime
    summary["invocation_cpu_seconds"] = time.process_time()
    summary["resumed"] = args.resume
    summary["fresh_reproduction"] = not args.resume
    # This entry runs a directory; it does not extract or attest an archive.
    summary["fresh_archive_extraction"] = False
    summary["execution_environment"] = {
        "platform": "Linux",
        "python_implementation": sys.implementation.name,
        "python_major_minor": f"{sys.version_info.major}.{sys.version_info.minor}",
        "python_hash_seed": env.get("PYTHONHASHSEED", "not-set"),
        "timezone": env.get("TZ", "not-set"),
        "peak_rss_unit": "KiB",
        "cpu_time_unit": "seconds",
        "wall_time_unit": "seconds",
    }
    (output / "documented_commands.json").write_text(json.dumps(documented, indent=2) + "\n")
    (output / "reproduction.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
