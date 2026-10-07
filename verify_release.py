#!/usr/bin/env python3
"""Validate the delivered trace-refinement artifact.

Quick mode checks the supported runtime, required scientific assets, JSON
readability, frozen result coverage, replayable example evidence, and the unit
suite in ordinary and optimized modes. ``--campaign`` additionally runs the
published reproduction in isolated temporary directories under four
hash-seed/time-zone configurations.  Every campaign receives a fresh
``--output`` directory and the delivered ``results`` directory via
``--compare``; completion is accepted only after the new output contains all
40 chunks, all 10,000 ordered primary records, and a successful scientific-
field comparison with that frozen baseline.

The verifier deliberately does not maintain or validate a whole-tree source
fingerprint manifest.  Scientific acceptance comes from required-file checks,
input/result structure, executable tests, and semantic replay.
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
VOLATILE = {"__pycache__", ".pytest_cache", ".mypy_cache", ".coverage"}
FORBIDDEN_DELIVERY_FILES = {
    "SOURCE-MANIFEST.sha256",
    "FIGURE-HANDOFF.md",
    "REVIEWER-RISK-MATRIX.md",
    "_profile_release_tests_tmp.py",
}
DETERMINISM_CONFIGS = (
    {"python_hash_seed": "1729", "timezone": "UTC"},
    {"python_hash_seed": "1729", "timezone": "America/Los_Angeles"},
    {"python_hash_seed": "2718", "timezone": "UTC"},
    {"python_hash_seed": "2718", "timezone": "America/Los_Angeles"},
)
REQUIRED_FILES = (
    "LICENSE",
    "README.md",
    "REPRODUCIBILITY.md",
    "DEPENDENCIES.md",
    "reproduce.py",
    "verify_release.py",
    "proofs/semantics.md",
    "tests/test_core.py",
    "tests/test_release_cli.py",
    "tests/test_prepared_checker.py",
    "src/adversarial_checks.py",
    "src/cases.py",
    "src/checker.py",
    "src/compiler.py",
    "src/exhaustive_audit.py",
    "src/experiments.py",
    "src/extension_checks.py",
    "src/extensions.py",
    "src/language.py",
    "src/oracle.py",
    "src/policy.py",
    "src/public_inputs.py",
    "src/reference_check.py",
    "src/summarize.py",
    "src/symbolic.py",
    "src/theory_checks.py",
    "external_inputs/MANIFEST.json",
    "external_inputs/casbin/selection.json",
    "external_inputs/casbin/assertions.json",
    "results/summary.json",
    "results/theory.json",
    "results/extensions.json",
    "results/adversarial.json",
    "results/exhaustive.json",
    "results/reference_verification.json",
    "results/pilot/pilot.json",
    "results/reproducibility_entry_check.json",
)


def count_tests() -> int:
    count = 0
    for path in (ROOT / "tests").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        count += sum(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
            for node in ast.walk(tree)
        )
    return count


def run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    timeout: int = 900,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command, cwd=cwd, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=timeout, env=env, check=False,
        )
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return {"cmd": command, "returncode": 124, "timed_out": True,
                "output_tail": output[-12000:], "timeout_seconds": timeout}
    return {
        "cmd": command,
        "returncode": completed.returncode,
        "output_tail": completed.stdout[-12000:],
    }


def supported_environment() -> dict[str, Any]:
    linux = sys.platform.startswith("linux")
    resource_available = importlib.util.find_spec("resource") is not None
    return {
        "name": "supported_environment",
        "ok": linux and resource_available,
        "platform": platform.system(),
        "python_implementation": platform.python_implementation(),
        "python_major_minor": f"{sys.version_info.major}.{sys.version_info.minor}",
        "resource_module": resource_available,
        "required": "CPython on Linux with the POSIX resource module",
        "peak_rss_unit": "KiB on Linux",
        "cpu_and_wall_time_unit": "seconds",
    }


def required_assets() -> dict[str, Any]:
    missing = [relative for relative in REQUIRED_FILES if not (ROOT / relative).is_file()]
    forbidden = [name for name in sorted(FORBIDDEN_DELIVERY_FILES) if (ROOT / name).exists()]

    input_manifest_errors: list[str] = []
    input_file_count = 0
    manifest_path = ROOT / "external_inputs" / "MANIFEST.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entries = manifest.get("files", [])
            if not isinstance(entries, list):
                input_manifest_errors.append("external input manifest files field is not a list")
            else:
                input_file_count = len(entries)
                for entry in entries:
                    relative = entry.get("path") if isinstance(entry, dict) else None
                    if not isinstance(relative, str):
                        input_manifest_errors.append("external input manifest has an entry without a path")
                        continue
                    path = ROOT / relative
                    if not path.is_file():
                        input_manifest_errors.append(f"missing frozen input: {relative}")
                        continue
                    declared_bytes = entry.get("bytes")
                    if isinstance(declared_bytes, int) and path.stat().st_size != declared_bytes:
                        input_manifest_errors.append(f"byte-count mismatch for frozen input: {relative}")
        except Exception as error:  # the error is reported as evidence, not hidden
            input_manifest_errors.append(str(error))

    return {
        "name": "required_scientific_assets",
        "ok": not missing and not forbidden and not input_manifest_errors,
        "required_files": len(REQUIRED_FILES),
        "missing": missing,
        "forbidden_present": forbidden,
        "frozen_input_entries": input_file_count,
        "frozen_input_errors": input_manifest_errors,
        "whole_source_fingerprint_checked": False,
    }


def parse_json_evidence() -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    count = 0
    for path in ROOT.rglob("*.json"):
        count += 1
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as error:
            errors.append({"file": str(path.relative_to(ROOT)), "error": str(error)})
    return {"name": "json_parse", "ok": not errors, "files": count, "errors": errors}


def inspect_chunk_set(directory: Path) -> dict[str, int]:
    chunks = directory / "chunks"
    expected_jsonl = [f"{start:05d}-{start + 249:05d}.jsonl" for start in range(0, 10000, 250)]
    expected_metrics = [f"{start:05d}-{start + 249:05d}.metrics.json" for start in range(0, 10000, 250)]
    actual_jsonl = sorted(path.name for path in chunks.glob("*.jsonl"))
    actual_metrics = sorted(path.name for path in chunks.glob("*.metrics.json"))
    if actual_jsonl != expected_jsonl:
        raise ValueError("primary chunk set is not the exact frozen 40-file sequence")
    if actual_metrics != expected_metrics:
        raise ValueError("chunk metric set is not the exact frozen 40-file sequence")

    expected_index = 0
    for name in expected_jsonl:
        path = chunks / name
        line_count = 0
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                row = json.loads(line)
                expected_case = f"case-{expected_index:05d}"
                if row.get("case") != expected_case:
                    raise ValueError(
                        f"primary record order differs at {expected_case}: {row.get('case')!r}"
                    )
                expected_index += 1
                line_count += 1
        if line_count != 250:
            raise ValueError(f"{name} contains {line_count} records rather than 250")
    if expected_index != 10000:
        raise ValueError(f"primary record total is {expected_index}, not 10000")

    metric_total = 0
    for name in expected_metrics:
        metric = json.loads((chunks / name).read_text(encoding="utf-8"))
        if not isinstance(metric.get("count"), int):
            raise ValueError(f"{name} has no integer count")
        metric_total += metric["count"]
    if metric_total != 10000:
        raise ValueError(f"chunk metric total is {metric_total}, not 10000")

    return {"chunks": 40, "metric_files": 40, "primary_records": 10000}


def frozen_result_structure() -> dict[str, Any]:
    errors: list[str] = []
    details: dict[str, Any] = {}
    try:
        details.update(inspect_chunk_set(ROOT / "results"))
        summary = json.loads((ROOT / "results" / "summary.json").read_text(encoding="utf-8"))
        if summary.get("primary_cases") != 10000:
            raise ValueError("delivered summary does not report 10,000 primary cases")
        details["summary_primary_cases"] = summary.get("primary_cases")
    except Exception as error:
        errors.append(str(error))
    return {"name": "frozen_result_structure", "ok": not errors, **details, "errors": errors}


def semantic_example_replay() -> dict[str, Any]:
    errors: list[str] = []
    accepted = 0
    rejected = 0
    examples_root = ROOT / "results" / "examples"
    example_directories = sorted(path for path in examples_root.iterdir() if path.is_dir())

    source_path = str((ROOT / "src").resolve())
    if source_path not in sys.path:
        sys.path.insert(0, source_path)
    try:
        import checker  # type: ignore
        import compiler  # type: ignore
        import language  # type: ignore
    except Exception as error:
        return {
            "name": "semantic_example_replay",
            "ok": False,
            "examples": len(example_directories),
            "errors": [f"cannot import scientific modules: {error}"],
        }

    for directory in example_directories:
        label = directory.name
        required = ("policy.cnl", "policy.json", "automaton.json", "certificate.json", "diagnostic.json")
        absent = [name for name in required if not (directory / name).is_file()]
        if absent:
            errors.append(f"{label}: missing {', '.join(absent)}")
            continue
        try:
            policy = checker.load(directory / "policy.json")
            machine = checker.load(directory / "automaton.json")
            checker.inspect_policy(policy)
            checker.inspect_machine(policy, machine, compare_initial=False)
            certificate = checker.load(directory / "certificate.json")
            stored_diagnostic = checker.load(directory / "diagnostic.json")
            if language.read_policy(directory / "policy.cnl") != policy:
                raise ValueError("surface policy and frozen typed policy differ")

            try:
                checker.verify(policy, machine, certificate)
                equivalent = True
                accepted += 1
            except checker.Rejected as error:
                if error.kind != "mismatch":
                    raise ValueError(f"example verification is {error.kind}: {error}") from error
                equivalent = False
                rejected += 1

            if bool(stored_diagnostic.get("equivalent")) != equivalent:
                raise ValueError("certificate verdict and stored diagnosis differ")
            recomputed = compiler.diagnose(policy, machine)
            if recomputed != stored_diagnostic:
                raise ValueError("stored diagnosis differs from current deterministic diagnosis")

            if not equivalent:
                rows = compiler.replay(
                    policy,
                    machine,
                    stored_diagnostic["indices"],
                    stored_diagnostic["binding"],
                )
                if len(rows) != stored_diagnostic["length"]:
                    raise ValueError("replayed witness length differs")
                if any(row["source"] != row["target"] for row in rows[:-1]):
                    raise ValueError("a proper witness prefix already differs")
                if stored_diagnostic["length"] == 0:
                    source_initial = language.initial(policy)
                    target_initial = machine["observations"][machine["initial"]]
                    if rows or source_initial == target_initial:
                        raise ValueError("empty witness does not distinguish initial observations")
                elif not rows or rows[-1]["source"] == rows[-1]["target"]:
                    raise ValueError("the final witness step does not distinguish the machines")
        except Exception as error:
            errors.append(f"{label}: {error}")

    return {
        "name": "semantic_example_replay",
        "ok": not errors and len(example_directories) == 49,
        "examples": len(example_directories),
        "accepted": accepted,
        "non_equivalent": rejected,
        "errors": errors,
    }


def campaign_command(output: Path, baseline: Path) -> list[str]:
    """Construct the reproduction command used by the release entry point."""
    return [
        sys.executable,
        "reproduce.py",
        "--output",
        str(output),
        "--compare",
        str(baseline),
    ]


def inspect_campaign_output(
    output: Path,
    *,
    expected_seed: str | None = None,
    expected_timezone: str | None = None,
) -> dict[str, Any]:
    details = inspect_chunk_set(output)
    summary_path = output / "summary.json"
    reproduction_path = output / "reproduction.json"
    if not summary_path.is_file() or not reproduction_path.is_file():
        raise ValueError("campaign did not materialize both summary.json and reproduction.json")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    reproduction = json.loads(reproduction_path.read_text(encoding="utf-8"))
    for name, value in (("summary", summary), ("reproduction", reproduction)):
        if value.get("primary_cases") != 10000:
            raise ValueError(f"{name} does not report 10,000 primary cases")
        if value.get("baseline_scientific_records_match") is not True:
            raise ValueError(f"{name} does not confirm scientific-field agreement with the baseline")
    if reproduction.get("fresh_reproduction") is not True or reproduction.get("resumed") is not False:
        raise ValueError("campaign was not a fresh non-resumed run")
    if reproduction.get("documented_commands_succeeded") is not True:
        raise ValueError("documented command replay did not complete successfully")

    environment = reproduction.get("execution_environment")
    if not isinstance(environment, dict):
        raise ValueError("campaign did not record its supported execution environment")
    if expected_seed is not None and environment.get("python_hash_seed") != expected_seed:
        raise ValueError("campaign recorded a different Python hash seed")
    if expected_timezone is not None and environment.get("timezone") != expected_timezone:
        raise ValueError("campaign recorded a different time zone")
    if environment.get("platform") != "Linux" or environment.get("peak_rss_unit") != "KiB":
        raise ValueError("campaign was not recorded under the supported Linux resource convention")

    return {
        **details,
        "baseline_scientific_records_match": True,
        "documented_commands_succeeded": True,
        "python_hash_seed": environment.get("python_hash_seed"),
        "timezone": environment.get("timezone"),
    }


def run_campaign_matrix() -> dict[str, Any]:
    configurations: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="trace-refinement-verify-") as temporary_name:
        temporary = Path(temporary_name)
        artifact = temporary / "artifact"
        shutil.copytree(
            ROOT,
            artifact,
            ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", "*.pyo", ".coverage", ".pytest_cache", ".mypy_cache"
            ),
        )
        baseline = artifact / "results"
        runs = temporary / "runs"
        runs.mkdir()

        for configuration in DETERMINISM_CONFIGS:
            seed = configuration["python_hash_seed"]
            timezone = configuration["timezone"]
            slug = timezone.replace("/", "-")
            output = runs / f"seed-{seed}-{slug}"
            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHONHASHSEED": seed,
                    "TZ": timezone,
                    "LC_ALL": "C.UTF-8",
                    "LANG": "C.UTF-8",
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            )
            invocation = run(
                campaign_command(output, baseline),
                cwd=artifact,
                timeout=1800,
                env=environment,
            )
            evidence: dict[str, Any] | None = None
            evidence_error: str | None = None
            if invocation["returncode"] == 0:
                try:
                    evidence = inspect_campaign_output(
                        output,
                        expected_seed=seed,
                        expected_timezone=timezone,
                    )
                except Exception as error:
                    evidence_error = str(error)
            else:
                evidence_error = "reproduction process returned nonzero"
            configurations.append(
                {
                    "python_hash_seed": seed,
                    "timezone": timezone,
                    "ok": invocation["returncode"] == 0 and evidence is not None,
                    "invocation": invocation,
                    "evidence": evidence,
                    "evidence_error": evidence_error,
                }
            )

    return {
        "name": "campaign_determinism_matrix",
        "ok": len(configurations) == 4 and all(row["ok"] for row in configurations),
        "configurations": configurations,
        "configuration_count": len(configurations),
        "cross_configuration_scientific_match": all(
            (row.get("evidence") or {}).get("baseline_scientific_records_match") is True
            for row in configurations
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--campaign",
        action="store_true",
        help="run the full campaign under two hash seeds x two time zones",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    arguments = parser.parse_args()

    checks: list[dict[str, Any]] = []
    checks.append(supported_environment())

    links = [str(path.relative_to(ROOT)) for path in ROOT.rglob("*") if path.is_symlink()]
    caches = [
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*")
        if path.name in VOLATILE or path.suffix in {".pyc", ".pyo"}
    ]
    checks.append(
        {
            "name": "archive_hygiene",
            "ok": not links and not caches,
            "links": links,
            "cache_entries": caches,
        }
    )
    checks.append(required_assets())
    checks.append(parse_json_evidence())
    checks.append(frozen_result_structure())
    checks.append(semantic_example_replay())

    ordinary = run([sys.executable, "-W", "error", "-m", "unittest", "discover", "-s", "tests"])
    optimized = run(
        [sys.executable, "-OO", "-W", "error", "-m", "unittest", "discover", "-s", "tests"]
    )
    checks.append(
        {
            "name": "unit_tests",
            "ok": ordinary["returncode"] == 0 and optimized["returncode"] == 0,
            "test_methods": count_tests(),
            "ordinary": ordinary,
            "optimized": optimized,
        }
    )

    if arguments.campaign:
        checks.append(run_campaign_matrix())

    report = {
        "schema_version": 2,
        "root": ".",
        "checks": checks,
        "ok": all(check["ok"] for check in checks),
        "scope": {
            "source_snapshot_fingerprint": False,
            "novelty_review": False,
            "venue_rule_review": False,
        },
    }
    if arguments.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        for check in checks:
            print(("PASS" if check["ok"] else "FAIL") + "  " + check["name"])
        print("PASS  release" if report["ok"] else "FAIL  release")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
