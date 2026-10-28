"""Discover a bounded literal REST source chain without per-project path maps.

Only source bytes are parsed. No application, SQL dump or upstream test is run.
Ambiguous settings/seeds and incomplete scans cannot yield an agreement verdict.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys

from language import strict_json
from native_casbin import AdmissionError
from rest_source_chain import SourceArchive, compare_rest_source_chain


def discover_rest_chain(archive_path, domain, *, max_python_members=2000):
    if type(max_python_members) is not int or max_python_members < 1:
        raise ValueError("source scan cap must be a positive integer")
    result = {"status": "inconclusive", "accepted": None,
              "discovery_complete": False, "settings_candidates": [], "seed_candidates": [],
              "whole_application_verified": False, "source_modules_imported_or_executed": False,
              "manual_inputs": ["source archive identity", "finite request domain"],
              "scope": "unique literal default REST permission, bundled seed and selected native consumer"}
    bundle = SourceArchive(archive_path)
    try:
        python_members = sorted(name for name in bundle.members if name.endswith(".py"))
        result["python_members"] = len(python_members)
        result["seed_candidates"] = sorted(name for name in bundle.members if name.endswith(".sql"))
        if len(python_members) > max_python_members:
            return {**result, "reason": "complete source inventory exceeds the scan cap"}
        for name in python_members:
            source = bundle.read(name)
            # This is a byte prefilter only. Strings/comments do not establish
            # an active assignment; literal validation occurs in the consumer.
            if b"REST_FRAMEWORK" not in source:
                continue
            try:
                tree = ast.parse(source)
            except (SyntaxError, ValueError, RecursionError):
                return {**result, "reason": "a potential settings member does not parse", "problem_member": name}
            has_setting = any(isinstance(node, ast.Name) and node.id == "REST_FRAMEWORK"
                              and isinstance(node.ctx, (ast.Store, ast.Del)) for node in ast.walk(tree))
            if has_setting:
                result["settings_candidates"].append(name)
        result["discovery_complete"] = True
        if not result["settings_candidates"] or not result["seed_candidates"]:
            return {**result, "status": "missing_input", "reason": "no unique literal-settings/bundled-seed pair is available"}
        if len(result["settings_candidates"]) != 1 or len(result["seed_candidates"]) != 1:
            return {**result, "status": "ambiguous_input", "reason": "multiple source settings or SQL snapshots; do not select by successful output"}
        settings, seed = result["settings_candidates"][0], result["seed_candidates"][0]
    except AdmissionError as error:
        return {**result, "status": error.status, "reason": str(error)}
    finally:
        bundle.close()
    try:
        comparison = compare_rest_source_chain(archive_path, settings, seed, domain)
    except AdmissionError as error:
        return {**result, "status": error.status, "reason": str(error)}
    except RuntimeError as error:
        return {**result, "status": "native_error", "reason": type(error).__name__}
    return {**result, "status": comparison["status"], "accepted": comparison["accepted"],
            "comparison": comparison,
            "unverified_boundaries": comparison["unverified_boundaries"] + [
                "repository startup chooses the discovered settings",
                "bundled SQL is the application's current deployed policy snapshot"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--domain", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.receipt.exists():
        parser.error("receipt already exists; never reuse an older success")
    try:
        with args.domain.open("rb") as stream:
            raw = stream.read(1_048_577)
        if len(raw) > 1_048_576:
            raise AdmissionError("request domain exceeds its input envelope", "inconclusive")
        result = discover_rest_chain(args.archive, strict_json(raw.decode("utf-8-sig")))
    except (OSError, ValueError, AdmissionError) as error:
        result = {"status": getattr(error, "status", "invalid"), "accepted": None,
                  "error_type": type(error).__name__, "whole_application_verified": False}
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    with args.receipt.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"status": result["status"], "accepted": result["accepted"],
                      "receipt": str(args.receipt)}, ensure_ascii=True))
    return 0 if result["accepted"] is True else 1 if result["accepted"] is False else 2


if __name__ == "__main__":
    raise SystemExit(main())
