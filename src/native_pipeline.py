"""One bounded entry point for native configuration and source-interface checks.

Receipts identify the admitted scope, input paths and unresolved boundaries.
No command imports source modules, probes services or executes repository tests.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from checker import Rejected
from language import PolicyError, strict_json
from native_casbin import AdmissionError, MAX_TEXT_BYTES, compare_native


def read_bytes(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_TEXT_BYTES + 1)
    if len(data) > MAX_TEXT_BYTES:
        raise AdmissionError("input exceeds byte envelope", "inconclusive")
    return data


def text(path):
    return read_bytes(path).decode("utf-8-sig", errors="strict")


def evaluate(args):
    if args.mode == "version-cache-application":
        from versioned_discovery import discover_versioned_chain
        return discover_versioned_chain(args.archive, strict_json(text(args.epochs)), strict_json(text(args.requests)),
            default_model=args.default_model, stable_epochs=args.stable_epochs)
    if args.mode == "snapshot-application":
        from snapshot_discovery import discover_snapshot_chain
        return discover_snapshot_chain(args.archive, strict_json(text(args.rows)), strict_json(text(args.owners)),
            strict_json(text(args.requests)), ready=args.ready_interface)
    if args.mode == "file-wrapper-application":
        from file_wrapper_discovery import discover_file_wrappers
        return discover_file_wrappers(args.archive, ordered_argument_contract=("principal", "resource", "action"))
    if args.mode == "yaml-application":
        from yaml_discovery import discover_yaml_chain
        return discover_yaml_chain(args.archive, strict_json(text(args.contexts)), strict_json(text(args.domain)))
    if args.mode == "request-outcomes":
        from request_outcomes import compare_request_outcomes
        try:
            result = compare_request_outcomes(read_bytes(args.source), text(args.model))
            return {**result["comparison"], "source_projection": result}
        except RuntimeError as error:
            raise AdmissionError("request outcome native runtime failed: " + type(error).__name__, "native_error") from error
    if args.mode in ("version-cache", "cache-first"):
        from effect_slice import SliceFault
        try:
            if args.mode == "version-cache":
                from versioned_cache import compare_versioned_cache
                return compare_versioned_cache(read_bytes(args.source), text(args.model), strict_json(text(args.epochs)), strict_json(text(args.requests)))
            from cached_decision import compare_cached_decision
            return compare_cached_decision(read_bytes(args.source), text(args.model), text(args.policy))
        except SliceFault as error:
            raise AdmissionError("selected source returned typed failure: " + error.name, "source_error") from error
        except RuntimeError as error:
            raise AdmissionError("cache comparison runtime failed: " + type(error).__name__, "native_error") from error
    if args.mode == "domain-role-updates":
        from threadpool_roles import compare_domain_updates, native_domain_engine
        try:
            return compare_domain_updates(read_bytes(args.source), text(args.model), engine_factory=native_domain_engine)
        except RuntimeError as error:
            raise AdmissionError("domain-role comparison runtime failed: " + type(error).__name__, "native_error") from error
    if args.mode == "persistent-store":
        from persistent_store import compare_store
        try:
            return compare_store(read_bytes(args.source), text(args.model), strict_json(text(args.rows)),
                                 initial=args.initial_store, persistence=not args.memory_only, owned_explicit_save=args.owned_explicit_save)
        except RuntimeError as error:
            raise AdmissionError("file-store comparison runtime failed: " + type(error).__name__, "native_error") from error
    if args.mode == "historical-boundary":
        if args.interface == "post-transform-guard":
            from transform_guard import compare_transform_guard
            comparison = compare_transform_guard(read_bytes(args.source))
            return {**comparison["comparison"], "source_descriptor": comparison["descriptor"], "source_projection": comparison}
        from historical_boundary import compare_session_filter, compare_sync_permissions
        comparison = (compare_session_filter if args.interface == "session-filter" else compare_sync_permissions)(read_bytes(args.source))
        return {**comparison["result"], "source_descriptor": comparison["descriptor"], "source_projection": comparison}
    if args.mode == "snapshot-policy":
        from snapshot_policy import compare_snapshot
        return compare_snapshot(read_bytes(args.source), text(args.model), strict_json(text(args.rows)),
                                strict_json(text(args.owners)), strict_json(text(args.requests)), method=args.consumer)
    if args.mode == "yaml-policy":
        from yaml_policy import compare_yaml_policy, parse_yaml
        return compare_yaml_policy(read_bytes(args.source), text(args.model), text(args.policy), parse_yaml(text(args.yaml_policy)),
                                   strict_json(text(args.contexts)), strict_json(text(args.domain)))
    if args.mode == "family-diagnosis":
        from source_family import diagnose_source_family
        return diagnose_source_family(strict_json(text(args.reference_json)), strict_json(text(args.machine_json)))
    if args.mode == "call-handoff":
        from call_handoff import extract_call_handoff, project_handoff
        descriptor = extract_call_handoff(read_bytes(args.source), args.function, args.callee, args.parameters)
        return {"status": "projected_not_verified", "accepted": None, "source_descriptor": descriptor,
                "consumer_arguments": project_handoff(descriptor, strict_json(text(args.inputs))),
                "scope": "selected typed string handoff only; caller guards and receiver runtime binding unverified"}
    if args.mode == "return-contract":
        from return_contract import extract_tuple_contract, inspect_return_consumers, compare_boolean_guard
        contract = extract_tuple_contract(read_bytes(args.producer_source), args.producer_function)
        consumers = inspect_return_consumers(read_bytes(args.source), args.callee, contract)
        comparisons = []
        for guard in consumers["boolean_guards"]:
            try:
                comparisons.append({"line": guard["line"], **compare_boolean_guard(guard, contract)})
            except AdmissionError as error:
                comparisons.append({"line": guard["line"], "status": error.status, "accepted": None, "reason": str(error)})
        return {"status": "diagnosed", "accepted": None, "producer_contract": contract, "consumers": consumers,
                "comparisons": comparisons, "scope": "return shape and owned Boolean protocol; import bindings and route reachability separate",
                "whole_application_verified": False}
    if args.mode == "claim-boundary":
        from token_roles import compare_claim_boundary
        return compare_claim_boundary(read_bytes(args.source), read_bytes(args.enum_source), text(args.model), text(args.policy),
            strict_json(text(args.claims)), args.admin_role, not args.no_admin_bypass)
    if args.mode == "rest-application":
        from rest_source_chain import compare_rest_source_chain
        return compare_rest_source_chain(args.archive, args.settings, args.seed, strict_json(text(args.domain)))
    if args.mode == "relational-seed":
        from relational_policy import extract_relational_adapter, compile_relational_seed
        # Seed dumps have a separate four-MiB envelope; read_bytes intentionally
        # retains its smaller one-MiB source/config limit for every other input.
        with Path(args.seed).open("rb") as stream:
            seed = stream.read(4 * 1024 * 1024 + 1)
        descriptor = extract_relational_adapter(read_bytes(args.adapter_source), read_bytes(args.model_source), read_bytes(args.user_source))
        return compile_relational_seed(descriptor, seed)
    if args.mode == "source-paths":
        from source_paths import discover_authorization_paths
        return {**discover_authorization_paths(read_bytes(args.source)), "status": "discovered_not_verified", "accepted": None}
    if args.mode == "query-filter":
        from tenant_query import compare_query_filter
        return compare_query_filter(read_bytes(args.source))
    model = text(args.model)
    if args.mode == "rest-configuration":
        from rest_policy import compare_rest_policy
        rows = [[value.strip() for value in line.split(",")] for line in text(args.policy).splitlines() if line.strip() and not line.lstrip().startswith("#")]
        return compare_rest_policy(model, rows, strict_json(text(args.domain)))
    if args.mode == "tenant-configuration":
        from tenant_routes import compare_tenant_routes
        return compare_tenant_routes(model, text(args.policy))
    if args.mode == "tenant-lookup":
        from native_casbin import _engine
        from tenant_dependency import bind_tenant_dependency_source
        from tenant_lookup import compare_tenant_lookup
        from tenant_routes import admit_tenant_routes
        configuration = admit_tenant_routes(model, text(args.policy))
        return compare_tenant_lookup(read_bytes(args.source), args.function,
            bind_tenant_dependency_source(read_bytes(args.dependency_source)), _engine(configuration), read_bytes(args.query_source))
    if args.mode == "configuration":
        policy = text(args.policy)
        if args.domain:
            from finite_routes import compare_finite_routes
            return compare_finite_routes(model, policy, strict_json(text(args.domain)))
        return compare_native(model, policy)
    if args.mode == "wrapper":
        from python_wrapper import compare_wrapper
        return compare_wrapper(read_bytes(args.source), args.function, args.parameters, args.engine,
                               model, text(args.policy), line_syntax=args.policy_line_syntax)
    if args.mode == "request":
        from request_frontend import compare_request_frontend
        return compare_request_frontend(read_bytes(args.source), args.function, model,
                                        text(args.policy), strict_json(text(args.domain)))
    if args.mode == "request-scan":
        from frontend_scan import scan_request_frontends
        return scan_request_frontends(read_bytes(args.source), model, text(args.policy), strict_json(text(args.domain)))
    if args.mode == "cache":
        from policy_cache import export_policy_cache
        return export_policy_cache(model, strict_json(text(args.rows)), args.initial_store, args.initial_cache)
    if args.mode == "source-contract":
        from source_contracts import extract_contract, replay_contract
        contract = extract_contract(read_bytes(args.source), args.function, [args.model_alias])
        return replay_contract(contract, model)
    raise AdmissionError("unknown operation", "invalid")


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    modes = root.add_subparsers(dest="mode", required=True)
    for name in ("configuration", "wrapper", "request", "request-scan", "cache", "source-contract",
                 "tenant-configuration", "query-filter", "tenant-lookup", "source-paths", "relational-seed", "rest-configuration", "rest-application", "claim-boundary", "family-diagnosis", "call-handoff", "return-contract", "yaml-policy", "yaml-application", "snapshot-policy", "snapshot-application", "historical-boundary", "persistent-store", "domain-role-updates", "version-cache", "version-cache-application", "cache-first", "request-outcomes", "file-wrapper-application"):
        child = modes.add_parser(name)
        if name not in ("query-filter", "source-paths", "relational-seed", "rest-application", "family-diagnosis", "call-handoff", "return-contract", "historical-boundary", "yaml-application", "file-wrapper-application", "snapshot-application", "version-cache-application"):
            child.add_argument("--model", required=True)
        child.add_argument("--receipt", help="new JSON path; existing files are never replaced")
        if name == "version-cache-application":
            for field in ("archive", "epochs", "requests"):
                child.add_argument("--" + field, required=True)
            child.add_argument("--default-model", action="store_true", help="explicit absent model override premise")
            child.add_argument("--stable-epochs", action="store_true", help="explicit immutable epoch during each source invocation")
        if name == "file-wrapper-application":
            child.add_argument("--archive", required=True)
            child.add_argument("--ordered-method-contract", choices=("principal-resource-action",), required=True,
                help="explicit positional input roles, not inferred authentication semantics")
        if name == "snapshot-application":
            for field in ("archive", "rows", "owners", "requests"):
                child.add_argument("--" + field, required=True)
            child.add_argument("--ready-interface", action="store_true", help="explicit initialized, immutable snapshot precondition")
        if name in ("configuration", "wrapper", "request", "request-scan", "tenant-configuration", "tenant-lookup", "rest-configuration", "claim-boundary", "yaml-policy", "cache-first"):
            child.add_argument("--policy", required=True)
        if name in ("wrapper", "request", "source-contract", "tenant-lookup", "call-handoff"):
            child.add_argument("--source", required=True)
            child.add_argument("--function", required=True)
        if name == "request-scan":
            child.add_argument("--source", required=True)
        if name in ("query-filter", "source-paths"):
            child.add_argument("--source", required=True)
        if name == "tenant-lookup":
            child.add_argument("--dependency-source", required=True)
            child.add_argument("--query-source", required=True)
        if name == "relational-seed":
            for field in ("adapter-source", "model-source", "user-source", "seed"):
                child.add_argument("--" + field, required=True)
        if name in ("configuration", "request", "request-scan"):
            child.add_argument("--domain", required=name != "configuration")
        if name == "wrapper":
            child.add_argument("--parameters", nargs=3, required=True, metavar=("SUBJECT", "RESOURCE", "ACTION"))
            child.add_argument("--engine", required=True)
            child.add_argument("--policy-line-syntax", choices=("strict", "native-literals"), default="strict")
        if name == "cache":
            child.add_argument("--rows", required=True)
            child.add_argument("--initial-store", type=int, default=0)
            child.add_argument("--initial-cache", type=int, default=0)
        if name == "source-contract":
            child.add_argument("--model-alias", required=True)
        if name == "rest-configuration":
            child.add_argument("--domain", required=True)
        if name == "rest-application":
            for field in ("archive", "settings", "seed", "domain"):
                child.add_argument("--" + field, required=True)
        if name == "yaml-application":
            for field in ("archive", "contexts", "domain"):
                child.add_argument("--" + field, required=True)
        if name == "claim-boundary":
            for field in ("source", "enum-source", "claims", "admin-role"):
                child.add_argument("--" + field, required=True)
            child.add_argument("--no-admin-bypass", action="store_true")
        if name == "family-diagnosis":
            child.add_argument("--reference-json", required=True)
            child.add_argument("--machine-json", required=True)
        if name == "call-handoff":
            child.add_argument("--callee", required=True)
            child.add_argument("--parameters", nargs="+", required=True)
            child.add_argument("--inputs", required=True)
        if name == "return-contract":
            for field in ("source", "producer-source", "producer-function", "callee"):
                child.add_argument("--" + field, required=True)
        if name == "yaml-policy":
            for field in ("source", "yaml-policy", "contexts", "domain"):
                child.add_argument("--" + field, required=True)
        if name == "snapshot-policy":
            for field in ("source", "rows", "owners", "requests"):
                child.add_argument("--" + field, required=True)
            child.add_argument("--consumer", choices=("enforce", "check_permission"), default="check_permission")
        if name == "historical-boundary":
            child.add_argument("--source", required=True)
            child.add_argument("--interface", choices=("session-filter", "sync-permissions", "post-transform-guard"), required=True)
        if name == "persistent-store":
            child.add_argument("--source", required=True)
            child.add_argument("--rows", required=True)
            child.add_argument("--initial-store", type=int, default=0)
            child.add_argument("--memory-only", action="store_true")
            child.add_argument("--owned-explicit-save", action="store_true")
        if name == "domain-role-updates":
            child.add_argument("--source", required=True)
        if name in ("version-cache", "cache-first", "request-outcomes"):
            child.add_argument("--source", required=True)
        if name == "version-cache":
            child.add_argument("--epochs", required=True)
            child.add_argument("--requests", required=True)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        report = evaluate(args)
        if "accepted" not in report or report["accepted"] is not True and report["accepted"] is not False and report["accepted"] is not None:
            raise AdmissionError("evaluation lacks a typed comparison result", "invalid")
        report["input_paths"] = {key: str(Path(value).resolve()) for key, value in vars(args).items()
                                 if key in ("model", "policy", "source", "domain", "rows", "dependency_source", "query_source", "adapter_source", "model_source", "user_source", "archive", "seed", "enum_source", "claims", "reference_json", "machine_json", "producer_source", "inputs", "yaml_policy", "contexts", "owners", "requests", "epochs") and value and not (args.mode == "rest-application" and key == "seed")}
        report["runtime"] = {"python": sys.version.split()[0]}
        if args.mode == "query-filter":
            report["runtime"]["query"] = report["query_runtime"]
        elif args.mode == "relational-seed":
            import sqlite3
            report["runtime"]["owned_relational_reference_sqlite"] = sqlite3.sqlite_version
        elif args.mode not in ("source-paths", "family-diagnosis", "call-handoff", "return-contract", "historical-boundary"):
            from native_runtime import engine_identity
            report["runtime"]["engine"] = engine_identity()
        report["mode"] = args.mode
        code = 0 if report["accepted"] is True else 1 if report["accepted"] is False else 2
    except (AdmissionError, Rejected, PolicyError, OSError, UnicodeError, ValueError, TypeError, KeyError,
            RecursionError, ImportError) as error:
        status = getattr(error, "status", getattr(error, "kind", None))
        if status is None:
            status = ("missing_input" if isinstance(error, FileNotFoundError) else
                      "io_error" if isinstance(error, OSError) else
                      "inconclusive" if isinstance(error, PolicyError) and error.category == "LIMIT" else "invalid")
        report = {"mode": args.mode, "status": status, "accepted": None, "reason": str(error),
                  "scope": "no complete semantic comparison; input/admission failure retained",
                  "whole_application_verified": False}
        code = 2
    # Every handled outcome, including unsupported/missing/budget outcomes,
    # needs a receipt so batch denominators do not silently drop hard inputs.
    summary = {key: report[key] for key in ("mode", "status", "accepted", "scope", "counts", "reason",
                "native_enforce_calls", "native_reload_calls", "native_request_contexts", "assertions_checked",
                "candidate_functions", "functions_with_comparisons", "unsupported_or_inconclusive_functions", "native_select_executions")
               if key in report}
    if isinstance(summary.get("candidate_functions"), list):
        summary["candidate_functions"] = len(summary["candidate_functions"])
    if args.receipt:
        try:
            from policy import output
            output(args.receipt, report)
            summary.update(receipt=str(Path(args.receipt).resolve()), receipt_written=True)
        except (OSError, PolicyError, ValueError, UnicodeError) as error:
            summary = {"mode": args.mode, "status": "receipt_error", "accepted": None,
                       "evaluation_status": report["status"], "evaluation_accepted": report["accepted"],
                       "receipt_written": False, "reason": str(error)}
            code = 2
    print(json.dumps(summary, ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
