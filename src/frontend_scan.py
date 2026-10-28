"""Discover all enforce-containing functions, retaining unsupported outcomes.

This removes manual function selection for an admitted request-decoding source
file. It does not infer the outer authentication producer, runtime monkey
patches, model binding or a production request distribution.
"""
from __future__ import annotations

import ast

from language import PolicyError
from native_casbin import AdmissionError, MAX_NATIVE_WORK, MAX_TEXT_BYTES
from request_frontend import compare_request_frontend


def discover(source: bytes) -> list[dict]:
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("source scan exceeds input envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("unreadable source scan input", "invalid") from error
    candidates = []

    def direct_calls(node):
        pending = list(ast.iter_child_nodes(node))
        while pending:
            item = pending.pop()
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if (isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute)
                    and item.func.attr == "enforce"):
                yield item.lineno
            pending.extend(ast.iter_child_nodes(item))

    def definitions(body, prefix=""):
        for node in body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                selector = prefix + node.name
                if not isinstance(node, ast.ClassDef):
                    calls = sorted(direct_calls(node))
                    if calls:
                        candidates.append({"function": selector, "line": node.lineno,
                                           "end_line": node.end_lineno, "enforce_lines": calls})
                definitions(node.body, selector + ".")
            else:
                # Conditional definitions remain candidates even when the
                # exact-function translator cannot admit their runtime binding.
                definitions(list(ast.iter_child_nodes(node)), prefix)
    definitions(tree.body)
    if len(candidates) > 64:
        raise AdmissionError("too many candidate functions for one bounded scan", "inconclusive")
    return sorted(candidates, key=lambda item: (item["line"], item["function"]))


def scan_request_frontends(source: bytes, model_text: str, policy_text: str, domain: dict) -> dict:
    candidates = discover(source)
    if not candidates:
        return {"status": "unsupported", "accepted": None, "candidate_functions": 0,
                "reason": "no direct enforce-containing functions were found", "cases": [],
                "whole_application_verified": False}
    if not isinstance(domain, dict) or set(domain) != {"principals", "resources", "actions"}:
        raise AdmissionError("source scan needs an explicit finite request domain", "invalid")
    work = len(candidates)
    for values in domain.values():
        if not isinstance(values, list):
            raise AdmissionError("finite request domains must be lists", "invalid")
        work *= len(values)
    if 2 * work > MAX_NATIVE_WORK:
        raise AdmissionError("aggregate source scan request work exceeds its envelope", "inconclusive")
    reports = []
    for candidate in candidates:
        try:
            result = compare_request_frontend(source, candidate["function"], model_text, policy_text, domain)
        except (AdmissionError, PolicyError) as error:
            result = {"status": getattr(error, "status", "inconclusive" if getattr(error, "category", None) == "LIMIT" else "invalid"),
                      "accepted": None, "reason": str(error)}
        reports.append({**candidate, "result": result})
    completed = [item for item in reports if type(item["result"].get("accepted")) is bool]
    mismatches = [item for item in completed if item["result"]["accepted"] is False]
    # A partial scan never turns unsupported functions into an all-clear result.
    accepted = False if mismatches else True if len(completed) == len(reports) else None
    return {"status": "mismatch" if mismatches else "equivalent" if accepted is True else "partial",
            "accepted": accepted, "scope": "all direct enforce-containing source functions, under isolated decoder and fixed configuration contracts",
            "candidate_functions": len(candidates), "functions_with_comparisons": len(completed),
            "unsupported_or_inconclusive_functions": len(reports) - len(completed),
            "functions_with_mismatches": len(mismatches), "source_module_executed": False,
            "model_and_engine_binding_inferred": False, "whole_application_verified": False,
            "native_request_contexts": sum(item["result"].get("native_request_contexts", 0) for item in reports),
            "cases": reports}
