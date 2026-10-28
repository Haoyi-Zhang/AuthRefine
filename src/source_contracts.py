"""Extract literal upstream test contracts without importing their test modules.

This small language admits fixture initialization, producer changes, explicit
reloads and literal Boolean assertions. An owned set-store substitutes for the
upstream database adapter; this checks the published contract against native
Casbin, NOT the database adapter or the surrounding application's correctness.
"""
from __future__ import annotations

import ast

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from policy_cache import PolicySnapshot


def _literal(node):
    if sum(1 for _ in ast.walk(node)) > 4096:
        raise AdmissionError("literal contract exceeds syntax envelope", "inconclusive")
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError, RecursionError) as error:
        raise AdmissionError("contract values must be source literals") from error


def _method(node, receiver, operation):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == receiver
            and node.func.attr == operation)


def extract_contract(source: bytes, selector: str, model_aliases: list[str]) -> dict:
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("test source exceeds syntax envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, RecursionError, ValueError) as error:
        raise AdmissionError("invalid test source", "invalid") from error
    parts = selector.split(".")
    body = tree.body
    if len(parts) == 2:
        classes = [node for node in body if isinstance(node, ast.ClassDef) and node.name == parts[0]]
        if len(classes) != 1:
            raise AdmissionError("test class is not unique")
        body = classes[0].body
    elif len(parts) != 1:
        raise AdmissionError("test selector must identify a top-level or class function")
    functions = [node for node in body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == parts[-1]]
    if len(functions) != 1 or not isinstance(functions[0], ast.FunctionDef):
        raise AdmissionError("test function is not unique")
    function = functions[0]
    args = function.args
    if (function.decorator_list or args.vararg or args.kwarg or args.kwonlyargs or args.defaults
            or args.posonlyargs or [arg.arg for arg in args.args] != ["self"]):
        raise AdmissionError("test function requires a separate fixture/parameter conversion")
    statements = function.body[:]
    if statements and isinstance(statements[0], ast.Expr) and isinstance(statements[0].value, ast.Constant) and isinstance(statements[0].value.value, str):
        statements.pop(0)
    if not statements or len(statements) > 512:
        raise AdmissionError("test statement envelope", "inconclusive")
    first = statements.pop(0)
    if not (isinstance(first, ast.Assign) and len(first.targets) == 1 and isinstance(first.targets[0], ast.Name)
            and _method(first.value, "self", "get_enforcer") and not first.value.args):
        raise AdmissionError("contract must start with the declared enforcer fixture")
    enforcer = first.targets[0].id
    if enforcer == "self":
        raise AdmissionError("fixture receiver cannot be rebound")
    keywords = {item.arg: item.value for item in first.value.keywords}
    if len(keywords) != len(first.value.keywords) or set(keywords) != {"conf_file", "policies"}:
        raise AdmissionError("fixture requires exactly model and policy references")
    model, policies = keywords["conf_file"], keywords["policies"]
    if not isinstance(model, ast.Name) or model.id not in model_aliases or not isinstance(policies, ast.Name):
        raise AdmissionError("fixture identifiers need declared source-model bindings")
    # This is extraction of the literal table in a snapshot, not execution of
    # all module-level assignments or a claim about runtime mutation of it.
    definitions = [node for node in tree.body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == policies.id]
    if len(definitions) != 1:
        raise AdmissionError("literal policy table must be unique")
    table = _literal(definitions[0].value)
    if not isinstance(table, list) or len(table) > 512:
        raise AdmissionError("invalid or oversized literal policy table", "invalid")
    rows = []
    for entry in table:
        if (not isinstance(entry, (list, tuple)) or len(entry) != 3
                or entry[0] not in ("p", "g") or not isinstance(entry[1], str)
                or not entry[1].startswith(entry[0]) or not isinstance(entry[2], (list, tuple))
                or not all(isinstance(value, str) for value in entry[2])):
            raise AdmissionError("invalid typed policy table entry", "invalid")
        rows.append([entry[1], *entry[2]])
    operations = []
    adapter = None
    result_names = set()
    for statement in statements:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
            target, call = statement.targets[0].id, statement.value
            if target in {"self", enforcer, adapter} or target in result_names:
                raise AdmissionError("contract identifiers cannot be rebound")
            if _method(call, enforcer, "get_adapter") and not call.args and not call.keywords and adapter is None:
                adapter = target
                continue
            op = call.func.attr if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) else None
            if adapter is None or op not in ("add_policy", "remove_policy") or not _method(call, adapter, op) or call.args:
                raise AdmissionError("assignment is outside the literal producer contract")
            fields = {item.arg: item.value for item in call.keywords}
            if len(fields) != len(call.keywords) or set(fields) != {"sec", "ptype", "rule"}:
                raise AdmissionError("producer change needs complete literal typed fields")
            operations.append({"operation": op, "section": _literal(fields["sec"]),
                               "kind": _literal(fields["ptype"]), "fields": _literal(fields["rule"]),
                               "result_name": target, "source_line": statement.lineno})
            result_names.add(target)
        elif isinstance(statement, ast.Expr) and _method(statement.value, enforcer, "load_policy") and not statement.value.args and not statement.value.keywords:
            operations.append({"operation": "reload", "source_line": statement.lineno})
        elif isinstance(statement, ast.Assert) and statement.msg is None:
            test = statement.test
            if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Is)
                    and len(test.comparators) == 1 and isinstance(test.comparators[0], ast.Constant)
                    and type(test.comparators[0].value) is bool):
                raise AdmissionError("only literal Boolean identity assertions are admitted")
            expected = test.comparators[0].value
            if isinstance(test.left, ast.Name) and test.left.id in result_names:
                operations.append({"operation": "assert_result", "result_name": test.left.id,
                                   "expected": expected, "source_line": statement.lineno})
            elif _method(test.left, enforcer, "enforce") and not test.left.keywords and len(test.left.args) == 3:
                request = [_literal(value) for value in test.left.args]
                if any(not isinstance(value, str) for value in request):
                    raise AdmissionError("native contract request needs three strings")
                operations.append({"operation": "assert_enforce", "request": request,
                                   "expected": expected, "source_line": statement.lineno})
            else:
                raise AdmissionError("assertion value is outside the supported contract")
        else:
            raise AdmissionError("unsupported statement at test line " + str(statement.lineno))
    if not any(op["operation"].startswith("assert_") for op in operations):
        raise AdmissionError("contract has no source assertions")
    return {"selector": selector, "model_alias": model.id, "policy_constant": policies.id,
            "source_start": function.lineno, "source_end": function.end_lineno,
            "initial_rows": rows, "operations": operations,
            "fixture_contract": "caller supplies literal model binding and Enforcer construction; upstream database implementation is not executed"}


def replay_contract(contract: dict, model_text: str) -> dict:
    if (not isinstance(contract, dict) or not isinstance(contract.get("operations"), list)
            or not 1 <= len(contract["operations"]) <= 512
            or not any(op.get("operation") in ("assert_enforce", "assert_result")
                       for op in contract["operations"] if isinstance(op, dict))):
        raise AdmissionError("replay requires bounded operations with source assertions", "invalid")
    snapshot = PolicySnapshot(model_text, contract["initial_rows"])
    values, assertions, trace = {}, [], []
    try:
        for operation in contract["operations"]:
            kind = operation["operation"]
            entry = dict(operation)
            if kind in ("add_policy", "remove_policy"):
                values[operation["result_name"]] = snapshot.update(kind, operation["section"], operation["kind"], operation["fields"])
                entry["observed"] = values[operation["result_name"]]
            elif kind == "reload":
                snapshot.reload()
            elif kind in ("assert_enforce", "assert_result"):
                observed = (snapshot.enforce(operation["request"]) if kind == "assert_enforce"
                            else values[operation["result_name"]])
                entry.update(observed=observed, matches=observed is operation["expected"])
                assertions.append(entry)
            else:
                raise AdmissionError("unknown extracted contract operation", "invalid")
            trace.append(entry)
    except AdmissionError:
        raise
    except Exception as error:
        raise AdmissionError("native contract replay failed: " + type(error).__name__, "native_error") from error
    return {"status": "agreement" if all(item["matches"] for item in assertions) else "mismatch",
            "accepted": all(item["matches"] for item in assertions), "assertions_checked": len(assertions),
            "native_enforce_calls": snapshot.native_enforce_calls, "native_reload_calls": snapshot.native_reload_calls,
            "expected_behavior_source": "literal assertions extracted from upstream source, not native decisions",
            "database_adapter_verified": False, "whole_application_verified": False,
            "contract": contract, "trace": trace}
