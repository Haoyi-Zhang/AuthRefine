"""Passive nonempty-tuple/Boolean protocol checks on selected source boundaries.

Only ASTs and owned typed return records are interpreted. This does not execute
an application, certify route reachability or establish exploitability.
"""
import ast
import itertools

from checker import verify_reachable
from language import normalize
from native_casbin import AdmissionError, MAX_TEXT_BYTES
from python_wrapper import dotted


def parse(source):
    if len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("return-contract source exceeds input envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, UnicodeError, RecursionError) as error:
        raise AdmissionError("return-contract source does not parse", "invalid") from error
    if sum(1 for _ in ast.walk(tree)) > 50000:
        raise AdmissionError("return-contract AST envelope exceeded", "inconclusive")
    return tree


def local_nodes(scope):
    yield scope
    for child in ast.iter_child_nodes(scope):
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            yield from local_nodes(child)


def extract_tuple_contract(source, function):
    scope = parse(source)
    for part in function.split("."):
        candidates = [node for node in scope.body if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == part]
        if len(candidates) != 1:
            raise AdmissionError("tuple producer is missing or ambiguous")
        scope = candidates[0]
    if not isinstance(scope, ast.FunctionDef) or scope.decorator_list:
        raise AdmissionError("tuple producer must be an undecorated synchronous function")
    nodes = list(local_nodes(scope))
    returns = [node for node in nodes if isinstance(node, ast.Return)]
    if (not returns or not isinstance(scope.body[-1], ast.Return) or
            any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in nodes) or
            any(not isinstance(node.value, ast.Tuple) or any(isinstance(item, ast.Starred) for item in node.value.elts) for node in returns)):
        raise AdmissionError("all normal producer returns need explicit fixed nonempty tuples")
    arities = {len(node.value.elts) for node in returns}
    if len(arities) != 1 or not 1 <= next(iter(arities)) <= 8:
        raise AdmissionError("producer tuple arity is empty, inconsistent or outside the bounded contract")
    return {"producer": function, "line": scope.lineno, "tuple_arity": next(iter(arities)),
            "normal_return_lines": [node.lineno for node in returns],
            "truthiness_on_normal_return": True, "source_module_executed": False,
            "exceptions_and_runtime_rebinding_verified": False}


def inspect_return_consumers(source, callee, contract):
    tree = parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and dotted(node.func) == callee]
    if len(calls) > 256:
        raise AdmissionError("consumer call envelope exceeded", "inconclusive")
    call_ids = {node: index for index, node in enumerate(calls)}
    ambiguous = set()
    root = callee.split(".")[0]
    for call in calls:
        current = parents.get(call)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                args = current.args
                names = {arg.arg for arg in args.posonlyargs + args.args + args.kwonlyargs}
                names.update(arg.arg for arg in (args.vararg, args.kwarg) if arg is not None)
                if root in names or any(isinstance(node, ast.Name) and node.id == root and
                        isinstance(node.ctx, (ast.Store, ast.Del)) for node in local_nodes(current)):
                    ambiguous.add(call)
            current = parents.get(current)

    def expression(node):
        if node in call_ids:
            if node in ambiguous:
                raise AdmissionError("selected receiver is shadowed or rebound in the caller scope")
            return {"operation": "tuple_call", "call": call_ids[node]}
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return {"operation": "not", "operand": expression(node.operand)}
        if isinstance(node, ast.BoolOp):
            return {"operation": "and" if isinstance(node.op, ast.And) else "or", "operands": [expression(item) for item in node.values]}
        if isinstance(node, ast.Constant) and type(node.value) is bool:
            return {"operation": "literal", "value": node.value}
        raise AdmissionError("Boolean consumer test contains an unresolved operation")

    guards, covered, opaque = [], set(), []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            continue
        relevant = [call for call in calls if call in set(ast.walk(node.test))]
        if not relevant:
            continue
        try:
            descriptor = expression(node.test)
        except AdmissionError as error:
            opaque.append({"line": node.lineno, "reason": str(error)})
            continue
        if len(relevant) > 8:
            opaque.append({"line": node.lineno, "reason": "Boolean decision family exceeds bounded input domain"})
            continue
        ids = [call_ids[call] for call in relevant]
        guards.append({"line": node.lineno, "end_line": node.end_lineno, "call_ids": ids, "expression": descriptor,
                       "scope": "normal returned-tuple observation at the selected Boolean test; surrounding route not executed"})
        covered.update(ids)
    unpacked, other = [], []
    for call, index in call_ids.items():
        parent = parents.get(call)
        if (isinstance(parent, ast.Assign) and parent.value is call and len(parent.targets) == 1
                and isinstance(parent.targets[0], (ast.Tuple, ast.List)) and len(parent.targets[0].elts) == contract["tuple_arity"]
                and all(isinstance(item, ast.Name) for item in parent.targets[0].elts)):
            if call in ambiguous:
                other.append({"call": index, "line": call.lineno, "status": "consumer_binding_ambiguous"})
            else:
                unpacked.append({"call": index, "line": call.lineno, "targets": [item.id for item in parent.targets[0].elts]})
        elif index not in covered:
            other.append({"call": index, "line": call.lineno, "status": "consumer_use_not_admitted"})
    return {"callee": callee, "calls": [{"id": index, "line": node.lineno, "end_line": node.end_lineno} for node, index in call_ids.items()],
            "boolean_guards": guards, "unpacked_calls": unpacked, "other_calls": other, "opaque_guards": opaque,
            "source_module_executed": False, "whole_application_verified": False}


def compare_boolean_guard(guard, contract):
    """Own finite guard protocol: actual tuple truth vs declared decision field.

    A counterexample concerns the interface only. It is not an upstream request,
    live credential, HTTP response, or completed vulnerability reproduction.
    """
    ids = guard["call_ids"]
    if not 1 <= len(ids) <= 4 or contract["tuple_arity"] < 1:
        raise AdmissionError("guard comparison exceeds the finite interface envelope", "inconclusive")
    records = list(itertools.product((False, True), repeat=len(ids)))

    def evaluate(node, decisions, tuple_observation):
        kind = node["operation"]
        if kind == "tuple_call":
            if tuple_observation:
                # Constructed owned tuple, not an imported producer invocation.
                record = (decisions[node["call"]],) + (None,) * (contract["tuple_arity"] - 1)
                return bool(record)
            return decisions[node["call"]]
        if kind == "not":
            return not evaluate(node["operand"], decisions, tuple_observation)
        if kind in ("and", "or"):
            values = [evaluate(item, decisions, tuple_observation) for item in node["operands"]]
            return all(values) if kind == "and" else any(values)
        if kind == "literal":
            return node["value"]
        raise AdmissionError("unreviewed Boolean observation operation", "invalid")
    names = ["decisions:" + "".join("1" if value else "0" for value in record) for record in records]
    policy = {"principals": names, "resources": ["guard"], "actions": ["evaluate"], "roles": [], "members": [], "state": [], "aliases": [], "rules": []}
    observations = []
    for name, record in zip(names, records):
        values = dict(zip(ids, record))
        expected = evaluate(guard["expression"], values, False)
        actual = evaluate(guard["expression"], values, True)
        if expected:
            policy["rules"].append({"decision": "allow", "guard": [{"field": "principal", "name": name, "negated": False}], "updates": []})
        observations.append({"input": list(record), "reference_test": expected, "tuple_observed_test": actual})
    policy = normalize(policy)
    by_name = dict(zip(names, observations))
    machine = {"state_names": [], "alphabet": [[name, "guard", "evaluate"] for name in policy["principals"]], "observations": [0], "initial": 0,
               "transitions": [[["allow" if by_name[name]["tuple_observed_test"] else "deny", 0] for name in policy["principals"]]]}
    result = verify_reachable(policy, machine)
    return {"status": result["status"], "accepted": result["accepted"], "comparison": result, "observations": observations,
            "policy": policy, "machine": machine,
            "scope": "owned typed producer/consumer return protocol, not execution or exploitation of the source application"}
