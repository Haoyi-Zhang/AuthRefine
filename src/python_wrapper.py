"""Translate a small pure Python authorization wrapper without importing it.

The caller supplies the semantic parameter mapping and the native engine
binding. Success is local to this function and its fixed configuration, not a
claim that every application entry point reaches it or that its caller supplies
an authenticated identity.
"""
from __future__ import annotations

import ast

from checker import verify_reachable
from native_casbin import AdmissionError, EXTRA_MATCHERS, MAX_NATIVE_WORK, _engine, admit_configuration
from public_inputs import translate


def dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted(node.value)
        return parent + "." + node.attr if parent else None
    return None


def extract_wrapper(source: str | bytes, function: str, parameters: list[str], engine: str) -> dict:
    if (not isinstance(parameters, list) or len(parameters) != 3 or
            not all(isinstance(x, str) and x for x in parameters) or len(set(parameters)) != 3):
        raise AdmissionError("supply three distinct principal/resource/action parameter names", "invalid")
    if not isinstance(engine, str) or not engine or engine.split(".")[0] in parameters:
        raise AdmissionError("engine and semantic request parameters must be distinct", "invalid")
    if len(source) > 1_048_576:
        raise AdmissionError("source input exceeds extraction envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, UnicodeError) as error:
        raise AdmissionError("source does not parse without guessed decoding", "invalid") from error
    current: ast.AST = tree
    for part in function.split("."):
        definitions = [node for node in getattr(current, "body", [])
                       if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == part]
        if len(definitions) != 1:
            raise AdmissionError("function path is missing or has multiple definitions")
        current = definitions[0]
    if not isinstance(current, ast.FunctionDef) or current.decorator_list:
        raise AdmissionError("only undecorated synchronous functions are admitted")
    names = [argument.arg for argument in current.args.posonlyargs + current.args.args]
    if current.args.vararg or current.args.kwarg or current.args.kwonlyargs or current.args.defaults:
        raise AdmissionError("variadic, keyword-only, or default argument semantics need a separate translation")
    if not set(parameters) <= set(names):
        raise AdmissionError("semantic parameters are not declared function parameters", "invalid")
    if engine.split(".")[0] not in names:
        raise AdmissionError("native engine binding must be an explicit function parameter")
    body = list(current.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        raise AdmissionError("wrapper has statements beyond the admitted pure return expression")

    def expression(node: ast.AST) -> dict:
        if isinstance(node, ast.Constant) and type(node.value) is bool:
            return {"operation": "boolean", "value": node.value}
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return {"operation": "not", "operand": expression(node.operand)}
        if isinstance(node, ast.Call) and dotted(node.func) == engine + ".enforce":
            if node.keywords or len(node.args) != 3:
                raise AdmissionError("native call must have exactly three positional arguments")
            arguments = []
            for argument in node.args:
                if isinstance(argument, ast.Name) and argument.id in parameters:
                    arguments.append({"parameter": argument.id})
                elif isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    arguments.append({"literal": argument.value})
                else:
                    raise AdmissionError("native argument needs unsupported dataflow or object decoding")
            return {"operation": "enforce", "arguments": arguments}
        raise AdmissionError("return expression is outside the pure native-wrapper fragment")

    result = expression(body[0].value)
    return {"function": function, "line": current.lineno, "end_line": current.end_lineno,
            "parameters": parameters, "engine_parameter": engine, "expression": result,
            "source_module_executed": False, "whole_application_verified": False}


def compare_wrapper(source: str | bytes, function: str, parameters: list[str], engine_parameter: str,
                    model_text: str, policy_text: str, *, line_syntax: str = "strict") -> dict:
    extraction = extract_wrapper(source, function, parameters, engine_parameter)
    if line_syntax == "strict":
        configuration = admit_configuration(model_text, policy_text)
    elif line_syntax == "native-literals":
        from native_literal_policy import admit_native_literals
        configuration = admit_native_literals(model_text, policy_text)
    else:
        raise AdmissionError("unknown policy line syntax", "invalid")
    if configuration.family == "rbac_with_domains":
        raise AdmissionError("four-field request wrappers need an explicit domain interface")
    if configuration.family in EXTRA_MATCHERS:
        raise AdmissionError("wildcard wrappers need an explicit finite request domain; literal-name conversion is not sufficient")
    policy = translate(configuration.family, configuration.rows)
    alphabet = [[u, o, a] for u in policy["principals"] for o in policy["resources"] for a in policy["actions"]]
    if len(alphabet) * max(1, len(configuration.rows)) > MAX_NATIVE_WORK:
        raise AdmissionError("native wrapper work envelope exceeded", "inconclusive")
    try:
        engine = _engine(configuration)
    except AdmissionError:
        raise
    except Exception as error:
        raise AdmissionError("native policy loading failed: " + type(error).__name__, "native_error") from error
    calls = 0

    def evaluate(expression: dict, environment: dict[str, str]) -> bool:
        nonlocal calls
        if expression["operation"] == "boolean":
            return expression["value"]
        if expression["operation"] == "not":
            return not evaluate(expression["operand"], environment)
        arguments = [environment[value["parameter"]] if "parameter" in value else value["literal"]
                     for value in expression["arguments"]]
        try:
            result = engine.enforce(*arguments)
        except Exception as error:
            raise AdmissionError("native wrapper evaluation failed: " + type(error).__name__, "native_error") from error
        if type(result) is not bool:
            raise AdmissionError("native authorization did not return a Boolean", "invalid")
        calls += 1
        return result

    transitions = [["allow" if evaluate(extraction["expression"], dict(zip(parameters, request))) else "deny", 0]
                   for request in alphabet]
    machine = {"state_names": [], "alphabet": alphabet, "observations": [0], "initial": 0,
               "transitions": [transitions]}
    comparison = verify_reachable(policy, machine)
    return {"status": comparison["status"], "accepted": comparison["accepted"],
            "scope": "isolated pure function under supplied parameter and native-engine contracts",
            "policy_line_syntax": line_syntax,
            "extraction": extraction, "native_enforce_calls": calls,
            "policy": policy, "machine": machine, "comparison": comparison,
            "application_security_verified": False}
