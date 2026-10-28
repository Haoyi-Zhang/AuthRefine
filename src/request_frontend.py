"""Interpret an admitted request-decoding method without importing its module.

Only typed reads, local assignments, explicit guards, and calls to reviewed
Request/user primitives and the pinned native enforcer are available. This is
not Python eval/exec, a general Python interpreter, or credential verification.
"""
from __future__ import annotations

import ast
import copy
from importlib.metadata import version
from types import SimpleNamespace

from checker import verify_reachable
from finite_routes import compare_finite_routes
from language import normalize
from native_casbin import AdmissionError, _engine, admit_configuration
from python_wrapper import dotted

_NO_RETURN = object()
_ALLOWED_NODES = (ast.Assign, ast.Name, ast.Load, ast.Store, ast.Attribute, ast.Subscript, ast.Call, ast.Constant,
                  ast.Return, ast.Expr, ast.If, ast.IfExp, ast.Raise, ast.Assert, ast.Compare,
                  ast.In, ast.NotIn, ast.Eq, ast.NotEq, ast.UnaryOp, ast.Not, ast.BoolOp, ast.And, ast.Or)
_CALLS = {"Request", "isinstance", "RuntimeError", "self.enforcer.enforce"}
_RESERVED = {"Request", "BaseUser", "RuntimeError", "isinstance"}


def extract_frontend(source: str | bytes, function: str) -> ast.FunctionDef:
    if len(source) > 1_048_576:
        raise AdmissionError("request source exceeds extraction envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, UnicodeError, ValueError) as error:
        raise AdmissionError("request source cannot be parsed without guessed decoding", "invalid") from error
    imports = {alias.asname or alias.name: (node.module, alias.name)
               for node in tree.body if isinstance(node, ast.ImportFrom) for alias in node.names}
    if imports.get("Request") != ("starlette.requests", "Request") or imports.get("BaseUser") != ("starlette.authentication", "BaseUser"):
        raise AdmissionError("request and user primitives do not have admitted import bindings")
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            raise AdmissionError("star imports leave request primitive bindings unresolved")
        if isinstance(node, ast.Import) and any((alias.asname or alias.name.split(".")[0]) in _RESERVED for alias in node.names):
            raise AdmissionError("module import rebinds a trusted request primitive")
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in _RESERVED:
            raise AdmissionError("module definition rebinds a trusted request primitive")
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id in _RESERVED for target in targets):
                raise AdmissionError("module rebinds a trusted request primitive")
    current = tree
    for part in function.split("."):
        matches = [node for node in current.body if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name == part]
        if len(matches) != 1:
            raise AdmissionError("request method path is missing or ambiguous")
        current = matches[0]
    if not isinstance(current, ast.FunctionDef) or current.decorator_list:
        raise AdmissionError("only undecorated synchronous request methods are admitted")
    args = current.args
    if ([argument.arg for argument in args.posonlyargs + args.args] != ["self", "scope", "receive"] or
            args.defaults or args.kwonlyargs or args.vararg or args.kwarg):
        raise AdmissionError("request method has an unsupported argument interface")
    for statement in current.body:
        for node in ast.walk(statement):
            if not isinstance(node, _ALLOWED_NODES):
                raise AdmissionError("request method contains unsupported syntax: " + type(node).__name__)
            if isinstance(node, ast.Call) and (dotted(node.func) not in _CALLS or node.keywords):
                raise AdmissionError("request method calls an unmodeled function")
            if isinstance(node, ast.Call):
                arity = {"Request": 2, "isinstance": 2, "RuntimeError": 1, "self.enforcer.enforce": 3}[dotted(node.func)]
                if len(node.args) != arity:
                    raise AdmissionError("request primitive has an unsupported argument count")
            if isinstance(node, ast.Constant) and node.value is not None and type(node.value) not in (str, bool):
                raise AdmissionError("request method contains an unsupported literal")
            if isinstance(node, ast.Raise) and (node.exc is None or node.cause is not None):
                raise AdmissionError("bare or chained request exceptions require a separate translation")
            if isinstance(node, ast.Assign) and (len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name)
                                                or node.targets[0].id in _RESERVED):
                raise AdmissionError("only local, nonreserved request variables may be assigned")
    return current


def evaluate_frontend(function: ast.FunctionDef, scope: dict, engine) -> bool:
    try:
        from starlette.authentication import BaseUser, SimpleUser, UnauthenticatedUser
        from starlette.datastructures import URL
        from starlette.requests import Request
    except ImportError as error:
        raise AdmissionError("install the pinned request-runtime dependencies", "dependency_missing") from error
    if version("starlette") != "1.10.0":
        raise AdmissionError("request comparison requires the recorded Starlette dependency", "dependency_missing")
    environment = {"scope": scope, "self": SimpleNamespace(enforcer=engine),
                   "receive": None, "BaseUser": BaseUser}

    def boolean(value):
        if type(value) is not bool:
            raise AdmissionError("request branch is not a Boolean", "invalid")
        return value

    def value(node):
        if isinstance(node, ast.Constant):
            if node.value is None or type(node.value) in (str, bool):
                return node.value
            raise AdmissionError("unsupported request literal")
        if isinstance(node, ast.Name):
            if node.id not in environment:
                raise AdmissionError("request reads an unbound variable: " + node.id)
            return environment[node.id]
        if isinstance(node, ast.Attribute):
            owner = value(node.value)
            allowed = ((type(owner) is Request and node.attr in ("url", "method", "user")) or
                       (type(owner) is URL and node.attr == "path") or
                       (type(owner) in (SimpleUser, UnauthenticatedUser) and node.attr in ("is_authenticated", "display_name")) or
                       (type(owner) is SimpleNamespace and node.attr == "enforcer"))
            if not allowed:
                raise AdmissionError("request attribute is outside the observed interface")
            return getattr(owner, node.attr)
        if isinstance(node, ast.Subscript):
            container, key = value(node.value), value(node.slice)
            if type(container) is not dict or type(key) is not str:
                raise AdmissionError("request subscription is not a named scope field")
            if key not in container:
                raise AdmissionError("request scope lacks a required field: " + key, "input_rejected")
            return container[key]
        if isinstance(node, ast.IfExp):
            return value(node.body if boolean(value(node.test)) else node.orelse)
        if isinstance(node, ast.UnaryOp):
            return not boolean(value(node.operand))
        if isinstance(node, ast.Compare):
            if len(node.ops) != 1 or len(node.comparators) != 1:
                raise AdmissionError("chained scope comparisons require a separate translation")
            left, right, operation = value(node.left), value(node.comparators[0]), node.ops[0]
            if isinstance(operation, (ast.In, ast.NotIn)):
                if type(left) is not str or type(right) is not dict:
                    raise AdmissionError("membership is limited to named scope fields")
                return left in right if isinstance(operation, ast.In) else left not in right
            return left == right if isinstance(operation, ast.Eq) else left != right
        if isinstance(node, ast.BoolOp):
            for item in node.values:
                result = boolean(value(item))
                if isinstance(node.op, ast.And) and not result:
                    return False
                if isinstance(node.op, ast.Or) and result:
                    return True
            return isinstance(node.op, ast.And)
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            arguments = [value(argument) for argument in node.args]
            if name == "Request" and len(arguments) == 2:
                return Request(*arguments)
            if name == "isinstance" and len(arguments) == 2 and arguments[1] is BaseUser:
                return isinstance(arguments[0], BaseUser)
            if name == "RuntimeError" and len(arguments) == 1 and type(arguments[0]) is str:
                return RuntimeError(arguments[0])
            if name == "self.enforcer.enforce" and len(arguments) == 3 and all(type(item) is str for item in arguments):
                if value(node.func.value) is not engine:
                    raise AdmissionError("native call receiver no longer matches its supplied binding")
                return engine.enforce(*arguments)
            raise AdmissionError("request calls a primitive outside its typed interface")
        raise AdmissionError("unhandled request expression")

    def statements(body):
        for statement in body:
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant) and type(statement.value.value) is str:
                continue
            if isinstance(statement, ast.Assign):
                environment[statement.targets[0].id] = value(statement.value)
            elif isinstance(statement, ast.If):
                result = statements(statement.body if boolean(value(statement.test)) else statement.orelse)
                if result is not _NO_RETURN:
                    return result
            elif isinstance(statement, ast.Assert):
                if not boolean(value(statement.test)):
                    raise AdmissionError("request violates the asserted input interface", "input_rejected")
            elif isinstance(statement, ast.Raise):
                error = value(statement.exc)
                if not isinstance(error, RuntimeError):
                    raise AdmissionError("unsupported request exception")
                raise AdmissionError(str(error), "input_rejected")
            elif isinstance(statement, ast.Return):
                return boolean(value(statement.value))
            else:
                raise AdmissionError("unhandled request statement")
        return _NO_RETURN

    try:
        result = statements(function.body)
    except AdmissionError:
        raise
    except Exception as error:
        raise AdmissionError("native request primitive failed: " + type(error).__name__, "input_rejected") from error
    if result is _NO_RETURN:
        raise AdmissionError("request method has no completed Boolean result")
    return result


def compare_request_frontend(source: str | bytes, function_name: str, model_text: str,
                             policy_text: str, domain: dict[str, list[str]]) -> dict:
    from starlette.authentication import SimpleUser, UnauthenticatedUser
    function = extract_frontend(source, function_name)
    base = compare_finite_routes(model_text, policy_text, domain)
    source_policy = base["policy"]
    configuration = admit_configuration(model_text, policy_text)
    if "anonymous" not in source_policy["principals"]:
        raise AdmissionError("include the declared anonymous identity in the finite user interface")
    engine = _engine(configuration)
    rules = []
    for rule in source_policy["rules"]:
        rules.append({**copy.deepcopy(rule), "guard": [
            {"field": "state", "name": "authenticated", "value": True}] + copy.deepcopy(rule["guard"])})
        kept, permitted = [], True
        for atom in rule["guard"]:
            if atom["field"] in ("principal", "role"):
                truth = (atom["name"] == "anonymous" if atom["field"] == "principal" else
                         ["anonymous", atom["name"]] in source_policy["members"])
                permitted &= not truth if atom["negated"] else truth
            else:
                kept.append(copy.deepcopy(atom))
        if permitted:
            rules.append({**copy.deepcopy(rule), "guard": [
                {"field": "state", "name": "authenticated", "value": False}] + kept})
    expected = normalize({**copy.deepcopy(source_policy), "state": [["authenticated", False]], "rules": rules})
    alphabet = base["machine"]["alphabet"]
    rows = []
    for authenticated in (False, True):
        transitions = []
        for user, path, action in alphabet:
            scope = {"type": "http", "method": action, "path": path, "scheme": "http", "headers": [],
                     "server": ("example.test", 80), "query_string": b"",
                     "user": SimpleUser(user) if authenticated else UnauthenticatedUser()}
            decision = evaluate_frontend(function, scope, engine)
            transitions.append(["allow" if decision else "deny", int(authenticated)])
        rows.append(transitions)
    machine = {"state_names": ["authenticated"], "alphabet": alphabet, "observations": [0, 1],
               "initial": 0, "transitions": rows}
    comparisons = []
    for initial in (False, True):
        expected["state"] = [["authenticated", initial]]
        machine["initial"] = int(initial)
        comparisons.append(verify_reachable(expected, machine))
    return {"status": "equivalent" if all(row["accepted"] for row in comparisons) else "mismatch",
            "accepted": all(row["accepted"] for row in comparisons),
            "source_function": function_name, "source_lines": [function.lineno, function.end_lineno],
            "source_module_executed": False, "native_request_contexts": 2 * len(alphabet),
            "request_runtime": "Starlette 1.10.0",
            "global_primitives_and_engine_binding": "supplied isolated-function contract; not a whole-module execution proof",
            "scope": "admitted HTTP decoding method; supplied authenticated/anonymous user contexts; explicit finite routes",
            "authentication_producer_verified": False, "outer_dispatch_and_all_entry_points_verified": False,
            "comparisons": comparisons}
