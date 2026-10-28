"""Interpret a bounded authorization dependency slice, never an app module.

Trusted inputs are already-validated authentication records, a native engine
bound to fixed configuration, and a request path. Token validation, application
startup, database code and endpoint effects are outside this interface.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

from native_casbin import AdmissionError, MAX_TEXT_BYTES


@dataclass(frozen=True)
class AuthInput:
    kind: str
    role: str
    permissions: tuple[str, ...]
    scopes: tuple[str, ...]
    username: str = "study-user"


class SourceFault(Exception):
    """An observed/injected application exception, NOT an admission failure."""


class HTTPDenied(SourceFault):
    def __init__(self, status, detail):
        self.status = status
        super().__init__(detail)


@dataclass(frozen=True)
class Primitive:
    name: str


@dataclass(frozen=True)
class SourceFunction:
    name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    module: str


@dataclass(frozen=True)
class Dependency:
    factory: str
    argument_name: str
    initializer: tuple[ast.stmt, ...]
    function: SourceFunction


_NODES = (ast.Assign, ast.Return, ast.If, ast.Raise, ast.Try, ast.ExceptHandler,
          ast.ImportFrom, ast.Expr, ast.Pass, ast.Name, ast.Constant, ast.Attribute,
          ast.Call, ast.keyword, ast.Await, ast.Subscript, ast.IfExp, ast.UnaryOp,
          ast.Not, ast.Compare, ast.BoolOp, ast.And, ast.Or, ast.Eq, ast.NotEq,
          ast.Is, ast.IsNot, ast.In, ast.NotIn, ast.Gt, ast.GtE, ast.Lt, ast.LtE,
          ast.List, ast.Tuple, ast.Dict, ast.JoinedStr, ast.FormattedValue,
          ast.Load, ast.Store, ast.alias)


def _parse(source):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("dependency source exceeds its byte envelope", "inconclusive")
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("dependency source cannot be parsed", "invalid") from error


def _function(tree, name):
    matches = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]
    if len(matches) != 1 or matches[0].decorator_list:
        raise AdmissionError("source function must be unique and undecorated")
    return matches[0]


def _admit(body):
    nodes = [n for statement in body for n in ast.walk(statement)]
    if len(nodes) > 4096:
        raise AdmissionError("dependency slice exceeds syntax envelope", "inconclusive")
    for node in nodes:
        if not isinstance(node, _NODES):
            raise AdmissionError("unsupported dependency syntax: " + type(node).__name__)
        if isinstance(node, ast.Assign) and (len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name)):
            raise AdmissionError("dependency assignments must bind one local name")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id not in ("get_current_auth", "isinstance", "len", "HTTPException", "_check_with_casbin", "check_permission", "get_enforcer"):
                    raise AdmissionError("call is outside the dependency primitive vocabulary")
            elif not isinstance(node.func, ast.Attribute) or node.func.attr not in ("enforce", "strip", "split", "get", "debug"):
                raise AdmissionError("method call is outside the dependency primitive vocabulary")
        if isinstance(node, ast.Try) and (node.orelse or node.finalbody or len(node.handlers) != 1
                                         or not isinstance(node.handlers[0].type, ast.Name)
                                         or node.handlers[0].type.id != "Exception"):
            raise AdmissionError("only the declared Exception fallback is admitted")
        if isinstance(node, ast.ImportFrom) and not (node.level == 2 and node.module == "auth.rbac"
                 and [(n.name, n.asname) for n in node.names] == [("check_permission", None)]):
            raise AdmissionError("source import lacks a reviewed cross-module binding")
        if isinstance(node, ast.Raise) and (node.exc is None or node.cause is not None):
            raise AdmissionError("implicit or chained dependency raise is unsupported")
        if isinstance(node, ast.FormattedValue) and (node.conversion != -1 or node.format_spec is not None):
            raise AdmissionError("formatted dependency value needs a separate conversion")


def extract_dependency(source: bytes, factory: str, module="api.auth") -> Dependency:
    outer = _function(_parse(source), factory)
    args = outer.args
    if (not isinstance(outer, ast.FunctionDef) or len(args.args) != 1 or args.posonlyargs
            or args.vararg or args.kwarg or args.kwonlyargs or args.defaults):
        raise AdmissionError("dependency factory must have one explicit argument")
    statements = list(outer.body)
    if statements and isinstance(statements[0], ast.Expr) and isinstance(statements[0].value, ast.Constant) and isinstance(statements[0].value.value, str):
        statements.pop(0)
    nested = [n for n in statements if isinstance(n, ast.AsyncFunctionDef)]
    if (len(nested) != 1 or not isinstance(statements[-1], ast.Return)
            or not isinstance(statements[-1].value, ast.Name) or statements[-1].value.id != nested[0].name
            or statements[-2] is not nested[0]):
        raise AdmissionError("factory must return its single asynchronous dependency")
    function = nested[0]
    a = function.args
    if (function.decorator_list or [n.arg for n in a.args] != ["request", "api_key"]
            or a.posonlyargs or a.vararg or a.kwarg or a.kwonlyargs or len(a.defaults) != 1):
        raise AdmissionError("dependency request/provider interface is unsupported")
    default = a.defaults[0]
    if not (isinstance(default, ast.Call) and isinstance(default.func, ast.Name) and default.func.id == "Security"
            and len(default.args) == 1 and isinstance(default.args[0], ast.Name)
            and default.args[0].id == "api_key_header" and not default.keywords):
        raise AdmissionError("dependency injection default is not the declared header contract")
    initializer = tuple(statements[:-2])
    if any(not isinstance(n, ast.Assign) for n in initializer):
        raise AdmissionError("factory initialization is outside the pure slice")
    _admit([*initializer, *function.body])
    return Dependency(factory, args.args[0].arg, initializer, SourceFunction(factory + "." + function.name, function, module))


def extract_function(source, name, module):
    function = _function(_parse(source), name)
    a = function.args
    if (not isinstance(function, ast.FunctionDef) or a.posonlyargs or a.vararg or a.kwarg or a.kwonlyargs or a.defaults):
        raise AdmissionError("source helper interface is unsupported")
    _admit(function.body)
    return SourceFunction(name, function, module)


class FlowInterpreter:
    def __init__(self, auth: AuthInput, path: str, engine, backend_function: SourceFunction,
                 engine_helper: SourceFunction, engine_available=True, method="GET"):
        from language import named
        from starlette.requests import Request
        if (not isinstance(auth, AuthInput) or auth.kind not in ("session", "api_key")
                or any(not named(value) for value in (auth.role, auth.username, path))
                or type(auth.permissions) is not tuple or type(auth.scopes) is not tuple
                or len(auth.permissions) > 32 or len(auth.scopes) > 32
                or any(not named(v) for v in auth.permissions + auth.scopes)
                or type(engine_available) is not bool or type(method) is not str or method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")):
            raise AdmissionError("invalid validated-auth input contract", "invalid")
        self.auth, self.engine, self.engine_available = auth, engine, engine_available
        self.request = Request({"type": "http", "method": method, "path": path, "scheme": "http",
                                "headers": [], "server": ("example.test", 80), "query_string": b""})
        self.functions = {"_check_with_casbin": backend_function, "check_permission": engine_helper}
        self.steps, self.depth, self.trace = 0, 0, []
        self.native_calls, self.provider_calls, self.native_errors = 0, 0, 0

    def charge(self):
        self.steps += 1
        if self.steps > 4096:
            raise AdmissionError("dependency interpretation work exhausted", "inconclusive")

    def globals(self, module):
        common = {name: Primitive(name) for name in ("get_current_auth", "SessionAuth", "HTTPException", "len", "isinstance", "get_enforcer", "logger")}
        if module == "api.auth":
            common["_check_with_casbin"] = self.functions["_check_with_casbin"]
        return common

    def evaluate(self, dependency, argument):
        if not isinstance(argument, str) or not 0 < len(argument) <= 256:
            raise AdmissionError("dependency argument must be a bounded name", "invalid")
        environment = self.globals(dependency.function.module)
        environment[dependency.argument_name] = argument
        self.statements(dependency.initializer, environment, dependency.function.module)
        environment.update(request=self.request, api_key=None)
        status = None
        try:
            result = self.run(dependency.function, [self.request, None], environment)
            if result is not self.auth:
                raise AdmissionError("authorization dependency did not return the validated input record")
            decision = "allow"
        except HTTPDenied as denied:
            if denied.status not in (401, 403):
                raise AdmissionError("non-authorization HTTP exception is not a policy denial") from denied
            decision, status = "deny", denied.status
        if self.native_errors:
            raise AdmissionError("native consumer failed; fallback is not ordinary native agreement", "native_error")
        return {"decision": decision, "http_status": status, "native_calls": self.native_calls,
                "provider_calls": self.provider_calls, "trace": self.trace}

    def run(self, function, arguments, closure=None):
        self.depth += 1
        if self.depth > 8:
            raise AdmissionError("source call depth exceeds interface envelope", "inconclusive")
        names = [a.arg for a in function.node.args.args]
        if len(names) != len(arguments):
            raise AdmissionError("source helper argument count differs", "invalid")
        environment = self.globals(function.module) if closure is None else dict(closure)
        environment.update(zip(names, arguments))
        self.trace.append({"function": function.name, "module": function.module, "line": function.node.lineno})
        try:
            result = self.statements(function.node.body, environment, function.module)
            if not isinstance(result, _Return):
                raise AdmissionError("source helper lacks a completed return")
            return result.value
        finally:
            self.depth -= 1

    def value(self, node, env, module):
        self.charge()
        if isinstance(node, ast.Constant) and (node.value is None or type(node.value) in (str, bool, int)):
            return node.value
        if isinstance(node, ast.Name):
            if node.id not in env:
                raise AdmissionError("unbound dependency identifier: " + node.id)
            return env[node.id]
        if isinstance(node, (ast.List, ast.Tuple)):
            return [self.value(n, env, module) for n in node.elts]
        if isinstance(node, ast.Dict):
            if any(k is None for k in node.keys):
                raise AdmissionError("dictionary expansion is unsupported")
            return {self.value(k, env, module): self.value(v, env, module) for k, v in zip(node.keys, node.values)}
        if isinstance(node, ast.Attribute):
            obj = self.value(node.value, env, module)
            if isinstance(obj, AuthInput) and node.attr in ("role", "permissions", "scopes", "username"):
                return getattr(obj, node.attr)
            if obj is self.request and node.attr == "url":
                return self.request.url
            if obj is self.request and node.attr == "method":
                return self.request.method
            from starlette.datastructures import URL
            if type(obj) is URL and node.attr == "path":
                return obj.path
            if obj is self.engine and node.attr == "enforce":
                return Primitive("native_enforce")
            if isinstance(obj, Primitive) and obj.name == "logger" and node.attr == "debug":
                return Primitive("log_debug")
            if type(obj) is str and node.attr in ("strip", "split"):
                return ("string_method", obj, node.attr)
            if type(obj) is dict and node.attr == "get":
                return ("dictionary_get", obj)
            raise AdmissionError("attribute lacks a typed dependency binding: " + node.attr)
        if isinstance(node, ast.Subscript):
            obj, index = self.value(node.value, env, module), self.value(node.slice, env, module)
            if type(obj) not in (list, tuple) or type(index) is not int or not 0 <= index < len(obj):
                raise AdmissionError("dependency index is outside the typed input contract")
            return obj[index]
        if isinstance(node, ast.IfExp):
            return self.value(node.body if self.truth(self.value(node.test, env, module)) else node.orelse, env, module)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not self.truth(self.value(node.operand, env, module))
        if isinstance(node, ast.BoolOp):
            for part in node.values:
                value = self.truth(self.value(part, env, module))
                if isinstance(node.op, ast.And) and not value:
                    return False
                if isinstance(node.op, ast.Or) and value:
                    return True
            return isinstance(node.op, ast.And)
        if isinstance(node, ast.Compare):
            if len(node.ops) != 1:
                raise AdmissionError("chained dependency comparisons are unsupported")
            left, right, op = self.value(node.left, env, module), self.value(node.comparators[0], env, module), node.ops[0]
            if isinstance(op, (ast.Is, ast.IsNot)):
                if right is not None and type(right) is not bool:
                    raise AdmissionError("identity comparison is restricted to None or Boolean")
                result = left is right
                return not result if isinstance(op, ast.IsNot) else result
            if isinstance(op, (ast.In, ast.NotIn)):
                if type(left) is not str or type(right) not in (tuple, list, dict):
                    raise AdmissionError("membership comparison lacks typed operands")
                result = left in right
                return not result if isinstance(op, ast.NotIn) else result
            if type(left) not in (str, int, bool) or type(right) is not type(left):
                raise AdmissionError("dependency comparison operands differ in type")
            operations = {ast.Eq: lambda: left == right, ast.NotEq: lambda: left != right,
                          ast.Gt: lambda: left > right, ast.GtE: lambda: left >= right,
                          ast.Lt: lambda: left < right, ast.LtE: lambda: left <= right}
            return operations[type(op)]()
        if isinstance(node, ast.JoinedStr):
            return "".join(str(self.value(part.value, env, module)) if isinstance(part, ast.FormattedValue)
                           else str(self.value(part, env, module)) for part in node.values)
        if isinstance(node, ast.Await):
            if not (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "get_current_auth"):
                raise AdmissionError("await is restricted to the validated-auth provider boundary")
            result = self.value(node.value, env, module)
            if not isinstance(result, _Provided):
                raise AdmissionError("awaited provider binding differs from its contract")
            return result.value
        if isinstance(node, ast.Call):
            function = self.value(node.func, env, module)
            arguments = [self.value(n, env, module) for n in node.args]
            keywords = {item.arg: self.value(item.value, env, module) for item in node.keywords}
            if len(keywords) != len(node.keywords) or None in keywords:
                raise AdmissionError("expanded or repeated dependency keywords are unsupported")
            if isinstance(function, SourceFunction) and not keywords:
                return self.run(function, arguments)
            if type(function) is tuple and not keywords:
                if function[0] == "string_method" and len(arguments) == 1 and type(arguments[0]) is str:
                    return getattr(function[1], function[2])(arguments[0])
                if function[0] == "dictionary_get" and len(arguments) == 2 and type(arguments[0]) is str:
                    return function[1].get(*arguments)
            if not isinstance(function, Primitive):
                raise AdmissionError("call lacks an admitted dependency binding")
            if function.name == "get_current_auth" and not keywords and len(arguments) == 2 and arguments[0] is self.request and arguments[1] is None:
                self.provider_calls += 1
                return _Provided(self.auth)
            if function.name == "get_enforcer" and not arguments and not keywords:
                if not self.engine_available:
                    raise SourceFault("owned backend-unavailable condition")
                return self.engine
            if function.name == "native_enforce" and not keywords and len(arguments) == 3 and all(type(v) is str for v in arguments):
                try:
                    result = self.engine.enforce(*arguments)
                except Exception as error:
                    self.native_errors += 1
                    raise SourceFault("native consumer failure: " + type(error).__name__) from error
                if type(result) is not bool:
                    raise AdmissionError("native consumer returned a non-Boolean", "native_error")
                self.native_calls += 1
                self.trace.append({"native_request": arguments, "decision": result})
                return result
            if function.name == "len" and not keywords and len(arguments) == 1 and type(arguments[0]) in (list, tuple, dict, str):
                return len(arguments[0])
            if function.name == "isinstance" and not keywords and len(arguments) == 2 and arguments[1] == Primitive("SessionAuth"):
                return isinstance(arguments[0], AuthInput) and arguments[0].kind == "session"
            if function.name == "HTTPException" and not arguments and set(keywords) == {"status_code", "detail"} and type(keywords["status_code"]) is int and type(keywords["detail"]) is str:
                return HTTPDenied(keywords["status_code"], keywords["detail"])
            if function.name == "log_debug" and not keywords and len(arguments) == 1 and type(arguments[0]) is str:
                return None
            raise AdmissionError("primitive call arguments are outside the typed contract: " + function.name)
        raise AdmissionError("unhandled dependency expression: " + type(node).__name__)

    @staticmethod
    def truth(value):
        if type(value) is not bool:
            raise AdmissionError("dependency branch requires a Boolean")
        return value

    def statements(self, body, env, module):
        for statement in body:
            self.charge()
            if isinstance(statement, ast.Assign):
                destination = statement.targets[0].id
                if destination in self.globals(module) or destination in ("request", "api_key"):
                    raise AdmissionError("source rebinds a supplied dependency primitive")
                env[destination] = self.value(statement.value, env, module)
            elif isinstance(statement, ast.Return):
                return _Return(self.value(statement.value, env, module))
            elif isinstance(statement, ast.If):
                result = self.statements(statement.body if self.truth(self.value(statement.test, env, module)) else statement.orelse, env, module)
                if isinstance(result, _Return):
                    return result
            elif isinstance(statement, ast.Raise):
                exception = self.value(statement.exc, env, module)
                if not isinstance(exception, HTTPDenied):
                    raise AdmissionError("dependency raise is not an admitted HTTP denial")
                raise exception
            elif isinstance(statement, ast.Try):
                try:
                    result = self.statements(statement.body, env, module)
                except SourceFault as error:
                    handler = statement.handlers[0]
                    if handler.name:
                        env[handler.name] = str(error)
                    result = self.statements(handler.body, env, module)
                    if handler.name:
                        env.pop(handler.name, None)
                if isinstance(result, _Return):
                    return result
            elif isinstance(statement, ast.ImportFrom):
                env["check_permission"] = self.functions["check_permission"]
            elif isinstance(statement, ast.Expr):
                if not isinstance(statement.value, ast.Constant) or type(statement.value.value) is not str:
                    self.value(statement.value, env, module)
            elif not isinstance(statement, ast.Pass):
                raise AdmissionError("unhandled dependency statement")
        return None


@dataclass(frozen=True)
class _Return:
    value: object


@dataclass(frozen=True)
class _Provided:
    value: AuthInput
