"""A typed tenant authorization slice, without importing application modules.

Principal validation, request.app.state.casbin and two audit sinks are explicit
bindings. Sink calls are recorded, NOT executed. Only authorization decisions
and arguments passed to the real native engine are compared by this interface.
"""
import ast
from dataclasses import dataclass

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from source_bindings import require_import_bindings


@dataclass(frozen=True)
class TenantPrincipal:
    user_id: int
    tenant_id: int
    role: str
    is_service: bool = False


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted(node.value) + "." + node.attr
    return ""


def _body(nodes):
    return [n for n in nodes if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                                    and isinstance(n.value.value, str))]


def extract_tenant_dependency(source):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("tenant dependency exceeds byte envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("tenant dependency source does not parse", "invalid") from error
    outer = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "require_perm"]
    if len(outer) != 1 or not isinstance(outer[0], ast.FunctionDef):
        raise AdmissionError("require_perm must be a unique synchronous factory")
    factory = outer[0]
    a = factory.args
    if (factory.decorator_list or [p.arg for p in a.args] != ["obj", "act"] or a.posonlyargs
            or a.defaults or a.kwonlyargs or a.vararg or a.kwarg):
        raise AdmissionError("unsupported tenant dependency factory signature")
    body = _body(factory.body)
    if (len(body) != 2 or not isinstance(body[0], ast.AsyncFunctionDef) or not isinstance(body[1], ast.Return)
            or not isinstance(body[1].value, ast.Name) or body[1].value.id != body[0].name):
        raise AdmissionError("factory must return its single captured async dependency")
    function = body[0]
    a = function.args
    if (function.decorator_list or [p.arg for p in a.args] != ["request", "principal", "session"]
            or a.posonlyargs or a.kwonlyargs or a.vararg or a.kwarg or len(a.defaults) != 2):
        raise AdmissionError("unsupported dependency input bindings")
    for default, target in zip(a.defaults, ("require_principal", "_session")):
        if not (isinstance(default, ast.Call) and _dotted(default.func) == "Depends"
                and len(default.args) == 1 and _dotted(default.args[0]) == target and not default.keywords):
            raise AdmissionError("dependency provider is not the declared input boundary")
    nodes = [n for statement in function.body for n in ast.walk(statement)]
    allowed = (ast.If, ast.Assign, ast.Return, ast.Raise, ast.Expr, ast.Await, ast.Name, ast.Attribute,
               ast.Constant, ast.Call, ast.keyword, ast.Compare, ast.Eq, ast.NotEq, ast.BoolOp,
               ast.Or, ast.And, ast.UnaryOp, ast.Not, ast.JoinedStr, ast.FormattedValue,
               ast.Dict, ast.Load, ast.Store)
    if len(nodes) > 2048:
        raise AdmissionError("tenant dependency syntax envelope exceeded", "inconclusive")
    for node in nodes:
        if not isinstance(node, allowed):
            raise AdmissionError("unsupported tenant dependency syntax: " + type(node).__name__)
        if isinstance(node, ast.Assign) and (len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name)
                                             or node.targets[0].id not in ("enforcer", "rtenant")):
            raise AdmissionError("tenant dependency may only bind its declared locals")
        if isinstance(node, ast.Call) and _dotted(node.func) not in ("enforcer.enforce", "write_audit", "session.commit", "HTTPException"):
            raise AdmissionError("tenant dependency call is outside reviewed primitive bindings")
        if isinstance(node, ast.FormattedValue) and (node.conversion != -1 or node.format_spec is not None):
            raise AdmissionError("format conversion is outside the string fragment")
    return {"function": function, "line": factory.lineno, "end_line": factory.end_lineno,
            "authentication_and_database_verified": False}


def bind_tenant_dependency_source(source):
    bindings = require_import_bindings(source, {"Depends": ("fastapi", 0, "Depends"),
        "HTTPException": ("fastapi", 0, "HTTPException"),
        "require_principal": ("dlw.auth.principal", 0, "require_principal"),
        "write_audit": ("dlw.services.audit", 0, "write_audit")})
    extraction = extract_tenant_dependency(source)
    extraction["source_bindings"] = bindings
    return extraction


class _Returned(Exception):
    pass


class _Denied(Exception):
    pass


def evaluate_tenant_dependency(extraction, engine, principal, obj, act):
    if (not isinstance(principal, TenantPrincipal) or type(principal.tenant_id) is not int
            or type(principal.user_id) is not int or type(principal.is_service) is not bool
            or not isinstance(principal.role, str) or not principal.role
            or not isinstance(obj, str) or not isinstance(act, str)):
        raise AdmissionError("invalid typed tenant dependency input", "invalid")
    env = {"obj": obj, "act": act}
    effects, calls = [], []

    def expression(node):
        if isinstance(node, ast.Constant) and type(node.value) in (str, int, bool, type(None)):
            return node.value
        if isinstance(node, ast.Name):
            if node.id == "principal":
                return principal
            if node.id == "session":
                return ("binding", "audit_session")
            if node.id in env:
                return env[node.id]
        if isinstance(node, ast.Attribute):
            name = _dotted(node)
            if name == "request.app.state.casbin":
                return ("binding", "native_engine")
            if name in ("principal.tenant_id", "principal.role", "principal.user_id", "principal.is_service"):
                return getattr(principal, name.split(".")[-1])
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not bool(expression(node.operand))
        if isinstance(node, ast.BoolOp):
            value = None
            for term in node.values:
                value = expression(term)
                if isinstance(node.op, ast.Or) and value or isinstance(node.op, ast.And) and not value:
                    break
            return value
        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
            left, right = expression(node.left), expression(node.comparators[0])
            if type(left) is not type(right):
                raise AdmissionError("comparison is outside the typed equality fragment")
            return left == right if isinstance(node.ops[0], ast.Eq) else left != right
        if isinstance(node, ast.JoinedStr):
            parts = [expression(value.value) if isinstance(value, ast.FormattedValue) else expression(value) for value in node.values]
            if any(type(value) not in (str, int, bool) for value in parts):
                raise AdmissionError("formatted string uses an unbound type")
            return "".join(str(value) for value in parts)
        if isinstance(node, ast.Dict):
            if any(key is None for key in node.keys):
                raise AdmissionError("dictionary unpacking is not admitted")
            return {expression(key): expression(value) for key, value in zip(node.keys, node.values)}
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            args = [expression(value) for value in node.args]
            if any(value.arg is None for value in node.keywords) or len({value.arg for value in node.keywords}) != len(node.keywords):
                raise AdmissionError("keyword unpacking is not admitted")
            kw = {value.arg: expression(value.value) for value in node.keywords}
            if name == "enforcer.enforce":
                if env.get("enforcer") != ("binding", "native_engine") or kw or len(args) != 5:
                    raise AdmissionError("native consumer receiver/argument binding changed")
                if (type(args[0]) is not str or type(args[1]) is not int or type(args[2]) is not str
                        or type(args[3]) is not str or type(args[4]) is not int):
                    raise AdmissionError("native tenant request does not have its declared five types")
                try:
                    answer = engine.enforce(*args)
                except Exception as error:
                    raise AdmissionError("native tenant consumer failed: " + type(error).__name__, "native_error") from error
                if type(answer) is not bool:
                    raise AdmissionError("native tenant consumer result is not Boolean", "native_error")
                calls.append({"arguments": args, "result": answer})
                return answer
            if name in ("write_audit", "session.commit"):
                if name == "write_audit" and args != [("binding", "audit_session")]:
                    raise AdmissionError("audit sink session binding changed")
                if name == "session.commit" and (args or kw):
                    raise AdmissionError("commit sink arguments are outside its binding")
                effects.append({"sink": name, "arguments": args, "keywords": kw, "executed": False})
                return ("awaitable", name)
            if name == "HTTPException":
                status = args[0] if len(args) == 1 else kw.get("status_code") if not args else None
                if status != 403 or set(kw) - {"detail", "status_code"}:
                    raise AdmissionError("HTTP response is outside the declared forbidden effect")
                return ("http", status)
        if isinstance(node, ast.Await):
            value = expression(node.value)
            if not (isinstance(value, tuple) and len(value) == 2 and value[0] == "awaitable"):
                raise AdmissionError("await does not target a declared audit sink")
            return None
        raise AdmissionError("unbound tenant dependency expression: " + type(node).__name__)

    def statements(nodes):
        for node in nodes:
            if isinstance(node, ast.If):
                statements(node.body if expression(node.test) else node.orelse)
            elif isinstance(node, ast.Assign):
                env[node.targets[0].id] = expression(node.value)
            elif isinstance(node, ast.Return):
                if expression(node.value) is not principal:
                    raise AdmissionError("dependency return differs from the principal binding")
                raise _Returned()
            elif isinstance(node, ast.Raise):
                if expression(node.exc) != ("http", 403) or node.cause is not None:
                    raise AdmissionError("unsupported dependency exception effect")
                raise _Denied()
            elif isinstance(node, ast.Expr):
                if not isinstance(node.value, ast.Constant):
                    expression(node.value)
            else:
                raise AdmissionError("unbound tenant dependency statement")
    try:
        statements(extraction["function"].body)
    except _Returned:
        decision = "allow"
    except _Denied:
        decision = "deny"
    else:
        raise AdmissionError("dependency falls through without a typed decision")
    return {"decision": decision, "native_calls": calls, "audit_effects": effects,
            "source_module_executed": False, "audit_or_application_database_executed": False}
