"""A complete selected request-guard slice with explicit call/error outcomes.

Only the AST is interpreted. Authenticated records, native policy, provider
availability and audit are owned capabilities. No JWT, HTTP request, application
module, database, endpoint or advisory example is executed.
"""
import ast
import configparser
from itertools import product
import re

from effect_slice import Capability, DataRecord, EffectInterpreter, SliceFault, extract_effect_program
from native_casbin import AdmissionError, _schema
from observation_protocol import compare_observations
from source_bindings import require_import_bindings


FLAGS = ("http_401", "http_403", "protocol_error", "native_called", "audit_written", "provider_error")
OWN_POLICY = (("p", "reader", "t1", "board", "read"), ("g", "alice", "reader", "t1"))


def bind_model(model):
    parsed = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=True)
    try:
        parsed.read_string(model)
    except configparser.Error as error:
        raise AdmissionError("request outcome model does not parse", "invalid") from error
    actual = {key: dict(parsed.items(key)) for key in parsed.sections()}
    expected = _schema("rbac_with_domains")
    expected["matchers"]["m"] = 'g(r.sub, p.sub, r.dom) && r.dom == p.dom && (r.obj == p.obj || p.obj == "*") && (r.act == p.act || p.act == "*")'
    compact = lambda table: {section: {key: re.sub(r"\s+", "", value) for key, value in fields.items()} for section, fields in table.items()}
    if parsed.defaults() or compact(actual) != compact(expected):
        raise AdmissionError("request outcome comparison requires its declared domain-role/wildcard schema")


def outcome(allowed=False, *, fault=None, native=False, audit=False):
    return {"decision": "allow" if allowed else "deny", "flags": {
        "http_401": fault == "HTTP401", "http_403": fault == "HTTP403", "protocol_error": fault == "TypeError",
        "native_called": native, "audit_written": audit, "provider_error": fault == "ProviderError"}}


def source_outcome(program, native, user, resource, action, provider_ready=True):
    counts = {"native": 0, "audit": 0}
    def enforce(*args):
        if len(args) != 4 or any(type(value) is not str for value in args):
            raise AdmissionError("request/native call needs four supplied strings")
        counts["native"] += 1
        result = native.enforce(*args)
        if type(result) is not bool:
            raise AdmissionError("request/native result is not a measured plain Boolean", "native_error")
        return result
    def get_enforcer():
        if not provider_ready:
            raise SliceFault("ProviderError", "owned uninitialized native provider")
        return DataRecord("native", {"enforce": Capability("enforce", enforce)})
    def audit(*args, **kwargs):
        counts["audit"] += 1
    def http_error(*, status_code, detail):
        if status_code not in (401, 403) or type(detail) is not str:
            raise AdmissionError("request source raised an undeclared HTTP outcome")
        return SliceFault("HTTP" + str(status_code), detail)
    request = DataRecord("request", {"state": DataRecord("state", {"auth_user": user})})
    instance = EffectInterpreter(program, DataRecord("module", {}), {"SYSTEM_DOMAIN": "system",
        "get_enforcer": Capability("get_enforcer", get_enforcer), "audit": Capability("audit", audit),
        "HTTPException": Capability("HTTPException", http_error)})
    fault = None
    try:
        returned = instance.run("_check_permission", [request, resource, action])
        if returned is not user:
            raise AdmissionError("guard must preserve the supplied authenticated record identity")
        allowed = True
    except SliceFault as error:
        if error.name not in ("HTTP401", "HTTP403", "TypeError", "ProviderError"):
            raise
        fault, allowed = error.name, False
    return outcome(allowed, fault=fault, native=bool(counts["native"]), audit=bool(counts["audit"])), counts


def reference_outcome(user, resource, action, provider_ready=True):
    """Declared bypass ordering and independent fixed owned role-matrix oracle.

    The bypass contract is supplied for this comparison; it is not a statement
    that these roles are externally entitled or issued securely.
    """
    if not user:
        return outcome(fault="HTTP401")
    uid = str(user.get("uid") or user.get("user_id") or "")
    domain = user.get("domain", "")
    role = user.get("system_role", user.get("role", ""))
    if role in {"system_owner", "system_admin", "admin"} and (domain == "system" or resource.startswith("system:")):
        return outcome(True)
    if not uid or not domain:
        return outcome(fault="HTTP403", audit=True)
    if not provider_ready:
        return outcome(fault="ProviderError")
    granted = uid == "alice" and domain == "t1" and resource == "board" and action == "read"
    return outcome(granted, fault=None if granted else "HTTP403", native=True, audit=not granted)


def owned_contexts():
    users = [None, {}]
    for identity, domain, role, role_key in product(("direct", "fallback", "missing"), ("", "system", "t1", "t2"),
                                                    ("member", "admin", "system_admin", "system_owner"), ("role", "system_role")):
        user = {"domain": domain, role_key: role, "username": "owned"}
        if identity == "direct":
            user["uid"] = "alice"
        elif identity == "fallback":
            user.update(uid="", user_id="bob")
        users.append(user)
    return [(user, resource, action, ready) for user, resource, action, ready in product(users,
        ("board", "missing", "system:settings"), ("read", "delete"), (False, True))]


def compare_request_outcomes(source, model):
    require_import_bindings(source, {"HTTPException": ("fastapi", 0, "HTTPException"),
        "SYSTEM_DOMAIN": ("app.rbac.enforcer", 0, "SYSTEM_DOMAIN"), "get_enforcer": ("app.rbac.enforcer", 0, "get_enforcer"),
        "audit": ("app.observability.audit", 0, "audit")})
    bind_model(model)
    program = extract_effect_program(source, None, (), ("_get_auth_user", "_check_permission"))
    import casbin
    native_model = casbin.Model()
    native_model.load_model_from_text(model)
    for row in OWN_POLICY:
        casbin.persist.load_policy_line(", ".join(row), native_model)
    native = casbin.AsyncEnforcer(native_model)
    native.build_role_links()
    references, observations, counts = [], [], {"native": 0, "audit": 0}
    contexts = owned_contexts()
    for user, resource, action, ready in contexts:
        observation, calls = source_outcome(program, native, user, resource, action, ready)
        references.append(reference_outcome(user, resource, action, ready))
        observations.append(observation)
        for key in counts:
            counts[key] += calls[key]
    result = compare_observations(references, observations, "complete selected request guard on owned identity/provider contexts; issuer, route registration, native initialization and business effects outside scope")
    return {"comparison": result, "different_case_observations": sum(a != b for a, b in zip(references, observations)),
        "source_protocol_error_cases": sum(row["flags"]["protocol_error"] for row in observations),
        "source_descriptor": {name: {"line": node.lineno, "end_line": node.end_lineno} for name, node in program.items()},
        "counts": counts, "cases": len(contexts), "fixed_owned_policy": OWN_POLICY,
        "native_provider_initialization_proved": False, "whole_application_verified": False,
        "supplied_reference_not_external_entitlement_or_deployment_verdict": True}
