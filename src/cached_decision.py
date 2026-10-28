"""Source cache-first authorization with explicit result/error/audit effects.

The actual native engine receives only owned role/policy rows. Cache, audit and
logger capabilities are owned typed observations, not Redis or application code.
"""
import ast
from itertools import product
from uuid import UUID

from effect_slice import Capability, DataRecord, EffectInterpreter, ErrorType, RecordType, SliceFault, extract_effect_program
from native_casbin import AdmissionError, admit_configuration
from native_runtime import engine_identity
from observation_protocol import compare_observations
from source_bindings import require_import_bindings


CACHE_MODES = ("miss", "allow", "deny", "other", "failure")
REFERENCE_POLICY = "\n".join(("p, readonly, accounts, read", "p, user, transactions, read", "p, user, transactions, write",
                               "p, admin, users, manage", "g, admin, user", "g, user, readonly"))


def constants(source):
    expected = {"CACHE_PREFIX": str, "CACHE_TTL_SECONDS": int}
    values = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in expected:
            name = node.targets[0].id
            if name in values or not isinstance(node.value, ast.Constant) or type(node.value.value) is not expected[name]:
                raise AdmissionError("cache constants need direct unique typed values")
            values[name] = node.value.value
    if set(values) != set(expected):
        raise AdmissionError("cache namespace/TTL declaration is missing")
    writes = {name: 0 for name in expected}
    def visit(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in writes:
                writes[node.name] += 1
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in writes:
            writes[node.id] += 1
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if (alias.asname or alias.name.split(".")[0]) in writes:
                    writes[alias.asname or alias.name.split(".")[0]] += 1
        for child in ast.iter_child_nodes(node):
            visit(child)
    for statement in ast.parse(source).body:
        visit(statement)
    if any(value != 1 for value in writes.values()):
        raise AdmissionError("cache constants have ambiguous or conditional rebindings")
    return values


class CachedDecisionEvaluation:
    def __init__(self, source, model, policy, cache_mode, *, native_fault=False, provider_fault=None):
        if cache_mode not in CACHE_MODES:
            raise AdmissionError("unknown owned cache observation")
        require_import_bindings(source, {"Success": ("src.core.result", 0, "Success"),
                                         "AuditAction": ("src.domain.enums", 0, "AuditAction")})
        configuration = admit_configuration(model, policy)
        if configuration.family != "rbac":
            raise AdmissionError("cached decision source requires the admitted exact role model")
        self.identity, self.constants = engine_identity(), constants(source)
        import casbin
        native_model = casbin.Model()
        native_model.load_model_from_text(model)
        for row in configuration.rows:
            casbin.persist.load_policy_line(", ".join(row), native_model)
        self.engine = casbin.AsyncEnforcer(native_model)
        self.engine.enable_auto_save(False)
        self.engine.build_role_links()
        self.events, self.writes = [], []
        self.counts = {"native_attempts": 0, "actual_native_enforce": 0}
        cached = {"miss": None, "allow": "1", "deny": "0", "other": "corrupt"}.get(cache_mode)
        record = DataRecord("failure", {"error": "owned cache miss/failure"}) if cache_mode == "failure" else DataRecord("success", {"value": cached})
        def get(key):
            self.events.append("cache_get")
            if provider_fault == "cache_get":
                raise SliceFault("CacheError", "owned cache failure")
            return record
        def set_value(key, value, *, ttl):
            self.events.append("cache_set")
            self.writes.append({"key": key, "value": value, "ttl": ttl})
            return DataRecord("success", {"value": None})
        def audit(**kwargs):
            self.events.append("audit")
            if provider_fault == "audit":
                raise SliceFault("AuditError", "owned audit failure")
            return DataRecord("success", {"value": None})
        def enforce(*args):
            self.counts["native_attempts"] += 1
            if native_fault:
                raise SliceFault("NativeError", "owned native failure control")
            self.counts["actual_native_enforce"] += 1
            try:
                value = self.engine.enforce(*args)
            except Exception as error:
                raise SliceFault("NativeError", type(error).__name__) from error
            if type(value) is not bool:
                raise AdmissionError("native cached decision is not Boolean", "native_error")
            return value
        def log(kind):
            return Capability("logger_" + kind, lambda *args, **kwargs: self.events.append("log_" + kind))
        receiver = DataRecord("receiver", {"_cache": DataRecord("cache", {"get": Capability("get", get, True), "set": Capability("set", set_value, True)}),
            "_enforcer": DataRecord("native", {"enforce": Capability("enforce", enforce)}),
            "_audit": DataRecord("audit", {"record": Capability("audit", audit, True)}),
            "_logger": DataRecord("logger", {kind: log(kind) for kind in ("debug", "info", "error")})})
        program = extract_effect_program(source, "CasbinAdapter", ("check_permission",))
        self.interpreter = EffectInterpreter(program, receiver, {**self.constants, "Success": RecordType("success", ("value",)),
            "AuditAction": DataRecord("audit_action", {"ACCESS_GRANTED": "granted", "ACCESS_DENIED": "denied"}), "Exception": ErrorType("Exception")})

    def call(self, user, resource, action):
        return self.interpreter.run("check_permission", [user, resource, action])


def compare_cached_decision(source, model, policy):
    if admit_configuration(model, policy).rows != admit_configuration(model, REFERENCE_POLICY).rows:
        raise AdmissionError("the fixed owned role-matrix reference requires its declared policy rows", "input_rejected")
    roles = ("readonly", "user", "admin")
    users = [UUID(int=i + 1) for i in range(3)]
    # Own policies and inheritance are explicit, not read from a current DB.
    own_policy = policy
    for user, role in zip(users, roles):
        own_policy += "\ng, " + str(user) + ", " + role
    cases, reference, observed, all_audit, counts = [], [], [], [], {"native_attempts": 0, "actual_native_enforce": 0}
    permissions = {"readonly": {("accounts", "read")},
        "user": {("accounts", "read"), ("transactions", "read"), ("transactions", "write")},
        "admin": {("accounts", "read"), ("transactions", "read"), ("transactions", "write"), ("users", "manage")}}
    for index, resource, action, mode, native_fault in product(range(3), ("accounts", "transactions", "users", "missing"), ("read", "write", "manage"), CACHE_MODES, (False, True)):
        user, role = users[index], roles[index]
        evaluation = CachedDecisionEvaluation(source, model, own_policy, mode, native_fault=native_fault)
        decision = evaluation.call(user, resource, action)
        if type(decision) is not bool:
            raise AdmissionError("cache-first source result did not resolve to Boolean")
        hit = mode in ("allow", "deny", "other")
        expected = mode == "allow" if hit else False if native_fault else (resource, action) in permissions[role]
        key = f"authz:{user}:{resource}:{action}"
        expected_writes = [] if hit else [{"key": key, "value": "1" if expected else "0", "ttl": 300}]
        expected_flags = {"cache_hit": hit, "native_called": not hit, "write_attempted": not hit,
            "audit_called": not hit, "native_error_handled": native_fault and not hit, "write_payload_exact": True}
        actual_flags = {"cache_hit": "log_debug" in evaluation.events, "native_called": evaluation.counts["native_attempts"] > 0,
            "write_attempted": "cache_set" in evaluation.events, "audit_called": "audit" in evaluation.events,
            "native_error_handled": "log_error" in evaluation.events, "write_payload_exact": evaluation.writes == expected_writes}
        reference.append({"decision": "allow" if expected else "deny", "flags": expected_flags})
        observed.append({"decision": "allow" if decision else "deny", "flags": actual_flags})
        all_audit.append({"decision": "allow" if expected else "deny", "flags": {**expected_flags, "audit_called": True}})
        cases.append({"user": str(user), "role": role, "resource": resource, "action": action, "cache": mode,
            "owned_native_failure": native_fault, "expected": expected, "observed": decision, "events": evaluation.events, "writes": evaluation.writes})
        for name, value in evaluation.counts.items():
            counts[name] += value
    result = compare_observations(reference, observed, "explicit cache-first/fail-closed normal contract with owned result providers and a native role-policy consumer")
    audit_result = compare_observations(all_audit, observed, "stronger all-checks-audited documentation contract; includes cache hits")
    return {"accepted": result["accepted"], "status": result["status"], "comparison": result, "all_checks_audited_contract": audit_result,
            "cache_hit_cases_without_audit": sum("audit" not in row["events"] for row in cases), "cases": cases, "counts": counts,
            "redis_postgresql_or_full_application_executed": False, "native_failure_controls_are_owned": True,
            "ttl_expiry_or_cache_invalidation_histories_verified": False, "new_security_finding": False}
