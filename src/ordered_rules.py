"""Explicit ordered-rule source bodies with serial native fallback.

The real source bodies and literal rule registration are parsed, never imported.
Token capture, immutable group/membership snapshots, native engine and serial
non-suppressing lock/threadpool capabilities are given separately. This does
not execute ContextVar scheduling, SQL, JWT validation or an application.
"""
import ast
import copy

from effect_slice import (Capability, Closure, DataRecord, EffectInterpreter, ErrorType,
    PRIMITIVES, RecordType, SerialContext, SliceFault, extract_effect_program)
from native_casbin import AdmissionError, MAX_TEXT_BYTES
from source_bindings import require_import_bindings, require_static_class_members, require_static_definitions

CONTEXT_FIELDS = ("user_id", "tenant_id", "obj", "act", "platform_role", "db", "token_ctx")
RULE_FIELDS = ("name", "objs", "acts", "needs_db", "decision", "predicate")


def literal(node):
    if isinstance(node, ast.Constant) and (node.value is None or type(node.value) in (str, bool)):
        return node.value
    if isinstance(node, (ast.Set, ast.Tuple)) and all(isinstance(item, ast.Constant) and type(item.value) is str for item in node.elts):
        return tuple(item.value for item in node.elts)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "frozenset"
            and not node.keywords and len(node.args) == 1 and isinstance(node.args[0], ast.Set)):
        return frozenset(literal(node.args[0]))
    raise AdmissionError("rule metadata is not a literal string-set/scalar")


def declaration(tree, name):
    matches, writes = [], 0
    def visit(node, direct=False):
        nonlocal writes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                writes += 1
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id == name:
            writes += 1
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and direct:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name) and targets[0].id == name and node.value is not None:
                matches.append(node.value)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            root = node.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name) and root.id == name:
                raise AdmissionError("rule metadata has a later mutation")
        for child in ast.iter_child_nodes(node):
            visit(child)
    for statement in tree.body:
        visit(statement, True)
    if writes != 1 or len(matches) != 1:
        raise AdmissionError("rule metadata needs one direct unmodified declaration: " + name)
    return matches[0]


def extract_ordered_rules(source):
    if type(source) is not bytes or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("ordered-rule source exceeds its envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("ordered-rule source does not parse", "invalid") from error
    require_import_bindings(source, {"dataclass": ("dataclasses", 0, "dataclass"),
        "current_token_ctx": ("app.api.token_context", 0, "current_token_ctx"),
        "_casbin_mod": ("app.core", 0, "casbin_enforcer"),
        "run_in_threadpool": ("fastapi.concurrency", 0, "run_in_threadpool"),
        "GroupRepository": ("app.repositories.group", 0, "GroupRepository"),
        "UserTenantRepository": ("app.repositories.tenant", 0, "UserTenantRepository")})
    definitions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    registry = declaration(tree, "CHECK_RULES")
    if not isinstance(registry, ast.Tuple) or not 1 <= len(registry.elts) <= 16:
        raise AdmissionError("rule registration requires a bounded explicit ordered tuple")
    rules = []
    for call in registry.elts:
        if (not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != "CheckRule"
                or call.args or len(call.keywords) != len(RULE_FIELDS) or {k.arg for k in call.keywords} != set(RULE_FIELDS)):
            raise AdmissionError("rule constructor fields differ from the typed contract")
        values = {k.arg: k.value for k in call.keywords}
        predicate = values.pop("predicate")
        if not isinstance(predicate, ast.Name):
            raise AdmissionError("rule predicate is not one direct source function")
        rule = {key: literal(value) for key, value in values.items()}
        rule["predicate"] = predicate.id
        if (type(rule["name"]) is not str or rule["decision"] not in ("allow", "deny")
                or type(rule["needs_db"]) is not bool
                or any(rule[key] is not None and type(rule[key]) is not frozenset for key in ("objs", "acts"))):
            raise AdmissionError("rule metadata values exceed the admitted schema")
        rules.append(rule)
    if len({rule["name"] for rule in rules}) != len(rules):
        raise AdmissionError("rule identities are duplicated")
    functions = tuple(dict.fromkeys([rule["predicate"] for rule in rules] + ["is_platform_writer", "_is_group_admin_of"]))
    require_static_definitions(tree, ["PermissionService", "CheckContext", "CheckRule", *functions], PRIMITIVES | {"PermissionError"})
    for name, fields in (("CheckContext", CONTEXT_FIELDS), ("CheckRule", RULE_FIELDS)):
        cls = definitions[name]
        if (not isinstance(cls, ast.ClassDef) or cls.bases or cls.keywords
                or [ast.unparse(node) for node in cls.decorator_list] != ["dataclass(frozen=True)"]):
            raise AdmissionError("record declaration needs the explicit frozen-dataclass body contract")
        annotations = [node for node in cls.body if isinstance(node, ast.AnnAssign)]
        if ([node.target.id if isinstance(node.target, ast.Name) else "" for node in annotations] != list(fields)
                or any(node.value is not None for node in annotations)):
            raise AdmissionError("record fields differ from the required exact constructor")
    rule_class = definitions["CheckRule"]
    require_static_class_members(rule_class, ["applies"])
    applies = next(node for node in rule_class.body if isinstance(node, ast.FunctionDef) and node.name == "applies")
    owned_class = ast.ClassDef(name="CheckRule", bases=[], keywords=[], body=[copy.deepcopy(applies)], decorator_list=[])
    owned_tree = ast.fix_missing_locations(ast.Module(body=[owned_class], type_ignores=[]))
    rule_program = extract_effect_program(ast.unparse(owned_tree).encode(), "CheckRule", ["applies"])
    if ast.dump(rule_program["applies"], include_attributes=False) != ast.dump(applies, include_attributes=False):
        raise AdmissionError("rule applies-body AST changed during explicit transport")
    program = extract_effect_program(source, "PermissionService", ["check", "require"], functions)
    constants = {name: literal(declaration(tree, name)) for name in ("PLATFORM_WRITER_ROLES", "GROUP_ADMIN_HQ_ROLES")}
    descriptor = {"methods": [{"name": name, "line": node.lineno, "end_line": node.end_lineno} for name, node in program.items()],
        "applies_body_line": applies.lineno, "literal_rules": [{**rule,
            "objs": sorted(rule["objs"]) if rule["objs"] is not None else None,
            "acts": sorted(rule["acts"]) if rule["acts"] is not None else None} for rule in rules],
        "dataclass_constructors_and_decorators_executed": False,
        "serial_lock_threadpool_is_given_not_measured": True, "assert_enabled_source_body_contract": True}
    return program, rule_program, rules, constants, descriptor


def run_ordered_check(extracted, context, native_enforce, *, required=False):
    program, rule_program, rules, constants, _ = extracted
    required_keys = {"user_id", "tenant_id", "obj", "act", "platform_role", "token", "db_present", "group", "membership"}
    if set(context) != required_keys:
        raise AdmissionError("ordered check input does not provide all owned snapshot contracts")
    effects = []
    db = DataRecord("opaque_db", {}) if context["db_present"] else None
    def capture():
        effects.append("token_capture")
        return context["token"]
    def group_repository(given_db):
        if given_db is not db or db is None:
            raise AdmissionError("group lookup lacks the explicitly supplied database contract")
        def groups(tenant):
            if tenant != context["tenant_id"]:
                raise AdmissionError("group lookup changed its supplied tenant binding")
            effects.append("groups_for_tenant")
            return () if context["group"] is None else (context["group"],)
        return DataRecord("group_repo", {"list_for_tenant": Capability("owned_group_snapshot", groups, True)})
    def membership_repository(given_db):
        if given_db is not db or db is None:
            raise AdmissionError("membership lookup lacks the supplied database contract")
        def membership(user, tenant):
            if user != context["user_id"] or tenant != context["group"].fields["headquarters_tenant_id"]:
                raise AdmissionError("membership lookup changed its supplied user/headquarters binding")
            effects.append("current_hq_membership")
            return context["membership"]
        return DataRecord("membership_repo", {"current_role": Capability("owned_membership_snapshot", membership, True)})
    def enforce(*args):
        effects.append("native_enforce")
        result = native_enforce(*args)
        if type(result) is not bool:
            raise AdmissionError("native policy consumer did not return a plain Boolean")
        return result
    def engine():
        effects.append("engine_get")
        return DataRecord("given_native_engine", {"enforce": Capability("native_enforce", enforce)})
    lock = SerialContext(lambda: effects.append("serial_enter"), lambda: effects.append("serial_exit"), asynchronous=False)
    receiver = DataRecord("permission_service", {})
    instance = EffectInterpreter(program, receiver, {**constants,
        "CheckContext": RecordType("context", CONTEXT_FIELDS), "PermissionError": ErrorType("PermissionError"),
        "current_token_ctx": DataRecord("context_provider", {"get": Capability("given_token_capture", capture)}),
        "GroupRepository": Capability("owned_group_repository", group_repository),
        "UserTenantRepository": Capability("owned_membership_repository", membership_repository),
        "_casbin_mod": DataRecord("casbin_provider", {"get_enforcer": Capability("given_engine", engine),
            "enforcer_lock": Capability("given_lock", lambda: lock)})})
    def serial_bridge(function):
        effects.append("serial_bridge")
        if not isinstance(function, Closure):
            raise AdmissionError("threadpool bridge received an unbound source closure")
        return instance.invoke(function, [], {})
    instance.bindings["run_in_threadpool"] = Capability("given_serial_threadpool", serial_bridge, True)
    bound_rules = []
    for rule in rules:
        record = DataRecord("rule", {key: value for key, value in rule.items() if key != "predicate"})
        applies_receiver = DataRecord("explicit_rule_metadata_receiver", dict(record.fields))
        applies_instance = EffectInterpreter(rule_program, applies_receiver, {})
        def applies(ctx, *, _name=rule["name"], _instance=applies_instance):
            effects.append("applies:" + _name)
            return _instance.run("applies", [ctx])
        def predicate(ctx, *, _name=rule["name"], _function=rule["predicate"]):
            effects.append("predicate:" + _name)
            return instance.run(_function, [ctx])
        record.fields["applies"] = Capability("source_rule_applies", applies)
        record.fields["predicate"] = Capability("source_rule_predicate", predicate, True)
        bound_rules.append(record)
    instance.bindings["CHECK_RULES"] = tuple(bound_rules)
    outcome = None
    try:
        outcome = instance.run("require" if required else "check",
            [context[name] for name in ("user_id", "tenant_id", "obj", "act", "platform_role")], {"db": db})
        if required:
            if outcome is not None:
                raise AdmissionError("require wrapper returned an uncontracted value")
            status = "allow"
        else:
            if type(outcome) is not bool:
                raise AdmissionError("check did not return its declared Boolean")
            status = "allow" if outcome else "deny"
    except SliceFault as error:
        status = "denied_by_require" if required and error.name == "PermissionError" else "error:" + error.name
    return {"status": status, "effects": effects, "source_function_calls": instance.function_calls,
        "native_calls": effects.count("native_enforce"), "token_reads": effects.count("token_capture")}
