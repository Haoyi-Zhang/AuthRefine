"""Selected serial domain-role mutations behind a source threadpool bridge.

Parses the complete admitted closures without importing the application or
running its database/lock/threadpool. The supplied native engine, immutable
initial grouping and current-role contract bound this local comparison.
"""
import ast
import configparser
from itertools import product

from native_casbin import AdmissionError, MAX_TEXT_BYTES, _schema
from observation_protocol import compare_observations
from persistent_store import shape, strip_docstring
from source_bindings import require_import_bindings, require_static_class_members


METHODS = {"add": "add_role_for_user_in_domain", "set": "set_role_for_user_in_domain", "remove": "remove_user_from_tenant"}


def extract_domain_updates(source):
    if type(source) is not bytes or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("threadpool role source exceeds byte envelope", "inconclusive")
    require_import_bindings(source, {"_casbin_mod": ("app.core", 0, "casbin_enforcer"),
                                     "run_in_threadpool": ("fastapi.concurrency", 0, "run_in_threadpool")})
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("role mutation source does not parse", "invalid") from error
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "PermissionService"]
    if len(classes) != 1 or classes[0].bases or classes[0].decorator_list or classes[0].keywords:
        raise AdmissionError("role service class binding is ambiguous")
    cls = classes[0]
    require_static_class_members(cls, METHODS.values())
    result = {}
    for operation, name in METHODS.items():
        node = next(item for item in cls.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name)
        parameters = ["user_id", "tenant_id"] if operation == "remove" else ["user_id", "role", "tenant_id"]
        args = node.args
        if (not isinstance(node, ast.AsyncFunctionDef) or node.decorator_list or args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg
                or args.defaults or [arg.arg for arg in args.args] != ["self", *parameters]):
            raise AdmissionError("role mutation method signature/protocol changed")
        body = strip_docstring(node.body)
        if len(body) != 2 or not isinstance(body[0], ast.FunctionDef) or body[0].name != "_do":
            raise AdmissionError("role mutation is not the complete admitted closure/threadpool bridge")
        closure = body[0]
        if (closure.decorator_list or closure.args.posonlyargs or closure.args.args or closure.args.kwonlyargs
                or closure.args.vararg or closure.args.kwarg or closure.args.defaults):
            raise AdmissionError("role closure takes unbound inputs")
        end = ast.parse("await run_in_threadpool(_do)").body[0]
        setup = ast.parse("e = _casbin_mod.get_enforcer()\nwith _casbin_mod.enforcer_lock():\n    pass").body
        cb = strip_docstring(closure.body)
        if (shape(body[1]) != shape(end) or len(cb) != 2 or shape(cb[0]) != shape(setup[0])
                or not isinstance(cb[1], ast.With) or len(cb[1].items) != 1
                or shape(cb[1].items[0]) != shape(setup[1].items[0])):
            raise AdmissionError("source engine/lock/await handoff needs a separate translation")
        statements = cb[1].body
        calls = []
        def call(statement, method, allowed, arity):
            value = statement.value if isinstance(statement, ast.Expr) else None
            if (not isinstance(value, ast.Call) or shape(value.func) != shape(ast.parse("e." + method, mode="eval").body)
                    or value.keywords or len(value.args) != arity
                    or any(not isinstance(arg, ast.Name) or arg.id not in allowed for arg in value.args)):
                raise AdmissionError("source native role operation is unresolved")
            return {"method": method, "arguments": [arg.id for arg in value.args]}
        expected_length = 2 if operation == "set" else 1
        if len(statements) != expected_length:
            raise AdmissionError("role closure has additional/missing effects")
        if operation in ("set", "remove"):
            loop = statements[0]
            if (not isinstance(loop, ast.For) or loop.orelse or not isinstance(loop.target, ast.Name)
                    or loop.target.id != "old" or len(loop.body) != 1):
                raise AdmissionError("role removal is not the admitted finite native snapshot loop")
            get = call(ast.Expr(value=loop.iter), "get_roles_for_user_in_domain", parameters, 2)
            delete = call(loop.body[0], "delete_roles_for_user_in_domain", [*parameters, "old"], 3)
            calls.append({"loop": get, "body": delete})
        if operation in ("set", "add"):
            calls.append(call(statements[-1], "add_role_for_user_in_domain", parameters, 3))
        result[operation] = {"method": name, "line": node.lineno, "end_line": node.end_lineno, "calls": calls}
    return {"operations": result, "source_module_executed": False, "threadpool_or_real_lock_executed": False,
            "binding_scope": "direct source import/engine getter/lock/await syntax; native receiver supplied separately"}


def native_domain_engine(model_text, policies, grouping):
    from native_runtime import engine_identity
    engine_identity()  # Reject an unreviewed/ambiguous package before use.
    parsed = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=True)
    try:
        parsed.read_string(model_text)
    except configparser.Error as error:
        raise AdmissionError("domain-role model does not parse", "invalid") from error
    expected = _schema("rbac_with_domains")
    expected["matchers"]["m"] = "g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch(r.obj, p.obj) && r.act == p.act"
    compact = lambda values: {key: {field: "".join(value.split()) for field, value in row.items()} for key, row in values.items()}
    if parsed.defaults() or compact({section: dict(parsed.items(section)) for section in parsed.sections()}) != compact(expected):
        raise AdmissionError("domain-role model requires a separate bounded semantics")
    import casbin
    model = casbin.Model()
    model.load_model_from_text(model_text)
    engine = casbin.Enforcer(model)
    engine.enable_auto_save(False)
    for row in policies:
        engine.add_policy(*row)
    for row in grouping:
        engine.add_grouping_policy(*row)
    return engine


def compare_domain_updates(source, model_text, *, engine_factory):
    descriptor = extract_domain_updates(source)
    roles = ("reader", "writer")
    other = {("alice", "reader", "beta"), ("bob", "writer", "alpha")}
    policies = [[role, domain, "records/*", action] for role, action in zip(roles, ("read", "write")) for domain in ("alpha", "beta")]
    cases, reference, observed, counts = [], [], [], {}
    def invoke(engine, call, env):
        name = call["method"]
        counts[name] = counts.get(name, 0) + 1
        return getattr(engine, name)(*[env[arg] for arg in call["arguments"]])
    for mask, selected, action in product(range(4), [("add", r) for r in roles] + [("set", r) for r in roles] + [("remove", None)], ("read", "write")):
        operation, role = selected
        before = {value for i, value in enumerate(roles) if mask & (1 << i)}
        expected = before | {role} if operation == "add" else {role} if operation == "set" else set()
        expected_rows = other | {("alice", r, "alpha") for r in expected}
        engine = engine_factory(model_text, policies, sorted(other | {("alice", r, "alpha") for r in before}))
        env = {"user_id": "alice", "role": role, "tenant_id": "alpha"}
        error_name = None
        try:
            for call in descriptor["operations"][operation]["calls"]:
                if "loop" in call:
                    old_roles = invoke(engine, call["loop"], env)
                    if type(old_roles) is not list or any(type(item) is not str for item in old_roles) or len(old_roles) > 8:
                        raise AdmissionError("native direct-role snapshot is outside finite envelope", "native_error")
                    for old in old_roles:
                        invoke(engine, call["body"], {**env, "old": old})
                else:
                    invoke(engine, call, env)
        except AdmissionError:
            raise
        except Exception as error:
            error_name = type(error).__name__
        actual_rows = {tuple(row) for row in engine.get_grouping_policy()}
        decision = engine.enforce("alice", "alpha", "records/doc", action)
        if type(decision) is not bool:
            raise AdmissionError("native domain consumer result is not Boolean", "native_error")
        counts["enforce"] = counts.get("enforce", 0) + 1
        def flags(rows, expected_universe, error):
            return {"reader_retained": ("alice", "reader", "alpha") in rows,
                    "writer_retained": ("alice", "writer", "alpha") in rows,
                    "other_tenant_intact": {row for row in rows if row[2] != "alpha"} == {("alice", "reader", "beta")},
                    "other_user_intact": {row for row in rows if row[0] != "alice"} == {("bob", "writer", "alpha")},
                    "unexpected_grouping_absent": rows <= expected_universe, "native_error": error}
        reference.append({"decision": "allow" if roles[("read", "write").index(action)] in expected else "deny",
                          "flags": flags(expected_rows, expected_rows, False)})
        observed.append({"decision": "allow" if decision else "deny", "flags": flags(actual_rows, expected_rows, error_name is not None)})
        cases.append({"initial_target_roles": sorted(before), "operation": operation, "requested_role": role, "action": action,
                      "expected_grouping": sorted(expected_rows), "observed_grouping": sorted(actual_rows), "native_error": error_name})
    result = compare_observations(reference, observed, "selected serial native domain-role mutations followed by a direct native consumer; provided complete grouping and role-replacement contract")
    return {"accepted": result["accepted"], "status": result["status"], "descriptor": descriptor, "cases": cases,
            "reference": reference, "observed": observed, "comparison": result, "native_operations": counts,
            "native_policy_rows": policies, "full_permission_check_chain_verified": False,
            "database_scd2_commit_adapter_or_threadpool_verified": False, "whole_application_verified": False}
