"""Source-bound exact-row mutation/consumer histories on owned temporary data.

Application modules are parsed, never imported. Native FileAdapter operations
use only a fresh owned file. Persistence expectations are a separately supplied
contract, not inferred from the adapter's observed result. An API's allow/deny
labels encode its Boolean result, not authority to administer the policy.
"""
import ast
from itertools import product
from pathlib import Path
from tempfile import TemporaryDirectory

from checker import verify_reachable
from language import normalize
from native_casbin import AdmissionError, MAX_TEXT_BYTES, admit_configuration
from native_runtime import engine_identity
from native_state_export import observe_store, policy_store_specification
from source_bindings import require_import_bindings, require_static_class_members


def shape(node):
    return ast.dump(node, include_attributes=False)


def body_shape(statements):
    return [shape(item) for item in statements]


def strip_docstring(statements):
    if statements and isinstance(statements[0], ast.Expr) and isinstance(statements[0].value, ast.Constant) and type(statements[0].value.value) is str:
        return statements[1:]
    return statements


def extract_store(source, class_name="PolicyEngine", methods=None):
    methods = methods or {"authorize": "authorize", "add": "add_policy_rule", "remove": "remove_policy_rule"}
    if (type(source) is not bytes or len(source) > MAX_TEXT_BYTES or type(class_name) is not str
            or set(methods) != {"authorize", "add", "remove"} or len(set(methods.values())) != 3
            or any(type(value) is not str or not value.isidentifier() for value in methods.values())):
        raise AdmissionError("store source/selected methods are outside the typed envelope", "invalid")
    require_import_bindings(source, {"casbin": ("casbin", 0, None), "os": ("os", 0, None)})
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("store source does not parse", "invalid") from error
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    if len(classes) != 1 or classes[0].bases or classes[0].keywords or classes[0].decorator_list:
        raise AdmissionError("selected store class must have one direct unmodified declaration")
    cls = classes[0]
    require_static_class_members(cls, ["__init__", *methods.values()])
    constructor = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
    expected_constructor = ast.parse("""
def __init__(self, secret_key, policy_path=None):
    self._secret_key = secret_key
    self._enforcer = casbin.Enforcer(_MODEL_PATH, policy_path) if policy_path else casbin.Enforcer(_MODEL_PATH)
    self._enforcer.enable_auto_save(True)
""").body[0]
    if (constructor.decorator_list or constructor.args.posonlyargs or constructor.args.kwonlyargs
            or constructor.args.vararg or constructor.args.kwarg
            or [arg.arg for arg in constructor.args.args] != ["self", "secret_key", "policy_path"]
            or [shape(item) for item in constructor.args.defaults] != [shape(ast.Constant(None))]
            or body_shape(strip_docstring(constructor.body)) != body_shape(expected_constructor.body)):
        raise AdmissionError("constructor/model/file/auto-save binding needs a separate translation")
    model_bindings = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                      and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "_MODEL_PATH"]
    model_expression = ast.parse("os.path.join(os.path.dirname(__file__), 'policy_model.conf')", mode="eval").body
    if len(model_bindings) != 1 or shape(model_bindings[0].value) != shape(model_expression):
        raise AdmissionError("source model must be the directly adjacent static model member")
    # Also reject module-level conditional rebindings of the selected class,
    # model symbol and exception primitive without evaluating arbitrary effects.
    writes = {class_name: 0, "_MODEL_PATH": 0, "Exception": 0}
    def count(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in writes:
                writes[node.name] += 1
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in writes:
            writes[node.id] += 1
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                if name in writes:
                    writes[name] += 1
        for child in ast.iter_child_nodes(node):
            count(child)
    for statement in tree.body:
        count(statement)
    if writes != {class_name: 1, "_MODEL_PATH": 1, "Exception": 0}:
        raise AdmissionError("store class/model/exception binding is rebound")
    result = {}
    native_names = {"authorize": "enforce", "add": "add_policy", "remove": "remove_policy"}
    for operation, method in methods.items():
        node = next(item for item in cls.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == method)
        args = node.args
        parameters = [arg.arg for arg in args.args]
        if (node.decorator_list or args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg or args.defaults
                or len(parameters) != 4 or parameters[0] != "self" or len(set(parameters)) != 4
                or bool(isinstance(node, ast.AsyncFunctionDef)) != (operation == "authorize")):
            raise AdmissionError("selected method signature/async return protocol changed")
        body = strip_docstring(node.body)
        if operation == "authorize":
            expected = ast.parse("""
try:
    return self._enforcer.enforce(subject, skill_id, action)
except Exception:
    logger.exception('authorize failed for (%s, %s, %s)', subject, skill_id, action)
    raise
""").body
            if parameters != ["self", "subject", "skill_id", "action"] or body_shape(body) != body_shape(expected):
                raise AdmissionError("authorize normal/exception path needs a separate translation")
            body = body[0].body
        if (len(body) != 1 or not isinstance(body[0], ast.Return) or not isinstance(body[0].value, ast.Call)
                or body[0].value.keywords or len(body[0].value.args) != 3):
            raise AdmissionError("store method is not one direct native return")
        call = body[0].value
        expected_func = ast.parse("self._enforcer." + native_names[operation], mode="eval").body
        if shape(call.func) != shape(expected_func) or any(not isinstance(value, ast.Name) or value.id not in parameters[1:] for value in call.args):
            raise AdmissionError("store method native binding is unresolved")
        result[operation] = {"method": method, "line": node.lineno, "end_line": node.end_lineno,
                             "native_method": native_names[operation],
                             "argument_positions": [parameters[1:].index(value.id) for value in call.args],
                             "async_function": isinstance(node, ast.AsyncFunctionDef)}
    return {"class": class_name, "model_basename": "policy_model.conf", "auto_save": True, "methods": result,
            "source_module_executed": False, "arbitrary_runtime_rebinding_verified": False,
            "native_exception_path_evaluated": False}


def persistent_specification(rows, initial=0):
    # Reuse the strict row/initial admission, not a table generated from native
    # observations. State ordering is disk_0..disk_n, memory_0..memory_n.
    base = policy_store_specification(rows, initial)
    n = len(rows)
    if n > 3:
        raise AdmissionError("two-layer store is bounded to three rows/six bits", "inconclusive")
    policy = {key: base[key] for key in ("principals", "resources", "roles", "members", "aliases")}
    policy.update(actions=["add", "authorize", "remove", "restart"],
                  state=[[f"{layer}_{i}", bool(initial & (1 << i))] for layer in ("disk", "memory") for i in range(n)], rules=[])
    literal = lambda field, name: {"field": field, "name": name, "negated": False}
    for i, label in enumerate(base["resources"]):
        for action in ("add", "authorize", "remove"):
            policy["rules"].append({"decision": "allow", "guard": [literal("resource", label), literal("action", action),
                {"field": "state", "name": f"memory_{i}", "value": action != "add"}],
                "updates": [{"name": f"{layer}_{i}", "value": action == "add"} for layer in ("disk", "memory")] if action != "authorize" else []})
    policy["rules"].append({"decision": "allow", "guard": [literal("action", "restart")],
                             "updates": [{"name": f"memory_{i}", "from": f"disk_{i}", "negated": False} for i in range(n)]})
    return normalize(policy)


def compare_store(source, model_text, rows, *, initial=0, persistence=True, owned_explicit_save=False):
    if type(persistence) is not bool or type(owned_explicit_save) is not bool:
        raise AdmissionError("comparison mode must be Boolean", "invalid")
    descriptor = extract_store(source)
    policy = persistent_specification(rows, initial) if persistence else policy_store_specification(rows, initial)
    if not persistence:
        policy["actions"].remove("has")
        policy["rules"] = [rule for rule in policy["rules"] if not any(atom.get("field") == "action" and atom.get("name") == "has" for atom in rule["guard"])]
        policy = normalize(policy)
    admitted = admit_configuration(model_text, "\n".join("p, " + ", ".join(row) for row in rows))
    if admitted.family != "basic":
        raise AdmissionError("only complete exact-row policies are bound to this store interface")
    identity = engine_identity()
    import casbin
    n = len(rows)
    if n > 3:
        raise AdmissionError("source-bound store work is bounded to three rows", "inconclusive")
    alphabet = [list(request) for request in product(policy["principals"], policy["resources"], policy["actions"])]
    operations = {"enforce": 0, "add_policy": 0, "remove_policy": 0, "restart": 0, "owned_save_policy": 0}
    def file_text(mask):
        return "\n".join("p, " + ", ".join(row) for i, row in enumerate(rows) if mask & (1 << i))
    def create(path):
        try:
            engine = casbin.Enforcer(str(path.with_name(descriptor["model_basename"])), str(path))
            engine.enable_auto_save(descriptor["auto_save"])
        except Exception as error:
            raise AdmissionError("native file-policy construction failed: " + type(error).__name__, "native_error") from error
        return engine
    table = []
    with TemporaryDirectory(prefix="authrefine-owned-store-") as scratch:
        path = Path(scratch) / "policy.csv"
        path.with_name(descriptor["model_basename"]).write_text(model_text, encoding="utf-8")
        for mask in range(2 ** (2 * n if persistence else n)):
            memory = mask >> n if persistence else mask
            disk = mask & ((1 << n) - 1) if persistence else memory
            transitions = []
            for _, label, action in alphabet:
                path.write_text(file_text(disk), encoding="utf-8")
                engine = create(path)
                # Observation-table preparation is owned setup, not a claimed
                # application operation or reachable production history.
                engine.enable_auto_save(False)
                engine.clear_policy()
                for i, row in enumerate(rows):
                    if memory & (1 << i):
                        engine.add_policy(*row)
                engine.enable_auto_save(descriptor["auto_save"])
                if observe_store(engine, rows) != memory:
                    raise AdmissionError("owned table setup differs from the declared memory state")
                if action == "restart":
                    engine = create(path)
                    value = True
                    operations["restart"] += 1
                else:
                    method = descriptor["methods"][action]
                    row = rows[int(label.removeprefix("permission_"))]
                    actual = [row[index] for index in method["argument_positions"]]
                    try:
                        value = getattr(engine, method["native_method"])(*actual)
                    except Exception as error:
                        raise AdmissionError("native store operation failed: " + type(error).__name__, "native_error") from error
                    operations[method["native_method"]] += 1
                    if owned_explicit_save and action in ("add", "remove") and value is True:
                        engine.save_policy()
                        operations["owned_save_policy"] += 1
                if type(value) is not bool:
                    raise AdmissionError("selected native API did not return a Boolean", "native_error")
                after_memory = observe_store(engine, rows)
                after_disk = admit_configuration(model_text, path.read_text(encoding="utf-8")).rows
                positions = {tuple(row): i for i, row in enumerate(rows)}
                if (len({tuple(row) for row in after_disk}) != len(after_disk)
                        or any(row[0] != "p" or tuple(row[1:]) not in positions for row in after_disk)):
                    raise AdmissionError("native file has a row outside the complete observation universe")
                disk_mask = sum(1 << positions[tuple(row[1:])] for row in after_disk)
                post = disk_mask | (after_memory << n) if persistence else after_memory
                transitions.append(["allow" if value else "deny", post])
            table.append(transitions)
    machine = {"state_names": [name for name, _ in policy["state"]], "alphabet": alphabet,
               "observations": list(range(len(table))), "initial": initial | (initial << n) if persistence else initial,
               "transitions": table}
    result = verify_reachable(policy, machine)
    return {"accepted": result["accepted"], "status": result["status"], "descriptor": descriptor,
            "scope": "sequential exact-row source mutation/native consumer" + (" with persistent file/fresh-instance observations" if persistence else "; current-instance memory only"),
            "native_runtime": identity, "rows": rows, "policy": policy, "machine": machine, "comparison": result,
            "native_operations": operations, "table_cells": len(table) * len(alphabet),
            "owned_explicit_save_control": owned_explicit_save, "temporary_files_owned_only": True,
            "application_or_upstream_tests_executed": False, "complete_application_verified": False,
            "administrative_authorization_verified": False, "deployment_or_security_finding_confirmed": False}
