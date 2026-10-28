"""An admitted REST RBAC schema with literal methods and an explicit override.

Comparison is over a declared finite request domain. keyMatch2 segment matching
and literal regex-prefix matching have separate reference implementations;
arbitrary regexes, URL normalization and complete application behavior are not
claimed. Native authorization uses the selected pinned Casbin engine.
"""
import configparser
import ast
import json
import re

from checker import verify_reachable
from language import named, normalize, PolicyError
from native_casbin import AdmissionError, Configuration, MAX_NATIVE_WORK, MAX_TEXT_BYTES, _compact, _check_role_depth, _engine
from native_runtime import engine_identity
from public_inputs import closure
from source_bindings import require_import_bindings


def extract_rest_consumer(source, *, class_name="ApiRBACPermission", adapter_module="apps.pgo_permission.utils.adapter", model_path="config/prem_model.conf"):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("REST consumer source exceeds envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("REST consumer source does not parse", "invalid") from error
    imports = {"os": ("os", 0, None), "casbin": ("casbin", 0, None),
        "settings": ("django.conf", 0, "settings"), "BasePermission": ("rest_framework.permissions", 0, "BasePermission"),
        "Adapter": (adapter_module, 0, "Adapter")}
    bindings = require_import_bindings(source, imports)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "verify_permission"]
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name]
    if len(functions) != 1 or len(classes) != 1:
        raise AdmissionError("REST source consumer is missing or ambiguous")
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if any((alias.asname or alias.name.split(".")[0]) not in imports for alias in node.names):
                raise AdmissionError("REST module has an unreviewed import initializer")
        elif isinstance(node, ast.FunctionDef) and node is functions[0]:
            pass
        elif isinstance(node, ast.ClassDef) and node is classes[0]:
            pass
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str:
            pass
        else:
            raise AdmissionError("REST module has an unreviewed initializer or conditional rebinding")
    fn = functions[0]
    a = fn.args
    if (fn.decorator_list or a.args or a.posonlyargs or a.kwonlyargs or a.kwarg or a.defaults
            or a.vararg is None or a.vararg.arg != "args"):
        raise AdmissionError("REST native wrapper does not preserve its declared tuple interface")
    parts = model_path.split("/")
    if not parts or any(not part or part in (".", "..") or not re.fullmatch(r"[A-Za-z_0-9.-]+", part) for part in parts):
        raise AdmissionError("REST model path is outside the relative literal fragment")
    expected = '''adapter = Adapter()
model_conf_file = os.path.join(settings.BASE_DIR, ''' + ", ".join(json.dumps(part) for part in parts) + ''')
e = casbin.Enforcer(model_conf_file, adapter=adapter)
return e.enforce(*args)'''
    body = [n for n in fn.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]
    if [ast.dump(n, include_attributes=False) for n in body] != [ast.dump(n, include_attributes=False) for n in ast.parse(expected).body]:
        raise AdmissionError("REST model/adapter/engine argument binding changed")
    cls = classes[0]
    if cls.decorator_list or [ast.dump(n, include_attributes=False) for n in cls.bases] != [ast.dump(ast.Name(id="BasePermission", ctx=ast.Load()), include_attributes=False)]:
        raise AdmissionError("REST permission class has another base/decorator contract")
    methods = [n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "has_permission"]
    if len(methods) != 1 or not isinstance(methods[0], ast.FunctionDef):
        raise AdmissionError("REST permission method is missing or ambiguous")
    method = methods[0]
    if cls.body != [method]:
        raise AdmissionError("REST permission class contains another initializer or override")
    a = method.args
    if (method.decorator_list or [p.arg for p in a.args] != ["self", "request", "view"] or a.vararg or a.kwarg
            or a.posonlyargs or a.kwonlyargs or a.defaults):
        raise AdmissionError("REST permission input signature changed")
    expected = '''path = request.META["PATH_INFO"]
username = request.user.username
method = request.method
return verify_permission(username, path, method)'''
    if [ast.dump(n, include_attributes=False) for n in method.body] != [ast.dump(n, include_attributes=False) for n in ast.parse(expected).body]:
        raise AdmissionError("REST request decoding/argument order is outside the admitted binding")
    # This checks source declarations only, not module initializer execution.
    protected = {"verify_permission", class_name}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in protected for t in targets):
                raise AdmissionError("REST consumer primitive was rebound")
    return {"wrapper_lines": [fn.lineno, fn.end_lineno], "request_method_lines": [method.lineno, method.end_lineno],
        "model_path": model_path, "tuple_order": ["request.user.username", "request.META[PATH_INFO]", "request.method"],
        "adapter_binding": adapter_module + ".Adapter", "source_imports": bindings,
        "source_module_or_http_server_executed": False}


def rest_schema(subject):
    return {"request_definition": {"r": "sub, obj, act"}, "policy_definition": {"p": "sub, obj, act"},
            "role_definition": {"g": "_, _"}, "policy_effect": {"e": "some(where (p.eft == allow))"},
            "matchers": {"m": 'g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && (p.act == "*" || regexMatch(r.act, p.act)) || r.sub == ' + json.dumps(subject)}}


def path_tokens(pattern):
    if pattern == "*":
        return ["*"]
    if not pattern.startswith("/") or len(pattern) > 256:
        raise AdmissionError("REST path pattern must be absolute and bounded")
    parts = pattern.split("/")[1:]
    for index, value in enumerate(parts):
        if value == "*" and index == len(parts) - 1:
            continue
        if value.startswith(":") and re.fullmatch(r":[a-zA-Z_][a-zA-Z_0-9]*", value):
            continue
        if not re.fullmatch(r"[a-zA-Z_0-9-]*", value):
            raise AdmissionError("REST path includes regex or an unsupported wildcard")
    return parts


def segment_match(path, pattern):
    parts = path_tokens(pattern)
    if parts == ["*"] and pattern == "*":
        return True
    if not path.startswith("/"):
        return False
    actual = path.split("/")[1:]
    for index, token in enumerate(parts):
        if token == "*":
            # /x/* requires the slash after x, unlike an unqualified /x prefix.
            return len(actual) > index
        if index >= len(actual) or token.startswith(":") and not actual[index] or not token.startswith(":") and actual[index] != token:
            return False
    return len(actual) == len(parts)


def admit_rest_policy(model_text, rows):
    if not isinstance(model_text, str) or len(model_text.encode()) > MAX_TEXT_BYTES:
        raise AdmissionError("REST model text exceeds envelope", "inconclusive")
    parser = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=True)
    try:
        parser.read_string(model_text)
        matcher = parser.get("matchers", "m")
    except configparser.Error as error:
        raise AdmissionError("REST model is unreadable", "invalid") from error
    actual = {section: {k: _compact(v) for k, v in parser.items(section)} for section in parser.sections()}
    match = re.search(r'\|\|\s*r\.sub\s*==\s*("(?:[^"\\]|\\.)*")\s*$', matcher)
    if match is None:
        raise AdmissionError("REST override must be one explicit string literal")
    try:
        override = json.loads(match.group(1))
    except ValueError as error:
        raise AdmissionError("REST override string is invalid", "invalid") from error
    if not named(override) or any(c in override for c in '\",[]()'):
        raise AdmissionError("REST override identifier is outside its literal fragment")
    expected = {section: {k: _compact(v) for k, v in fields.items()} for section, fields in rest_schema(override).items()}
    if parser.defaults() or actual != expected:
        raise AdmissionError("REST matcher, effect or model fields differ from the admitted schema")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 512:
        raise AdmissionError("REST policy row envelope exceeded", "inconclusive")
    policy_rows, texts = [], []
    for row in rows:
        if (not isinstance(row, list) or not all(named(value) and value == value.strip() and not any(c in value for c in '\",[]()') for value in row)
                or not (len(row) == 4 and row[0] == "p" or len(row) == 3 and row[0] == "g")):
            raise AdmissionError("REST policy contains invalid fields or undeclared row types")
        if row[0] == "p":
            path_tokens(row[2])
            if row[3] != "*" and not re.fullmatch(r"[A-Z]+", row[3]):
                raise AdmissionError("REST method pattern must be wildcard or one literal uppercase prefix")
        policy_rows.append(list(row))
        texts.append(", ".join(row))
    if not any(row[0] == "p" for row in rows):
        raise AdmissionError("empty-policy override semantics require a separate native contract")
    _check_role_depth("rest_override", policy_rows)
    return Configuration("rest_override", model_text, "\n".join(texts), policy_rows, list(range(1, len(rows) + 1))), override


def compare_rest_policy(model_text, rows, domain, reference_rows=None):
    configuration, override = admit_rest_policy(model_text, rows)
    reference, reference_override = admit_rest_policy(model_text, rows if reference_rows is None else reference_rows)
    if override != reference_override:
        raise AdmissionError("reference override differs")
    if not isinstance(domain, dict) or set(domain) != {"principals", "resources", "actions"}:
        raise AdmissionError("REST comparison requires three explicit request domains", "invalid")
    for key, values in domain.items():
        if not isinstance(values, list) or not values or len(set(values)) != len(values) or any(not named(value) for value in values):
            raise AdmissionError("REST finite domain contains invalid or duplicate inputs", "invalid")
        if len(values) > (16 if key == "principals" else 32):
            raise AdmissionError("REST request domain envelope exceeded", "inconclusive")
    if len(domain["principals"]) * len(domain["resources"]) * len(domain["actions"]) * len(rows) > MAX_NATIVE_WORK:
        raise AdmissionError("REST native work envelope exceeded", "inconclusive")
    policies = [row for row in reference.rows if row[0] == "p"]
    roles = sorted({row[1] for row in policies})
    edges = [(row[1], row[2]) for row in reference.rows if row[0] == "g"]
    policy = {**domain, "roles": roles, "members": [[user, role] for user in domain["principals"] for role in roles if role in closure(edges, user)],
              "state": [], "aliases": [], "rules": []}
    atom = lambda field, name, negated=False: {"field": field, "name": name, "negated": negated}
    if override in domain["principals"]:
        policy["rules"].append({"decision": "allow", "guard": [atom("principal", override)], "updates": []})
    for role in roles:
        for resource in domain["resources"]:
            allowed = {action for _, subject, pattern, method in policies if subject == role and segment_match(resource, pattern)
                       for action in domain["actions"] if method == "*" or action.startswith(method)}
            if not allowed:
                continue
            excluded = set(domain["actions"]) - allowed
            base = [atom("role", role), atom("resource", resource)]
            alternatives = [[atom("action", action, True) for action in sorted(excluded)]] if 3 + len(excluded) <= 4 * len(allowed) else [[atom("action", action)] for action in sorted(allowed)]
            for guards in alternatives:
                policy["rules"].append({"decision": "allow", "guard": base + guards, "updates": []})
    try:
        policy = normalize(policy)
    except PolicyError as error:
        raise AdmissionError(str(error), "inconclusive" if error.category == "LIMIT" else "invalid") from error
    engine = _engine(configuration)
    alphabet = [[u, r, a] for u in policy["principals"] for r in policy["resources"] for a in policy["actions"]]
    cells = []
    for request in alphabet:
        try:
            result = engine.enforce(*request)
        except Exception as error:
            raise AdmissionError("native REST decision failed: " + type(error).__name__, "native_error") from error
        if type(result) is not bool:
            raise AdmissionError("native REST decision is not Boolean", "native_error")
        cells.append(["allow" if result else "deny", 0])
    machine = {"state_names": [], "alphabet": alphabet, "observations": [0], "initial": 0, "transitions": [cells]}
    comparison = verify_reachable(policy, machine)
    return {"status": comparison["status"], "accepted": comparison["accepted"], "policy": policy, "machine": machine,
            "comparison": comparison, "native_runtime": engine_identity(), "native_enforce_calls": len(alphabet),
            "scope": "source/reference policy comparison on an explicit finite request domain",
            "unlisted_paths_or_application_verified": False, "override_subject": override}
