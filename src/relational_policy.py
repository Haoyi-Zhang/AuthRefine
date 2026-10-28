"""Typed source-adapter projection of a selected relational seed snapshot.

Application model/adapter modules are never imported. Only the admitted source
comprehensions are interpreted on projected records. An independent relational
join is run in an owned SQLite database, not on a third-party service/database.
"""
import ast
import sqlite3

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from sql_seed import project_seed
from source_bindings import require_import_bindings


def _tree(source):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("adapter source exceeds byte envelope", "inconclusive")
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("adapter source does not parse", "invalid") from error


def _one_class(tree, name):
    nodes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name]
    if len(nodes) != 1:
        raise AdmissionError("source model class is missing or ambiguous")
    def writes(node):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            return int(node.name == name)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return sum((alias.asname or alias.name.split(".")[0]) == name for alias in node.names)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id == name:
            return 1
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id == name:
                return 1
        return sum(writes(child) for child in ast.iter_child_nodes(node))
    if sum(writes(node) for node in tree.body) != 1:
        raise AdmissionError("source class or its methods are rebound outside the admitted declaration")
    return nodes[0]


def _body(function):
    return [n for n in function.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]


def _same(node, statement):
    return ast.dump(node, include_attributes=False) == ast.dump(ast.parse(statement).body[0], include_attributes=False)


def _table(model):
    metas = [n for n in model.body if isinstance(n, ast.ClassDef) and n.name == "Meta"]
    if len(metas) != 1:
        raise AdmissionError("model table declaration is ambiguous")
    declarations = [n for n in metas[0].body if isinstance(n, ast.Assign) and len(n.targets) == 1
                    and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "db_table"]
    if len(declarations) != 1 or not isinstance(declarations[0].value, ast.Constant) or type(declarations[0].value.value) is not str:
        raise AdmissionError("model table needs one literal name")
    return declarations[0].value.value


def _relation(model, field, target, reverse):
    nodes = [n for n in model.body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == field]
    if len(nodes) != 1:
        raise AdmissionError("model relation is missing or ambiguous")
    call = nodes[0].value
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name) and call.func.value.id == "models"
            and call.func.attr == "ManyToManyField" and not call.args):
        raise AdmissionError("model relation differs from the typed many-to-many fragment")
    keywords = {k.arg: k.value for k in call.keywords}
    if None in keywords or len(keywords) != len(call.keywords) or set(keywords) - {"to", "related_name", "verbose_name", "blank"}:
        raise AdmissionError("custom through/manager or expanded relation arguments need another contract")
    to = keywords.get("to")
    if not (isinstance(to, ast.Name) and to.id == target or isinstance(to, ast.Constant) and to.value == target):
        raise AdmissionError("model relation target changed")
    related = keywords.get("related_name")
    if not isinstance(related, ast.Constant) or related.value != reverse:
        raise AdmissionError("model relation reverse name changed")


def _projection(model, collection, item_fields, self_fields):
    methods = [n for n in model.body if isinstance(n, ast.FunctionDef) and n.name == "adapter"]
    if len(methods) != 1 or methods[0].decorator_list or [a.arg for a in methods[0].args.args] != ["self"]:
        raise AdmissionError("model adapter method is missing or ambiguous")
    method = methods[0]
    if method.args.vararg or method.args.kwarg or method.args.kwonlyargs or method.args.posonlyargs or method.args.defaults:
        raise AdmissionError("model adapter signature needs a separate contract")
    body = _body(method)
    if len(body) != 1 or not isinstance(body[0], ast.Return) or not isinstance(body[0].value, ast.ListComp):
        raise AdmissionError("model adapter is not a single projection comprehension")
    expression = body[0].value
    if len(expression.generators) != 1 or not isinstance(expression.elt, ast.Dict):
        raise AdmissionError("adapter comprehension shape is unsupported")
    gen = expression.generators[0]
    if (gen.ifs or gen.is_async or not isinstance(gen.target, ast.Name)
            or ast.dump(gen.iter, include_attributes=False) != ast.dump(ast.parse("self." + collection + ".all()", mode="eval").body, include_attributes=False)):
        raise AdmissionError("adapter relation iterator changed")
    fields, keys = [], []
    for key, value in zip(expression.elt.keys, expression.elt.values):
        if not isinstance(key, ast.Constant) or type(key.value) is not str or key.value in keys:
            raise AdmissionError("adapter dictionary has expanded or ambiguous keys")
        keys.append(key.value)
        if isinstance(value, ast.Constant) and type(value.value) is str:
            fields.append({"literal": value.value})
        elif isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
            origin, allowed = ("self", self_fields) if value.value.id == "self" else ("item", item_fields) if value.value.id == gen.target.id else (None, ())
            if origin is None or value.attr not in allowed:
                raise AdmissionError("adapter projection references an unbound model field")
            fields.append({"origin": origin, "field": value.attr})
        else:
            raise AdmissionError("adapter projection contains an unreviewed expression")
    if len(fields) not in (3, 4):
        raise AdmissionError("adapter row has an undeclared width")
    return {"line": method.lineno, "end_line": method.end_lineno, "dictionary_order": keys, "values": fields}


def extract_relational_adapter(adapter_source, model_source, user_source, *, role_model_module="apps.pgo_permission.models"):
    bindings = require_import_bindings(adapter_source, {"persist": ("casbin", 0, "persist"), "Role": ("models", 2, "Role"), "Rule": ("models", 2, "Rule")})
    require_import_bindings(model_source, {"models": ("django.db", 0, "models")})
    require_import_bindings(user_source, {"models": ("django.db", 0, "models"), "Role": (role_model_module, 0, "Role")})
    adapter = _one_class(_tree(adapter_source), "Adapter")
    functions = {n.name: n for n in adapter.body if isinstance(n, ast.FunctionDef)}
    if not {"__init__", "load_policy"} <= set(functions):
        raise AdmissionError("adapter loader is absent")
    for name, parameters in (("__init__", ["self"]), ("load_policy", ["self", "model"])):
        function = functions[name]
        a = function.args
        if (function.decorator_list or [p.arg for p in a.args] != parameters or a.posonlyargs or a.kwonlyargs
                or a.vararg or a.kwarg or a.defaults):
            raise AdmissionError("adapter loader input signature changed")
    init = _body(functions["__init__"])
    if len(init) != 1 or not _same(init[0], "self.adapter_models = [Role, Rule]"):
        raise AdmissionError("adapter model selection changed")
    expected = '''for db in self.adapter_models:
    for qs in db.objects.all():
        for item in qs.adapter():
            values = list(item.values())
            persist.load_policy_line(", ".join(values), model)'''
    body = _body(functions["load_policy"])
    if len(body) != 1 or not _same(body[0], expected):
        raise AdmissionError("adapter loader ordering/data flow changed")
    tree = _tree(model_source)
    role, rule = (_one_class(tree, name) for name in ("Role", "Rule"))
    user = _one_class(_tree(user_source), "UserProfile")
    _relation(role, "rule", "Rule", "role")
    _relation(user, "role", "Role", "user")
    tables = {"role": _table(role), "rule": _table(rule), "user": _table(user)}
    tables["role_rule"] = tables["role"] + "_rule"
    tables["user_role"] = tables["user"] + "_role"
    return {"tables": tables, "source_imports": bindings,
            "role_projection": _projection(role, "user", {"username"}, {"name"}),
            "rule_projection": _projection(rule, "role", {"name"}, {"path", "method", "name"}),
            "native_orm_or_application_module_executed": False,
            "relation_assumption": "ordinary Django default many-to-many tables, supplied complete selected seed rows",
            "inherited_model_managers_and_query_order_executed": False}


def compile_relational_seed(descriptor, sql_source):
    names = descriptor["tables"]
    fields = {"role": ["id", "name"], "rule": ["id", "name", "path", "method"], "user": ["id", "username"],
              "role_rule": ["id", "role_id", "rule_id"], "user_role": ["id", "userprofile_id", "role_id"]}
    seed = project_seed(sql_source, {names[key]: value for key, value in fields.items()})
    records = {key: [row["fields"] for row in seed["tables"][name]] for key, name in names.items()}
    by_id = {}
    for kind, rows in records.items():
        by_id[kind] = {}
        for row in rows:
            identifier = row["id"]
            if type(identifier) is not int or identifier in by_id[kind]:
                raise AdmissionError("seed primary key is invalid or duplicated", "invalid")
            by_id[kind][identifier] = row
    for kind, field in (("role", "name"), ("user", "username")):
        values = [row[field] for row in records[kind]]
        if any(type(value) is not str or not value for value in values) or len(set(values)) != len(values):
            raise AdmissionError("seed role/user identity is invalid or duplicated", "invalid")
    for relation, ends in (("role_rule", (("role_id", "role"), ("rule_id", "rule"))),
                           ("user_role", (("userprofile_id", "user"), ("role_id", "role")))):
        for row in records[relation]:
            for field, target in ends:
                if type(row[field]) is not int or row[field] not in by_id[target]:
                    raise AdmissionError("seed relation endpoint is missing or invalid", "invalid")
    def project(shape, subject, item):
        values = [term["literal"] if "literal" in term else (subject if term["origin"] == "self" else item)[term["field"]]
                  for term in shape["values"]]
        if any(type(value) is not str or not value or value != value.strip() or any(c in value for c in ",\r\n") for value in values):
            raise AdmissionError("adapter source row cannot be transported losslessly by its CSV loader")
        return values
    produced = []
    for role in records["role"]:
        for link in records["user_role"]:
            if link["role_id"] == role["id"]:
                produced.append(project(descriptor["role_projection"], role, by_id["user"][link["userprofile_id"]]))
    for rule in records["rule"]:
        for link in records["role_rule"]:
            if link["rule_id"] == rule["id"]:
                produced.append(project(descriptor["rule_projection"], rule, by_id["role"][link["role_id"]]))
    # Independent reference: relational joins, not the source comprehension's
    # dictionary order or its interpreted row projection.
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript("CREATE TABLE roles(id INTEGER PRIMARY KEY,name TEXT); CREATE TABLE rules(id INTEGER PRIMARY KEY,name TEXT,path TEXT,method TEXT); CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT); CREATE TABLE rr(id INTEGER PRIMARY KEY,role_id INTEGER,rule_id INTEGER); CREATE TABLE ur(id INTEGER PRIMARY KEY,userprofile_id INTEGER,role_id INTEGER);")
        for key, table in (("role", "roles"), ("rule", "rules"), ("user", "users"), ("role_rule", "rr"), ("user_role", "ur")):
            selected = fields[key]
            connection.executemany("INSERT INTO " + table + " VALUES (" + ",".join("?" for _ in selected) + ")",
                                   [[row[field] for field in selected] for row in records[key]])
        reference = [["g", *row] for row in connection.execute("SELECT users.username,roles.name FROM ur JOIN users ON users.id=ur.userprofile_id JOIN roles ON roles.id=ur.role_id ORDER BY roles.id,ur.id")]
        reference += [["p", *row] for row in connection.execute("SELECT roles.name,rules.path,rules.method FROM rr JOIN roles ON roles.id=rr.role_id JOIN rules ON rules.id=rr.rule_id ORDER BY rules.id,rr.id")]
    finally:
        connection.close()
    accepted = sorted(produced) == sorted(reference)
    return {"status": "agreement" if accepted else "mismatch", "accepted": accepted,
            "source_projection_type_contract": projection_type_contract(descriptor),
            "produced_rows": produced, "reference_rows": reference, "row_counts": {kind: len(rows) for kind, rows in records.items()},
            "source_projection": descriptor, "projected_seed": seed,
            "source_sql_executed": False, "application_or_django_orm_executed": False,
            "owned_reference_database": "SQLite memory, projected fields only; two independent relational SELECT joins",
            "current_deployment_state_verified": False}


def projection_type_contract(descriptor):
    expected = {"role_projection": [{"literal": "g"}, {"origin": "item", "field": "username"}, {"origin": "self", "field": "name"}],
                "rule_projection": [{"literal": "p"}, {"origin": "item", "field": "name"}, {"origin": "self", "field": "path"}, {"origin": "self", "field": "method"}]}
    checks = {key: descriptor.get(key, {}).get("values") == values for key, values in expected.items()}
    return {"admitted": all(checks.values()), "checks": checks, "canonical_terms": expected,
            "scope": "typed field-order contract before CSV transport; no full Python/ORM extraction theorem"}
