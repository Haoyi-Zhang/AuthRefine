"""Bounded async source slices over supplied, immutable database snapshots.

Await is interpreted as an explicit owned result token, not by executing an
application coroutine. Query/model objects below are ours; no ORM is imported.
Initialization, transactions, concurrency and later database writes are outside
this ready-interface contract, not silently translated as no-ops.
"""
import ast
from dataclasses import dataclass
import re

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from policy_slice import PolicyInterpreter, Call, SELF, ENGINE, _NODES
from source_bindings import require_import_bindings, require_static_class_members, require_static_definitions

METHODS = ("_load_policy_from_db", "get_global_roles", "is_system_admin", "is_resource_owner", "enforce", "check_permission")
NATIVE = {"add_policy", "add_grouping_policy", "add_named_grouping_policy", "enforce"}
RESERVED = {"self", "str", "CasbinRule", "ResourceOwner", "len", "sorted", "re"}


def extract_snapshot_program(source, class_name="PermissionService", model_import_module="app.models.permission"):
    if type(source) is not bytes or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("async source exceeds byte envelope", "inconclusive")
    if (type(class_name) is not str or not class_name.isidentifier() or type(model_import_module) is not str
            or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", model_import_module)):
        raise AdmissionError("snapshot class/import selectors require static identifiers")
    require_import_bindings(source, {"CasbinRule": (model_import_module, 0, "CasbinRule"),
                                    "ResourceOwner": (model_import_module, 0, "ResourceOwner")})
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("async source does not parse", "invalid") from error
    require_static_definitions(tree, [class_name], reserved=("str", "property"))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    if len(classes) != 1 or classes[0].bases or classes[0].decorator_list or classes[0].keywords:
        raise AdmissionError("snapshot service needs one direct unmodified class")
    cls = classes[0]
    require_static_class_members(cls, set(METHODS) | {"_ensure_initialized", "enforcer"})
    protected = set(METHODS) | {"_ensure_initialized", "enforcer", "__getattribute__", "__getattr__"}
    for statement in cls.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if any(isinstance(node, ast.Name) and node.id in protected for target in targets for node in ast.walk(target)):
                raise AdmissionError("snapshot class rebinds a selected method or property")
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name in {"__getattribute__", "__getattr__"}:
            raise AdmissionError("dynamic snapshot instance attributes are not admitted")
    getters = [node for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "enforcer"]
    if len(getters) != 1 or not isinstance(getters[0], ast.FunctionDef) or len(getters[0].decorator_list) != 1 or ast.dump(getters[0].decorator_list[0]) != ast.dump(ast.Name(id="property", ctx=ast.Load())):
        raise AdmissionError("native ready-interface accessor must be the declared property")
    getter_body = [node for node in getters[0].body if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str)]
    if (len(getters[0].args.args) != 1 or getters[0].args.args[0].arg != "self" or getters[0].args.defaults
            or getters[0].args.posonlyargs or getters[0].args.kwonlyargs or getters[0].args.vararg or getters[0].args.kwarg
            or len(getter_body) != 2 or not isinstance(getter_body[0], ast.If)
            or ast.dump(getter_body[0].test) != ast.dump(ast.parse("self._enforcer is None", mode="eval").body)
            or getter_body[0].orelse or len(getter_body[0].body) != 1 or not isinstance(getter_body[0].body[0], ast.Raise)
            or ast.dump(getter_body[1]) != ast.dump(ast.parse("return self._enforcer").body[0])):
        raise AdmissionError("native ready-interface accessor changed")
    guards = [node for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_ensure_initialized"]
    expected = ast.parse("async def _ensure_initialized(self):\n if not self._initialized:\n  await self.init()\n").body[0]
    if len(guards) != 1 or not isinstance(guards[0], ast.AsyncFunctionDef) or guards[0].decorator_list:
        raise AdmissionError("ready-interface guard is ambiguous")
    body = [node for node in guards[0].body if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str)]
    if (ast.dump(guards[0].args, include_attributes=False) != ast.dump(expected.args, include_attributes=False)
            or [ast.dump(node, include_attributes=False) for node in body] != [ast.dump(node, include_attributes=False) for node in expected.body]):
        raise AdmissionError("initialization guard changed; ready-interface projection is unsupported")
    result = {}
    allowed = _NODES + (ast.Await, ast.Starred, ast.ListComp, ast.comprehension)
    for name in METHODS:
        matches = [node for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
        if len(matches) != 1 or not isinstance(matches[0], ast.AsyncFunctionDef) or matches[0].decorator_list:
            raise AdmissionError("snapshot method must have one undecorated async declaration: " + name)
        function, args = matches[0], matches[0].args
        if (args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg or args.defaults
                or not args.args or args.args[0].arg != "self" or len({arg.arg for arg in args.args}) != len(args.args)
                or any(arg.arg in RESERVED for arg in args.args[1:])):
            raise AdmissionError("snapshot method signature is outside the typed interface")
        nodes = [node for statement in function.body for node in ast.walk(statement)]
        parents = {id(child): parent for statement in function.body for parent in ast.walk(statement) for child in ast.iter_child_nodes(parent)}
        if len(nodes) > 4096:
            raise AdmissionError("snapshot AST budget exceeded", "inconclusive")
        for node in nodes:
            if not isinstance(node, allowed) or isinstance(node, ast.Lambda):
                raise AdmissionError("unsupported snapshot syntax: " + type(node).__name__)
            if isinstance(node, ast.Assign) and (len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name)):
                raise AdmissionError("snapshot assignments must be local names")
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id in RESERVED:
                raise AdmissionError("snapshot source shadows a bound primitive")
            if isinstance(node, ast.For) and (node.orelse or not isinstance(node.target, ast.Name)):
                raise AdmissionError("snapshot loops must have one local target and no else")
            if isinstance(node, ast.ListComp) and (len(node.generators) != 1 or node.generators[0].is_async or not isinstance(node.generators[0].target, ast.Name)):
                raise AdmissionError("snapshot comprehension requires one bounded synchronous generator")
            if isinstance(node, ast.FormattedValue) and (node.conversion != -1 or node.format_spec is not None):
                raise AdmissionError("snapshot formatting conversion is unsupported")
            if isinstance(node, ast.Attribute):
                source_async = isinstance(node.value, ast.Name) and node.value.id == "self" and node.attr in set(METHODS) | {"_ensure_initialized"}
                terminal_query = node.attr in {"all", "exists"}
                if source_async or terminal_query:
                    call = parents.get(id(node))
                    awaited = parents.get(id(call)) if call is not None else None
                    if (not isinstance(call, ast.Call) or call.func is not node
                            or not isinstance(awaited, ast.Await) or awaited.value is not call):
                        raise AdmissionError("async source/query results must be directly awaited; deferred coroutine/alias semantics are unsupported")
        result[name] = function
    return result


@dataclass(frozen=True)
class Pending:
    result: object


@dataclass(frozen=True)
class Record:
    fields: dict


@dataclass(frozen=True)
class Table:
    name: str


@dataclass(frozen=True)
class Query:
    name: str
    filters: dict


class SnapshotInterpreter(PolicyInterpreter):
    def __init__(self, program, rules, owners, native, ready=True, step_limit=50000):
        super().__init__(program, None, native, step_limit)
        self.tables = {"CasbinRule": tuple(Record(dict(row)) for row in rules),
                       "ResourceOwner": tuple(Record(dict(row)) for row in owners)}
        self.ready = ready
        self.query_counts = {}

    def run(self, name, arguments):
        if name == "_ensure_initialized":
            self.charge()
            if arguments or self.ready is not True:
                raise AdmissionError("ready-interface precondition is not established", "input_rejected")
            return None
        return super().run(name, arguments)

    def value(self, node, env):
        self.charge()
        bindings = {"str": Call("scalar-str"), "CasbinRule": Table("CasbinRule"), "ResourceOwner": Table("ResourceOwner")}
        env = {**env, **bindings}
        if isinstance(node, ast.Await):
            pending = self.value(node.value, env)
            if type(pending) is not Pending:
                raise AdmissionError("await requires a bound async source or query result")
            return pending.result
        if isinstance(node, ast.Attribute):
            base = self.value(node.value, env)
            if base is SELF:
                if node.attr in ("enforcer", "_enforcer"):
                    return ENGINE
                if node.attr == "_ensure_initialized":
                    return Call("source", node.attr)
            if base is ENGINE and node.attr in NATIVE:
                return Call("snapshot-native", node.attr)
            if type(base) is Record and node.attr in base.fields:
                return base.fields[node.attr]
            if type(base) in (Table, Query) and node.attr in ("all", "filter", "exists"):
                return Call("snapshot-query", base, node.attr)
            if type(base) is str and node.attr == "startswith":
                return Call("startswith", base)
        if isinstance(node, ast.ListComp):
            generator = node.generators[0]
            values = self.value(generator.iter, env)
            if type(values) not in (tuple, list) or len(values) > 128:
                raise AdmissionError("snapshot comprehension input is not bounded", "inconclusive")
            result = []
            for item in values:
                local = dict(env)
                self.bind(generator.target, item, local)
                if all(self.truth(self.value(test, local)) for test in generator.ifs):
                    result.append(self.value(node.elt, local))
            return result
        if isinstance(node, ast.Call):
            function = self.value(node.func, env)
            args = []
            for arg in node.args:
                if isinstance(arg, ast.Starred):
                    values = self.value(arg.value, env)
                    if type(values) not in (tuple, list) or len(values) > 6:
                        raise AdmissionError("snapshot argument expansion exceeds row envelope")
                    args.extend(values)
                else:
                    args.append(self.value(arg, env))
            kwargs = {item.arg: self.value(item.value, env) for item in node.keywords}
            if None in kwargs or len(kwargs) != len(node.keywords) or not isinstance(function, Call):
                raise AdmissionError("snapshot call has unresolved binding or keyword expansion")
            return self.call(function, args, kwargs, env)
        return super().value(node, env)

    def call(self, function, args, kwargs, env):
        self.charge()
        if function.kind == "source" and not kwargs:
            return Pending(self.run(function.value, args))
        if function.kind == "scalar-str" and not kwargs and len(args) == 1 and type(args[0]) in (int, str):
            return str(args[0])
        if function.kind == "startswith" and not kwargs and len(args) == 1 and type(args[0]) is str:
            return function.value.startswith(args[0])
        if function.kind == "snapshot-native" and not kwargs:
            if len(args) > 6 or any(type(value) is not str for value in args):
                raise AdmissionError("native snapshot arguments need bounded scalar strings")
            self.native_calls += 1
            return self.native.invoke(function.value, args)
        if function.kind == "snapshot-query" and not args:
            table = function.value
            fields = {} if type(table) is Table else dict(table.filters)
            if set(fields) & set(kwargs) or any(type(value) not in (str, int, type(None)) for value in kwargs.values()):
                raise AdmissionError("snapshot query fields have overlapping or non-scalar values")
            fields.update(kwargs)
            schema = {"CasbinRule": {"ptype", *("v" + str(i) for i in range(6))},
                      "ResourceOwner": {"user_id", "resource_type", "resource_id"}}[table.name]
            if not set(fields) <= schema:
                raise AdmissionError("snapshot query field is not declared by the projected schema")
            if function.method == "filter":
                return Query(table.name, fields)
            rows = [row for row in self.tables[table.name] if all(type(row.fields[key]) is type(value) and row.fields[key] == value for key, value in fields.items())]
            key = table.name + "." + function.method
            self.query_counts[key] = self.query_counts.get(key, 0) + 1
            return Pending(rows if function.method == "all" else bool(rows))
        return super().call(function, args, kwargs, env)
