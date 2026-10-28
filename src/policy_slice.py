"""A bounded data-only interpreter for selected synchronous policy methods.

No eval/exec, application import, reflection, arbitrary object or I/O primitive
is available. The caller binds a reviewed native-policy interface and validated
plain data. Source extraction is explicit and unsupported syntax is retained.
"""
import ast
from dataclasses import dataclass
import re

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from language import named
from source_bindings import require_import_bindings, require_static_class_members

METHODS = ("_sync_yaml_to_casbin", "check_permission", "_check_custom_rules", "_match_rule_condition")
SELF = object()
ENGINE = object()
_NODES = (ast.Assign, ast.Return, ast.If, ast.For, ast.Expr, ast.Pass, ast.Name, ast.Constant, ast.Attribute,
          ast.Call, ast.keyword, ast.Subscript, ast.UnaryOp, ast.Not, ast.BoolOp, ast.And, ast.Or, ast.Compare,
          ast.Eq, ast.NotEq, ast.Is, ast.IsNot, ast.In, ast.NotIn, ast.GtE, ast.Gt, ast.Lt, ast.LtE,
          ast.List, ast.Tuple, ast.Dict, ast.JoinedStr, ast.FormattedValue, ast.Lambda, ast.arguments, ast.arg,
          ast.Load, ast.Store)
NATIVE = {"clear_policy", "add_policy", "add_grouping_policy", "save_policy", "enforce"}


def extract_policy_program(source, class_name="PolicyEngine"):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("policy method source exceeds byte envelope", "inconclusive")
    require_import_bindings(source, {"re": ("re", 0, None)})
    try:
        tree = ast.parse(source)
    except (ValueError, SyntaxError, RecursionError) as error:
        raise AdmissionError("policy method source does not parse", "invalid") from error
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    if len(classes) != 1 or classes[0].bases or classes[0].decorator_list or classes[0].keywords:
        raise AdmissionError("selected policy class must have one direct unmodified declaration")
    require_static_class_members(classes[0], METHODS)
    result = {}
    for name in METHODS:
        matches = [node for node in classes[0].body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
        if len(matches) != 1 or not isinstance(matches[0], ast.FunctionDef) or matches[0].decorator_list:
            raise AdmissionError("policy method must be uniquely declared and synchronous: " + name)
        function = matches[0]
        args = function.args
        if args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg or not args.args or args.args[0].arg != "self":
            raise AdmissionError("policy method signature is outside the selected interface")
        if any(not isinstance(node, ast.Constant) or node.value is not None for node in args.defaults):
            raise AdmissionError("policy default arguments require a separate translation")
        nodes = [node for statement in function.body for node in ast.walk(statement)]
        if len(nodes) > 4096:
            raise AdmissionError("policy method AST envelope exceeded", "inconclusive")
        for node in nodes:
            if not isinstance(node, _NODES):
                raise AdmissionError("unsupported policy method syntax: " + type(node).__name__)
            if isinstance(node, ast.Assign) and (len(node.targets) != 1 or not isinstance(node.targets[0], (ast.Name, ast.Tuple))):
                raise AdmissionError("policy method assignments must be local names or tuple unpacking")
            if isinstance(node, ast.For) and (node.orelse or not isinstance(node.target, (ast.Name, ast.Tuple))):
                raise AdmissionError("policy loop shape requires a separate translation")
            if isinstance(node, ast.FormattedValue) and (node.conversion != -1 or node.format_spec is not None):
                raise AdmissionError("policy formatted conversion is unsupported")
            if isinstance(node, ast.Lambda):
                # A data-only sort key, not an arbitrary callback.
                if (len(node.args.args) != 1 or node.args.posonlyargs or node.args.kwonlyargs or node.args.vararg or node.args.kwarg or node.args.defaults
                        or not isinstance(node.body, ast.Call) or not isinstance(node.body.func, ast.Attribute)
                        or not isinstance(node.body.func.value, ast.Name) or node.body.func.value.id != node.args.args[0].arg
                        or node.body.func.attr != "get" or node.body.keywords or len(node.body.args) != 2
                        or not all(isinstance(item, ast.Constant) for item in node.body.args)):
                    raise AdmissionError("policy sort key is not an admitted data lookup")
        result[name] = function
    return result


def program_descriptor(program):
    return {name: {"line": node.lineno, "end_line": node.end_lineno,
                   "parameters": [arg.arg for arg in node.args.args][1:], "source_module_executed": False}
            for name, node in program.items()}


@dataclass(frozen=True)
class Return:
    value: object


@dataclass(frozen=True)
class Call:
    kind: str
    value: object = None
    method: str = ""


@dataclass(frozen=True)
class RegexPresence:
    """Observation of a successful match; groups/identity are not admitted."""
    present: bool = True


class PolicyInterpreter:
    def __init__(self, program, policy_data, native, step_limit=50000):
        if type(step_limit) is not int or not 1 <= step_limit <= 100000:
            raise AdmissionError("policy interpretation budget exceeds admitted envelope", "inconclusive")
        self.program, self.data, self.native = program, policy_data, native
        self.steps, self.depth, self.limit, self.native_calls = 0, 0, step_limit, 0

    def charge(self):
        self.steps += 1
        if self.steps > self.limit:
            raise AdmissionError("policy slice work budget exhausted", "inconclusive")

    @staticmethod
    def truth(value):
        if isinstance(value, RegexPresence):
            return True
        if value is None or type(value) in (bool, str, int, list, tuple, dict):
            return bool(value)
        raise AdmissionError("policy truth test has an unbound object")

    def run(self, name, arguments):
        self.charge()
        if name not in self.program or self.depth >= 8:
            raise AdmissionError("policy method call is unresolved or too deep", "inconclusive")
        function = self.program[name]
        names = [arg.arg for arg in function.args.args][1:]
        minimum = len(names) - len(function.args.defaults)
        if not minimum <= len(arguments) <= len(names):
            raise AdmissionError("policy method argument count differs", "input_rejected")
        values = list(arguments) + [None] * (len(names) - len(arguments))
        env = dict(zip(names, values))
        if set(env) & {"self", "len", "sorted", "re"}:
            raise AdmissionError("policy method shadows a supplied primitive")
        env.update(self=SELF, len=Call("len"), sorted=Call("sorted"), re=Call("re"))
        self.depth += 1
        try:
            result = self.statements(function.body, env)
            return result.value if isinstance(result, Return) else None
        finally:
            self.depth -= 1

    def bind(self, target, value, env):
        if isinstance(target, ast.Name) and target.id not in ("self", "len", "sorted", "re"):
            env[target.id] = value
        elif isinstance(target, ast.Tuple) and type(value) in (list, tuple) and len(target.elts) == len(value):
            for part, item in zip(target.elts, value):
                self.bind(part, item, env)
        else:
            raise AdmissionError("policy assignment does not match a local typed value")

    def value(self, node, env):
        self.charge()
        if isinstance(node, ast.Constant) and (node.value is None or type(node.value) in (str, bool, int)):
            return node.value
        if isinstance(node, ast.Name) and node.id in env:
            return env[node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            values = [self.value(item, env) for item in node.elts]
            return tuple(values) if isinstance(node, ast.Tuple) else values
        if isinstance(node, ast.Dict) and all(key is not None for key in node.keys):
            return {self.value(key, env): self.value(value, env) for key, value in zip(node.keys, node.values)}
        if isinstance(node, ast.Attribute):
            base = self.value(node.value, env)
            if base is SELF:
                if node.attr == "yaml_policy":
                    return self.data
                if node.attr == "enforcer":
                    return ENGINE
                if node.attr in self.program:
                    return Call("source", node.attr)
            if base is ENGINE and node.attr in NATIVE:
                return Call("native", node.attr)
            if isinstance(base, Call) and base.kind == "re" and node.attr == "match":
                return Call("regex")
            if type(base) is dict and node.attr in ("get", "items"):
                return Call("dict", base, node.attr)
            if type(base) is str and node.attr == "split":
                return Call("split", base)
            raise AdmissionError("policy attribute has no supplied typed binding: " + node.attr)
        if isinstance(node, ast.Subscript):
            base, index = self.value(node.value, env), self.value(node.slice, env)
            if type(base) in (list, tuple) and type(index) is int and 0 <= index < len(base):
                return base[index]
            if type(base) is dict and type(index) is str and index in base:
                return base[index]
            raise AdmissionError("policy subscription is outside the typed domain", "input_rejected")
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not self.truth(self.value(node.operand, env))
        if isinstance(node, ast.BoolOp):
            for part in node.values:
                result = self.value(part, env)
                if isinstance(node.op, ast.And) and not self.truth(result) or isinstance(node.op, ast.Or) and self.truth(result):
                    return result
            return result
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right, op = self.value(node.left, env), self.value(node.comparators[0], env), node.ops[0]
            if isinstance(op, (ast.Is, ast.IsNot)) and (right is None or type(right) is bool):
                return (left is right) if isinstance(op, ast.Is) else (left is not right)
            if isinstance(op, (ast.In, ast.NotIn)) and type(left) is str and type(right) in (dict, list, tuple):
                return (left in right) if isinstance(op, ast.In) else (left not in right)
            if type(left) is type(right) and type(left) in (str, bool, int):
                ops = {ast.Eq: lambda: left == right, ast.NotEq: lambda: left != right, ast.GtE: lambda: left >= right,
                       ast.Gt: lambda: left > right, ast.Lt: lambda: left < right, ast.LtE: lambda: left <= right}
                if type(op) in ops:
                    return ops[type(op)]()
            raise AdmissionError("policy comparison has unsupported operand types")
        if isinstance(node, ast.JoinedStr):
            parts = [self.value(item.value, env) if isinstance(item, ast.FormattedValue) else self.value(item, env) for item in node.values]
            if any(value is not None and type(value) not in (str, bool, int) for value in parts):
                raise AdmissionError("policy string interpolation needs scalar values")
            return "".join(str(value) for value in parts)
        if isinstance(node, ast.Lambda):
            return Call("key", node)
        if isinstance(node, ast.Call):
            function = self.value(node.func, env)
            args = [self.value(arg, env) for arg in node.args]
            kwargs = {item.arg: self.value(item.value, env) for item in node.keywords}
            if None in kwargs or len(kwargs) != len(node.keywords) or not isinstance(function, Call):
                raise AdmissionError("policy call has unresolved binding or argument expansion")
            return self.call(function, args, kwargs, env)
        raise AdmissionError("unsupported policy expression: " + type(node).__name__)

    def call(self, function, args, kwargs, env):
        self.charge()
        if function.kind == "source" and not kwargs:
            return self.run(function.value, args)
        if function.kind == "native" and not kwargs:
            if function.value in ("clear_policy", "save_policy"):
                if args:
                    raise AdmissionError("native policy operation takes no arguments")
            elif len(args) != (2 if function.value == "add_grouping_policy" else 3) or any(not named(value) for value in args):
                raise AdmissionError("native policy arguments are not bounded strings")
            self.native_calls += 1
            return self.native.invoke(function.value, args)
        if function.kind == "dict" and not kwargs:
            if function.method == "get" and 1 <= len(args) <= 2 and type(args[0]) is str:
                return function.value.get(*args)
            if function.method == "items" and not args:
                return list(function.value.items())
        if function.kind == "split" and not kwargs and len(args) == 1 and args[0] == ":":
            return function.value.split(":")
        if function.kind == "len" and not kwargs and len(args) == 1 and type(args[0]) in (list, tuple, dict, str):
            return len(args[0])
        if function.kind == "regex" and not kwargs and len(args) == 2 and all(type(value) is str for value in args):
            # Match objects are observed only by truth; no arbitrary regex or
            # attacker-chosen pattern is accepted in this benign interface.
            if not re.fullmatch(r"\.\*[A-Za-z_]+\.\*(?:\|\.\*[A-Za-z_]+\.\*)*", args[0]) or len(args[1]) > 256:
                raise AdmissionError("custom-rule regex is outside the bounded literal-word vocabulary")
            return RegexPresence() if re.match(args[0], args[1]) else None
        if function.kind == "sorted" and len(args) == 1 and type(args[0]) in (list, tuple) and set(kwargs) == {"key", "reverse"}:
            key = kwargs["key"]
            if not isinstance(key, Call) or key.kind != "key" or type(kwargs["reverse"]) is not bool:
                raise AdmissionError("policy sorting has no admitted data key")
            if len(args[0]) > 128:
                raise AdmissionError("policy sort envelope exceeded", "inconclusive")
            decorated = []
            for item in args[0]:
                key_env = {**env, key.value.args.args[0].arg: item}
                value = self.value(key.value.body, key_env)
                if type(value) is not int or abs(value) > 1_000_000:
                    raise AdmissionError("rule priority must be a bounded integer")
                decorated.append((value, item))
            return [item for _, item in sorted(decorated, key=lambda pair: pair[0], reverse=kwargs["reverse"])]
        raise AdmissionError("policy call is outside the admitted primitive contract: " + function.kind)

    def statements(self, body, env):
        for node in body:
            self.charge()
            if isinstance(node, ast.Assign):
                self.bind(node.targets[0], self.value(node.value, env), env)
            elif isinstance(node, ast.Return):
                return Return(self.value(node.value, env) if node.value is not None else None)
            elif isinstance(node, ast.If):
                result = self.statements(node.body if self.truth(self.value(node.test, env)) else node.orelse, env)
                if isinstance(result, Return):
                    return result
            elif isinstance(node, ast.For):
                values = self.value(node.iter, env)
                if type(values) not in (list, tuple) or len(values) > 128:
                    raise AdmissionError("policy loop requires a bounded data sequence", "inconclusive")
                for item in values:
                    self.charge()
                    self.bind(node.target, item, env)
                    result = self.statements(node.body, env)
                    if isinstance(result, Return):
                        return result
            elif isinstance(node, ast.Expr):
                if not isinstance(node.value, ast.Constant) or type(node.value.value) is not str:
                    self.value(node.value, env)
            elif not isinstance(node, ast.Pass):
                raise AdmissionError("unsupported policy statement")
        return None
