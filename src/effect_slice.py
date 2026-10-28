"""Closed, bounded source-effect interpretation over explicit owned capabilities.

No module import, eval, exec, arbitrary object attribute or source bytecode is
available. Async calls create deferred owned tokens; work occurs only at await.
Admission/budget errors cannot be swallowed by a source except-Exception clause.
"""
import ast
from dataclasses import dataclass
from uuid import UUID

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from policy_slice import PolicyInterpreter, Call, Return, _NODES
from source_bindings import require_static_class_members, require_static_definitions


@dataclass
class DataRecord:
    kind: str
    fields: dict
    writable: frozenset = frozenset()


@dataclass(frozen=True)
class RecordType:
    kind: str
    names: tuple


@dataclass(frozen=True)
class Capability:
    """A deliberately supplied coordinator-owned callback, never a source one."""
    name: str
    callback: object
    asynchronous: bool = False


@dataclass(frozen=True)
class ErrorType:
    name: str


class SliceFault(Exception):
    def __init__(self, name, message=""):
        self.name, self.message = name, message
        super().__init__(name + ": " + message)


class LoopBreak(BaseException):
    """Interpreter control flow, never an application-catchable source fault."""


@dataclass
class Deferred:
    callback: object
    consumed: bool = False


@dataclass(frozen=True)
class Closure:
    function: object
    environment: dict
    bound_self: bool = False


@dataclass
class Generator:
    node: object
    environment: dict
    consumed: bool = False


@dataclass(frozen=True)
class SerialContext:
    enter: object
    exit: object
    asynchronous: bool = True


PRIMITIVES = {"bool", "str", "int", "list", "tuple", "frozenset", "set", "sorted", "isinstance", "getattr", "enumerate"}


def require_plain_data(value, *, forbidden_container=None, charge=None):
    """Bounded plain-data tree; aliases allowed, cycles and capabilities not.

    Used for the newly admitted dictionary write interface, not as an assertion
    that every other explicit source capability is a plain JSON value.
    """
    pending, remaining = [(value, 0, frozenset())], 2048
    while pending:
        item, depth, ancestors = pending.pop()
        if charge is not None:
            charge()
        remaining -= 1
        if depth > 16 or remaining < 0:
            raise AdmissionError("plain mapping value exceeds its structural envelope", "inconclusive")
        if item is None or type(item) is bool:
            continue
        if type(item) is str and len(item) <= 4096 or type(item) is int and item.bit_length() <= 64:
            continue
        if type(item) not in (list, tuple, dict) or len(item) > 128:
            raise AdmissionError("mapping writes need bounded plain data, not a deferred/capability/host object")
        if item is forbidden_container or id(item) in ancestors:
            raise AdmissionError("mapping write would introduce a cyclic data value")
        ancestry = ancestors | {id(item)}
        if type(item) is dict:
            if any(type(key) is not str or len(key) > 4096 for key in item):
                raise AdmissionError("mapping keys must be bounded plain strings")
            pending.extend((child, depth + 1, ancestry) for child in item.values())
        else:
            pending.extend((child, depth + 1, ancestry) for child in item)


def extract_effect_program(source, class_name, methods, functions=()):
    if type(source) is not bytes or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("effect slice source exceeds byte envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (ValueError, SyntaxError, RecursionError) as error:
        raise AdmissionError("effect slice does not parse", "invalid") from error
    if class_name is None:
        if methods:
            raise AdmissionError("module effect program cannot declare receiver methods")
        cls = None
    else:
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
        if len(classes) != 1 or classes[0].bases or classes[0].decorator_list or classes[0].keywords:
            raise AdmissionError("effect receiver requires one direct class declaration")
        cls = classes[0]
        require_static_class_members(cls, methods)
    if set(methods) & set(functions) or len(set(methods)) != len(methods) or len(set(functions)) != len(functions):
        raise AdmissionError("effect selected function names are duplicated")
    require_static_definitions(tree, [*functions, *([class_name] if class_name else [])], PRIMITIVES)
    selected = {}
    for name, scope in [(name, cls.body) for name in methods] + [(name, tree.body) for name in functions]:
        nodes = [node for node in scope if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
        if len(nodes) != 1:
            raise AdmissionError("effect function binding is ambiguous: " + name)
        node = nodes[0]
        if node.decorator_list and not (name in methods and len(node.decorator_list) == 1 and isinstance(node.decorator_list[0], ast.Name) and node.decorator_list[0].id == "staticmethod"):
            raise AdmissionError("effect decorators need a separate translation")
        parents = {id(child): parent for root in node.body for parent in ast.walk(root) for child in ast.iter_child_nodes(parent)}
        allowed = _NODES + (ast.Await, ast.Try, ast.ExceptHandler, ast.Raise, ast.AsyncWith, ast.With, ast.withitem,
            ast.FunctionDef, ast.AsyncFunctionDef, ast.Return, ast.Set, ast.SetComp, ast.ListComp, ast.GeneratorExp,
            ast.comprehension, ast.Starred, ast.arguments, ast.arg, ast.AnnAssign, ast.IfExp,
            ast.Assert, ast.BinOp, ast.BitAnd, ast.BitOr, ast.AugAssign, ast.Break)
        walked = [item for statement in node.body for item in ast.walk(statement)]
        if len(walked) > 4096:
            raise AdmissionError("effect AST budget exceeded", "inconclusive")
        # Type annotations are never evaluated. They may contain typing syntax
        # but are not part of the executable statement fragment.
        annotation_nodes = set()
        for item in ast.walk(node):
            annotation = item.annotation if isinstance(item, (ast.arg, ast.AnnAssign)) else item.returns if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
            if annotation is not None:
                annotation_nodes.update(id(child) for child in ast.walk(annotation))
        for item in walked:
            if id(item) in annotation_nodes:
                continue
            if not isinstance(item, allowed) or isinstance(item, ast.Lambda):
                raise AdmissionError("effect syntax is unsupported: " + type(item).__name__)
            if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)) and item.id in PRIMITIVES:
                raise AdmissionError("effect source shadows a bound primitive")
            if isinstance(item, ast.Call) and (any(keyword.arg is None for keyword in item.keywords) or len({keyword.arg for keyword in item.keywords}) != len(item.keywords)):
                raise AdmissionError("effect keyword expansion/duplicates are unsupported")
            if isinstance(item, ast.For):
                target = item.target
                local_target = isinstance(target, ast.Name) or (isinstance(target, ast.Tuple)
                    and 1 <= len(target.elts) <= 8 and all(isinstance(part, ast.Name) for part in target.elts)
                    and len({part.id for part in target.elts}) == len(target.elts))
                if item.orelse or not local_target:
                    raise AdmissionError("effect for-loop needs bounded local unpacking and no else")
            if isinstance(item, ast.Break):
                parent = parents.get(id(item))
                while parent is not None and not isinstance(parent, (ast.For, ast.FunctionDef, ast.AsyncFunctionDef)):
                    parent = parents.get(id(parent))
                if not isinstance(parent, ast.For):
                    raise AdmissionError("effect break requires an enclosing loop in the same function")
            if isinstance(item, (ast.SetComp, ast.ListComp, ast.GeneratorExp)) and (len(item.generators) != 1 or item.generators[0].is_async or not isinstance(item.generators[0].target, ast.Name)):
                raise AdmissionError("effect comprehension needs one synchronous bounded generator")
            if isinstance(item, ast.GeneratorExp):
                parent = parents.get(id(item))
                immediate_collection = isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name) and parent.func.id in {"tuple", "set", "frozenset", "sorted"}
                immediate_tuple_star = isinstance(parent, ast.Starred) and isinstance(parents.get(id(parent)), ast.Tuple)
                if not (immediate_collection or immediate_tuple_star):
                    raise AdmissionError("effect generator must be immediately consumed by a declared collection constructor")
            if isinstance(item, (ast.AsyncWith, ast.With)) and (len(item.items) != 1 or item.items[0].optional_vars is not None):
                raise AdmissionError("effect context manager has an unbound target")
            if isinstance(item, ast.AugAssign) and (not isinstance(item.target, ast.Name) or not isinstance(item.op, (ast.BitOr, ast.BitAnd))):
                raise AdmissionError("effect augmented assignment needs a local bounded string set")
            if isinstance(item, ast.Try) and (item.finalbody or item.orelse or any(handler.type is None or not isinstance(handler.type, ast.Name) for handler in item.handlers)):
                raise AdmissionError("effect try needs explicit named handlers and no else/finally")
            if isinstance(item, ast.FormattedValue) and (item.conversion != -1 or item.format_spec is not None):
                raise AdmissionError("effect formatted conversions are unsupported")
            if isinstance(item, ast.Assign) and (len(item.targets) != 1 or not isinstance(item.targets[0], (ast.Name, ast.Attribute, ast.Subscript))):
                raise AdmissionError("effect assignment needs one local, declared writable field or plain mapping slot")
        # Binding follows the declaration context, not the spelling of the
        # first parameter. A module/staticmethod parameter can be named self.
        node._effect_method = name in methods
        node._effect_bound_self = name in methods and not node.decorator_list
        selected[name] = node
    return selected


class EffectInterpreter(PolicyInterpreter):
    def __init__(self, program, receiver, bindings, step_limit=50000):
        super().__init__(program, None, None, step_limit)
        self.receiver, self.bindings = receiver, {name: Call("effect-builtin", name) for name in PRIMITIVES}
        self.bindings.update(bindings)
        self.fault_stack = []
        self.function_calls = {}
        for name, node in program.items():
            closure = Closure(node, self.bindings, bool(getattr(node, "_effect_bound_self", False)))
            if getattr(node, "_effect_method", False):
                receiver.fields[name] = closure
            else:
                self.bindings[name] = closure

    def run(self, name, arguments, kwargs=None):
        function = self.receiver.fields.get(name, self.bindings.get(name))
        if not isinstance(function, Closure):
            raise AdmissionError("unbound selected effect function")
        result = self.invoke(function, arguments, {} if kwargs is None else kwargs)
        return self.resolve(result) if isinstance(result, Deferred) else result

    def resolve(self, pending):
        self.charge()
        if pending is None or type(pending) in (str, bool, int, tuple, list, dict, set, frozenset, UUID) or isinstance(pending, DataRecord):
            # These explicitly bound plain values have no await protocol.
            # Keep this source error observable, rather than treating False
            # as an ordinary policy denial or swallowing it as unsupported.
            raise SliceFault("TypeError", "owned plain result is not awaitable")
        if not isinstance(pending, Deferred) or pending.consumed:
            raise AdmissionError("effect await needs a fresh deferred result")
        pending.consumed = True
        return pending.callback()

    def invoke(self, function, arguments, kwargs):
        self.charge()
        if isinstance(function, Capability):
            action = lambda: function.callback(*arguments, **kwargs)
            return Deferred(action) if function.asynchronous else action()
        if isinstance(function, ErrorType):
            if kwargs or len(arguments) > 1 or arguments and type(arguments[0]) is not str:
                raise AdmissionError("effect error constructor needs a plain message")
            return SliceFault(function.name, arguments[0] if arguments else "")
        if isinstance(function, RecordType):
            if len(arguments) > len(function.names) or set(kwargs) - set(function.names):
                raise AdmissionError("typed record constructor fields differ")
            fields = dict(zip(function.names, arguments))
            if set(fields) & set(kwargs) or set(fields) | set(kwargs) != set(function.names):
                raise AdmissionError("typed record requires every declared field exactly once")
            return DataRecord(function.kind, {**fields, **kwargs})
        if not isinstance(function, Closure):
            raise AdmissionError("effect call has no declared capability")
        args = function.function.args
        positional = [arg.arg for arg in args.args]
        keyword_only = [arg.arg for arg in args.kwonlyargs]
        names = positional + keyword_only
        values = [self.receiver, *arguments] if function.bound_self else list(arguments)
        if (args.posonlyargs or args.vararg or args.kwarg or type(kwargs) is not dict
                or len(values) > len(positional) or set(kwargs) - set(names)
                or set(positional[:len(values)]) & set(kwargs)
                or len(set(names)) != len(names) or set(names) & PRIMITIVES):
            raise AdmissionError("effect call/signature has unresolved arguments or shadows a primitive")
        defaults = dict(zip(positional[len(positional) - len(args.defaults):], args.defaults))
        defaults.update(zip(keyword_only, args.kw_defaults))
        if any(node is not None and (not isinstance(node, ast.Constant)
                or node.value is not None and type(node.value) not in (str, int, bool)) for node in defaults.values()):
            raise AdmissionError("effect defaults must be immutable scalar constants")
        bound = {**dict(zip(positional, values)), **kwargs}
        for name in names:
            if name not in bound:
                if name not in defaults or defaults[name] is None:
                    raise AdmissionError("effect call is missing a required argument")
                bound[name] = defaults[name].value
        local = {**function.environment, **bound}
        def execute():
            if self.depth >= 12:
                raise AdmissionError("effect source depth exhausted", "inconclusive")
            self.depth += 1
            self.function_calls[function.function.name] = self.function_calls.get(function.function.name, 0) + 1
            try:
                result = self.statements(function.function.body, local)
                return result.value if isinstance(result, Return) else None
            finally:
                self.depth -= 1
        return Deferred(execute) if isinstance(function.function, ast.AsyncFunctionDef) else execute()

    def truth(self, value):
        if type(value) in (set, frozenset):
            return bool(value)
        if isinstance(value, DataRecord):
            return True
        return super().truth(value)

    def sequence(self, value):
        if isinstance(value, Generator):
            if value.consumed:
                return []
            value.consumed = True
            return self.comprehension(value.node, value.environment)
        if type(value) in (tuple, list, set, frozenset) and len(value) <= 128:
            return list(value)
        raise AdmissionError("effect iteration needs bounded plain data", "inconclusive")

    def comprehension(self, node, env):
        gen = node.generators[0]
        result = []
        for item in self.sequence(self.value(gen.iter, env)):
            self.charge()
            local = {**env, gen.target.id: item}
            if all(self.truth(self.value(test, local)) for test in gen.ifs):
                result.append(self.value(node.elt, local))
        return result

    def value(self, node, env):
        self.charge()
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.BitAnd, ast.BitOr)):
            left, right = self.value(node.left, env), self.value(node.right, env)
            self.string_set(left)
            self.string_set(right)
            value = left & right if isinstance(node.op, ast.BitAnd) else left | right
            self.string_set(value)
            return value
        if isinstance(node, ast.IfExp):
            return self.value(node.body if self.truth(self.value(node.test, env)) else node.orelse, env)
        if isinstance(node, ast.JoinedStr):
            parts = []
            for item in node.values:
                value = self.value(item.value, env) if isinstance(item, ast.FormattedValue) else self.value(item, env)
                if value is not None and type(value) not in (str, bool, int, UUID):
                    require_plain_data(value, charge=self.charge)
                parts.append(str(value))
            joined = "".join(parts)
            if len(joined) > 16384:
                raise AdmissionError("effect interpolation exceeds its output envelope", "inconclusive")
            return joined
        if isinstance(node, ast.Await):
            return self.resolve(self.value(node.value, env))
        if isinstance(node, ast.Attribute):
            base = self.value(node.value, env)
            if isinstance(base, DataRecord) and node.attr in base.fields:
                return base.fields[node.attr]
            if type(base) is str and node.attr in ("startswith", "removeprefix", "lower", "split"):
                return Call("effect-string", base, node.attr)
            if type(base) is dict and node.attr == "get":
                return Call("dict", base, node.attr)
            raise AdmissionError("effect attribute is not an explicitly bound field: " + node.attr)
        if isinstance(node, ast.GeneratorExp):
            return Generator(node, dict(env))
        if isinstance(node, (ast.SetComp, ast.ListComp)):
            values = self.comprehension(node, env)
            return set(values) if isinstance(node, ast.SetComp) else values
        if isinstance(node, ast.Set):
            return {self.value(item, env) for item in node.elts}
        if isinstance(node, ast.Tuple) and any(isinstance(item, ast.Starred) for item in node.elts):
            result = []
            for item in node.elts:
                result.extend(self.sequence(self.value(item.value, env))) if isinstance(item, ast.Starred) else result.append(self.value(item, env))
            if len(result) > 128:
                raise AdmissionError("effect tuple expansion exceeds envelope", "inconclusive")
            return tuple(result)
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.In, ast.NotIn)):
            left, right = self.value(node.left, env), self.value(node.comparators[0], env)
            if type(left) is str and type(right) is str:
                if len(left) > 4096 or len(right) > 4096:
                    raise AdmissionError("effect substring operands exceed the string envelope", "inconclusive")
                return (left in right) if isinstance(node.ops[0], ast.In) else (left not in right)
            if type(left) is str and type(right) in (list, tuple, set, frozenset, dict):
                return (left in right) if isinstance(node.ops[0], ast.In) else (left not in right)
            if (left is None and type(right) in (list, tuple, set, frozenset) and len(right) <= 128
                    and all(type(item) is str for item in right)):
                return isinstance(node.ops[0], ast.NotIn)
            raise AdmissionError("effect membership has unbound value types")
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            left, right = self.value(node.left, env), self.value(node.comparators[0], env)
            if ((left is None and (right is None or type(right) in (str, bool, int)))
                    or (right is None and type(left) in (str, bool, int))):
                equal = left is None and right is None
                return equal if isinstance(node.ops[0], ast.Eq) else not equal
            # Values have already been evaluated; do not delegate and repeat
            # a possibly effectful source call in either operand.
            if type(left) is type(right) and type(left) in (str, bool, int):
                return (left == right) if isinstance(node.ops[0], ast.Eq) else (left != right)
            raise AdmissionError("effect equality has unbound operand types")
        if isinstance(node, ast.Call):
            function = self.value(node.func, env)
            arguments = []
            for item in node.args:
                arguments.extend(self.sequence(self.value(item.value, env))) if isinstance(item, ast.Starred) else arguments.append(self.value(item, env))
            kwargs = {item.arg: self.value(item.value, env) for item in node.keywords}
            return self.call(function, arguments, kwargs, env) if isinstance(function, Call) else self.invoke(function, arguments, kwargs)
        return super().value(node, env)

    def call(self, function, args, kwargs, env):
        self.charge()
        if function.kind == "dict":
            return super().call(function, args, kwargs, env)
        if function.kind == "effect-string" and function.method == "lower" and not args and not kwargs:
            return function.value.lower()
        if (function.kind == "effect-string" and function.method == "split" and not kwargs
                and len(args) == 1 and type(args[0]) is str and args[0] and len(args[0]) <= 4096
                and len(function.value) <= 4096):
            values = function.value.split(args[0])
            if len(values) > 128:
                raise AdmissionError("effect split exceeds its result envelope", "inconclusive")
            return values
        if (function.kind == "effect-string" and function.method in ("startswith", "removeprefix")
                and not kwargs and len(args) == 1 and type(args[0]) is str):
            return function.value.startswith(args[0]) if function.method == "startswith" else function.value.removeprefix(args[0])
        if function.kind == "effect-builtin" and not kwargs:
            name = function.value
            if name == "enumerate" and 1 <= len(args) <= 2 and type(args[0]) in (tuple, list):
                start = args[1] if len(args) == 2 else 0
                if type(start) is not int or abs(start) > 1_000_000:
                    raise AdmissionError("effect enumeration start must be a bounded integer")
                return list(enumerate(self.sequence(args[0]), start))
            if name == "isinstance" and len(args) == 2 and isinstance(args[1], RecordType):
                return isinstance(args[0], DataRecord) and args[0].kind == args[1].kind
            if (name == "isinstance" and len(args) == 2 and isinstance(args[1], Call)
                    and args[1].kind == "effect-builtin" and args[1].value in ("list", "str", "int", "bool", "tuple", "set", "frozenset")):
                kind = {"list": list, "str": str, "int": int, "bool": bool, "tuple": tuple, "set": set, "frozenset": frozenset}[args[1].value]
                # bool is a subclass of int in the actual source language.
                return isinstance(args[0], kind)
            if name == "getattr" and len(args) == 3 and isinstance(args[0], DataRecord) and type(args[1]) is str:
                return args[0].fields.get(args[1], args[2])
            if name in ("tuple", "set", "frozenset", "sorted") and len(args) == 1:
                values = self.sequence(args[0])
                if name == "sorted" and any(type(value) is not str for value in values):
                    raise AdmissionError("effect sort needs plain strings")
                return {"tuple": tuple, "set": set, "frozenset": frozenset, "sorted": sorted}[name](values)
            if name == "bool" and len(args) == 1:
                return self.truth(args[0])
            if name == "str" and len(args) == 1 and (type(args[0]) in (str, int, bool, UUID) or isinstance(args[0], SliceFault)):
                return str(args[0])
        raise AdmissionError("effect primitive has unresolved argument types")

    def bind(self, target, value, env):
        if isinstance(value, Deferred):
            raise AdmissionError("async source/capability values must be directly awaited before assignment")
        if isinstance(target, ast.Subscript):
            base, key = self.value(target.value, env), self.value(target.slice, env)
            if type(base) is not dict or type(key) is not str or len(key) > 4096:
                raise AdmissionError("effect subscript writes require a plain string-keyed mapping")
            if len(base) > 128 or key not in base and len(base) >= 128:
                raise AdmissionError("effect mapping write exceeds the entry envelope", "inconclusive")
            require_plain_data(value, forbidden_container=base, charge=self.charge)
            base[key] = value
            return
        if isinstance(target, ast.Attribute):
            base = self.value(target.value, env)
            if isinstance(base, DataRecord) and target.attr in base.writable:
                base.fields[target.attr] = value
                return
            raise AdmissionError("effect writes an undeclared mutable field")
        return super().bind(target, value, env)

    @staticmethod
    def string_set(value):
        if (type(value) not in (set, frozenset) or len(value) > 128
                or any(type(item) is not str for item in value)):
            raise AdmissionError("effect set operation needs bounded plain strings")

    def statements(self, body, env):
        for node in body:
            self.charge()
            if isinstance(node, ast.Break):
                raise LoopBreak()
            elif isinstance(node, ast.For):
                values = self.value(node.iter, env)
                if type(values) not in (list, tuple) or len(values) > 128:
                    raise AdmissionError("effect loop requires a bounded data sequence", "inconclusive")
                for item in values:
                    self.charge()
                    self.bind(node.target, item, env)
                    try:
                        result = self.statements(node.body, env)
                    except LoopBreak:
                        break
                    if isinstance(result, Return):
                        return result
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Python closures observe their shared enclosing bindings,
                # including assignments made after the function definition.
                env[node.name] = Closure(node, env)
            elif isinstance(node, ast.AugAssign):
                left = self.value(node.target, env)
                right = self.value(node.value, env)
                self.string_set(left)
                self.string_set(right)
                value = left | right if isinstance(node.op, ast.BitOr) else left & right
                self.string_set(value)
                if type(left) is set:
                    # Preserve Python's alias-visible in-place set update.
                    left.clear()
                    left.update(value)
                else:
                    self.bind(node.target, value, env)
            elif isinstance(node, ast.Assert):
                if not self.truth(self.value(node.test, env)):
                    message = self.value(node.msg, env) if node.msg is not None else ""
                    if type(message) is not str:
                        raise AdmissionError("effect assertion message needs a plain string")
                    raise SliceFault("AssertionError", message)
            elif isinstance(node, ast.AnnAssign):
                if node.value is not None:
                    self.bind(node.target, self.value(node.value, env), env)
            elif isinstance(node, ast.Try):
                try:
                    result = self.statements(node.body, env)
                except SliceFault as fault:
                    handler = None
                    for item in node.handlers:
                        error_type = env.get(item.type.id)
                        if not isinstance(error_type, ErrorType):
                            raise AdmissionError("source except target has no explicit error-type binding")
                        if error_type.name in (fault.name, "Exception"):
                            handler = item
                            break
                    if handler is None:
                        raise
                    if handler.name:
                        env[handler.name] = fault
                    self.fault_stack.append(fault)
                    try:
                        result = self.statements(handler.body, env)
                    finally:
                        self.fault_stack.pop()
                        # The exception suite shares enclosing bindings, but
                        # its target is cleared even if the handler raises.
                        if handler.name:
                            env.pop(handler.name, None)
                if isinstance(result, Return):
                    return result
            elif isinstance(node, ast.Raise):
                fault = self.value(node.exc, env) if node.exc is not None else self.fault_stack[-1] if self.fault_stack else None
                if not isinstance(fault, SliceFault):
                    raise AdmissionError("effect raise has no explicit fault value")
                if node.cause is not None:
                    cause = self.value(node.cause, env)
                    if cause is not None and not isinstance(cause, SliceFault):
                        raise AdmissionError("effect raise cause is not a fault or None")
                raise fault
            elif isinstance(node, (ast.AsyncWith, ast.With)):
                context = self.value(node.items[0].context_expr, env)
                if (not isinstance(context, SerialContext) or type(context.asynchronous) is not bool
                        or context.asynchronous != isinstance(node, ast.AsyncWith)):
                    raise AdmissionError("effect context lacks the corresponding supplied serial protocol")
                context.enter()
                try:
                    result = self.statements(node.body, env)
                finally:
                    context.exit()
                if isinstance(result, Return):
                    return result
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                value = self.value(node.value, env)
                if isinstance(value, Deferred):
                    raise AdmissionError("discarded async effect requires a separate coroutine-lifetime translation")
            else:
                result = super().statements([node], env)
                if isinstance(result, Return):
                    return result
        return None
