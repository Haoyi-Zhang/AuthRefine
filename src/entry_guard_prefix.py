"""Compare explicit pre-lookup guard bodies on supplied owned records.

This is a source-body contract. Class/method decorators, framework dispatch,
the permission predicate, request parsing, ORM queries and mutations are not
executed or proved. Reaching the next statement is not an access grant.
"""
import ast
import copy
from itertools import product
import json

from effect_slice import Capability, DataRecord, EffectInterpreter, PRIMITIVES, SliceFault, extract_effect_program
from native_casbin import AdmissionError, MAX_TEXT_BYTES
from observation_protocol import compare_observations
from persistent_store import shape, strip_docstring
from source_bindings import require_static_class_members, require_static_definitions


def extract_entry_prefixes(source, class_name, entries):
    if (type(source) is not bytes or len(source) > MAX_TEXT_BYTES or not entries
            or type(entries) is not dict or any(not name.isidentifier() or type(field) is not str
                for name, field in entries.items())):
        raise AdmissionError("entry-prefix selection is outside its envelope")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("entry-prefix source does not parse", "invalid") from error
    require_static_definitions(tree, [class_name], PRIMITIVES)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    require_static_class_members(cls, entries)
    functions = {node.name: node for node in cls.body if isinstance(node, ast.FunctionDef)}
    leading = ast.parse("obj = self.get_object()\nself.perm_check(request, obj)").body
    prefixes, selected_helpers, descriptors = {}, {}, []
    for name, field in entries.items():
        function = functions.get(name)
        if function is None or [arg.arg for arg in function.args.args][:2] != ["self", "request"]:
            raise AdmissionError("entry requires an explicit synchronous self/request body")
        body = strip_docstring(function.body)
        if len(body) < 3 or [shape(node) for node in body[:2]] != [shape(node) for node in leading]:
            raise AdmissionError("get-object/permission prelude changed")
        count = 2
        call = body[2].value if isinstance(body[2], ast.Expr) else None
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name) and call.func.value.id == "self"):
            helper = functions.get(call.func.attr)
            if (helper is None or helper.decorator_list or call.keywords or len(call.args) != 3
                    or shape(call.args[0]) != shape(ast.Name(id="obj", ctx=ast.Load()))
                    or not isinstance(call.args[1], ast.Constant) or call.args[1].value != field
                    or not isinstance(call.args[2], ast.Call) or shape(call.args[2].func) != shape(ast.Name(id="gettext", ctx=ast.Load()))
                    or call.args[2].keywords or len(call.args[2].args) != 1
                    or not isinstance(call.args[2].args[0], ast.Constant) or type(call.args[2].args[0].value) is not str):
                raise AdmissionError("prefix helper needs one direct body and the declared field/message protocol")
            selected_helpers[helper.name] = helper
            count += 1
        if len(body) <= count:
            raise AdmissionError("entry has no explicit unexamined tail")
        barrier = body[count]
        # Only admit the stated first lookup/parameter-processing boundary.
        # Never scan past an unknown statement to find a convenient guard.
        parameter = ast.parse(f"if {field!r} not in request.data:\n pass").body[0].test
        guarded_parameter = isinstance(barrier, ast.If) and shape(barrier.test) == shape(parameter)
        lookup = barrier.body[0] if isinstance(barrier, ast.Try) and barrier.body else None
        guarded_lookup = (isinstance(lookup, ast.Assign) and isinstance(lookup.value, ast.Call)
            and isinstance(lookup.value.func, ast.Attribute) and lookup.value.func.attr == "get"
            and isinstance(lookup.value.func.value, ast.Attribute)
            and isinstance(lookup.value.func.value.value, ast.Name) and lookup.value.func.value.value.id == "obj")
        selected_components = shape(barrier) == shape(ast.parse("components = obj.components").body[0])
        if not (guarded_parameter or guarded_lookup or selected_components):
            raise AdmissionError("next entry statement is not the declared pre-lookup boundary")
        prefixes[name] = copy.deepcopy(body[:count])
        descriptors.append({"entry": name, "field": field, "function_line": function.lineno,
            "prefix_last_line": body[count - 1].end_lineno, "unexamined_tail_line": barrier.lineno,
            "unexamined_tail_statements": len(body) - count,
            "decorator_expressions_not_executed": [ast.unparse(node) for node in function.decorator_list]})
    require_static_class_members(cls, [*entries, *selected_helpers])
    owned = ast.fix_missing_locations(ast.Module(body=[ast.ClassDef(name=class_name, bases=[],
        keywords=[], body=copy.deepcopy(list(selected_helpers.values())) or [ast.Pass()], decorator_list=[])], type_ignores=[]))
    program = extract_effect_program(ast.unparse(owned).encode(), class_name, list(selected_helpers))
    if any(shape(program[name]) != shape(helper) for name, helper in selected_helpers.items()):
        raise AdmissionError("selected helper executable AST changed")
    descriptor = {"class": class_name, "entries": descriptors,
        "helper_methods": [{"name": node.name, "line": node.lineno, "end_line": node.end_lineno}
            for node in selected_helpers.values()],
        "class_decorators_not_executed": [ast.unparse(node) for node in cls.decorator_list],
        "runtime_dispatch_or_inheritance_proved": False,
        "lookup_mutation_or_orm_executed": False, "reaches_tail_is_not_access_grant": True}
    return prefixes, program, descriptor


def compare_entry_prefixes(source, class_name, entries, blocked_scopes):
    if (set(blocked_scopes) != set(entries) or any(type(value) is not frozenset
            or not value <= {"project", "workspace"} for value in blocked_scopes.values())):
        raise ValueError("an independent scope contract is required for every entry")
    prefixes, program, descriptor = extract_entry_prefixes(source, class_name, entries)
    rows, expected, actual = [], [], []
    for name, (scope, manager, present) in product(entries, product(("global", "project", "workspace"), (False, True), (False, True))):
        group = DataRecord("owned_group", {"defining_project_id": "owned-project" if scope == "project" else None,
            "defining_workspace_id": "owned-workspace" if scope == "workspace" else None})
        request = DataRecord("opaque_request", {})
        effects = []
        def get_object():
            effects.append("object")
            if not present:
                raise SliceFault("NotFound", "owned missing object")
            return group
        def permission(given_request, given_group):
            if given_request is not request or given_group is not group:
                raise AdmissionError("prefix changed supplied request/group identity")
            effects.append("permission")
            if not manager:
                raise SliceFault("PermissionDenied", "owned predicate denied")
        def validation(payload):
            if type(payload) is not dict or set(payload) != {entries[name]} or type(payload[entries[name]]) is not str:
                raise AdmissionError("validation error changed its declared field protocol")
            return SliceFault("ValidationError", json.dumps(payload, sort_keys=True))
        receiver = DataRecord("explicit_receiver", {"get_object": Capability("supplied_object", get_object),
            "perm_check": Capability("supplied_management_permission", permission)})
        interpreter = EffectInterpreter(program, receiver,
            {"ValidationError": Capability("owned_validation_error", validation),
             "gettext": Capability("owned_identity_translation", lambda text: text)})
        outcome = "continues_to_unexamined_tail"
        try:
            interpreter.statements(prefixes[name], {"self": receiver, "request": request, **interpreter.bindings})
        except SliceFault as error:
            if error.name not in ("NotFound", "PermissionDenied", "ValidationError"):
                raise
            outcome = error.name
        wanted = ("NotFound" if not present else "PermissionDenied" if not manager
            else "ValidationError" if scope in blocked_scopes[name] else "continues_to_unexamined_tail")
        effect_expected = ["object"] + (["permission"] if present else [])
        actual.append({"decision": "allow" if outcome == "continues_to_unexamined_tail" else "deny",
            "flags": {"correct_exception_category": outcome == wanted, "correct_prefix_effects": effects == effect_expected}})
        expected.append({"decision": "allow" if wanted == "continues_to_unexamined_tail" else "deny",
            "flags": {"correct_exception_category": True, "correct_prefix_effects": True}})
        rows.append({"entry": name, "scope": scope, "supplied_management_permission": manager,
            "supplied_object_present": present, "observed": outcome, "expected": wanted, "prefix_effects": effects})
    comparison = compare_observations(expected, actual, "explicit pre-lookup body with supplied object/management predicates and independent scoped-team contract")
    return {"descriptor": descriptor, "comparison": comparison, "contexts": rows,
        "different_contexts": sum(row["observed"] != row["expected"] for row in rows),
        "full_request_mutation_dispatch_or_permission_implementation_verified": False}
