"""Explicit source guard prefixes before a reviewed, exact AST boundary.

Only the selected original statements are transported. This is not framework
dispatch, a complete request execution or a proof of the supplied predicates.
Unknown statements are never skipped to find a later convenient guard.
"""
import ast
import copy

from effect_slice import PRIMITIVES, extract_effect_program
from native_casbin import AdmissionError, MAX_TEXT_BYTES
from persistent_store import shape, strip_docstring
from source_bindings import require_static_class_members, require_static_definitions


def extract_guard_prefix(source, class_name, method, prefix_statements, barrier):
    if (type(source) is not bytes or len(source) > MAX_TEXT_BYTES
            or type(prefix_statements) is not int or not 1 <= prefix_statements <= 16
            or not isinstance(barrier, ast.stmt)):
        raise AdmissionError("guard prefix selection exceeds its declared envelope")
    try:
        tree = ast.parse(source)
    except (ValueError, SyntaxError, UnicodeError, RecursionError) as error:
        raise AdmissionError("guard prefix source does not parse", "invalid") from error
    require_static_definitions(tree, [class_name], PRIMITIVES)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    if len(classes) != 1 or classes[0].decorator_list or classes[0].keywords:
        raise AdmissionError("guard class needs one explicit undecorated declaration")
    cls = classes[0]
    require_static_class_members(cls, [method])
    functions = [node for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method]
    if len(functions) != 1 or functions[0].decorator_list:
        raise AdmissionError("guard method requires a direct undecorated declaration")
    function = functions[0]
    body = strip_docstring(function.body)
    if len(body) <= prefix_statements or shape(body[prefix_statements]) != shape(barrier):
        raise AdmissionError("next statement differs from the exact reviewed boundary")
    selected = copy.deepcopy(function)
    selected.body = copy.deepcopy(body[:prefix_statements])
    owned = ast.fix_missing_locations(ast.Module(body=[ast.ClassDef(name=class_name, bases=[],
        keywords=[], body=[selected], decorator_list=[])], type_ignores=[]))
    program = extract_effect_program(ast.unparse(owned).encode(), class_name, [method])
    if shape(program[method]) != shape(selected):
        raise AdmissionError("guard prefix executable AST changed in explicit transport")
    descriptor = {"class": class_name, "method": method, "function_line": function.lineno,
        "prefix_last_line": body[prefix_statements - 1].end_lineno,
        "first_unexamined_statement_line": body[prefix_statements].lineno,
        "unexamined_statements": len(body) - prefix_statements,
        "base_expressions_not_executed": [ast.unparse(node) for node in cls.bases],
        "receiver_dispatch_or_inheritance_proved": False,
        "continuation_is_not_an_access_grant": True}
    return program, descriptor
