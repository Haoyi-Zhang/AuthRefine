"""Interpret explicit source method bodies, not framework/MRO dispatch.

The returned program preserves the selected executable AST. Removing the base
class from its owned receiver is an explicit body-evaluation contract, never a
proof that a deployed framework dispatches to that body or supplies its fields.
"""
import ast
import copy

from effect_slice import PRIMITIVES, extract_effect_program
from native_casbin import AdmissionError, MAX_TEXT_BYTES
from source_bindings import require_static_class_members, require_static_definitions


def extract_explicit_bodies(source, class_name, methods):
    if type(source) is not bytes or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("explicit body source exceeds the byte envelope", "inconclusive")
    if not methods or len(set(methods)) != len(methods):
        raise AdmissionError("explicit body selection is empty or duplicated")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, UnicodeError, RecursionError) as error:
        raise AdmissionError("explicit body source does not parse", "invalid") from error
    require_static_definitions(tree, [class_name], PRIMITIVES)
    declarations = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    if len(declarations) != 1 or declarations[0].decorator_list or declarations[0].keywords:
        raise AdmissionError("explicit receiver class requires a unique undecorated declaration")
    cls = declarations[0]
    require_static_class_members(cls, methods)
    selected = [node for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in methods]
    if len(selected) != len(methods):
        raise AdmissionError("every selected body must have a direct class declaration")
    owned_class = ast.ClassDef(name=class_name, bases=[], keywords=[], body=copy.deepcopy(selected), decorator_list=[])
    owned_tree = ast.fix_missing_locations(ast.Module(body=[owned_class], type_ignores=[]))
    text = ast.unparse(owned_tree).encode("utf-8")
    program = extract_effect_program(text, class_name, methods)
    for node in selected:
        if ast.dump(node, include_attributes=False) != ast.dump(program[node.name], include_attributes=False):
            raise AdmissionError("selected executable AST changed during explicit body transport")
    descriptor = {"class": class_name, "explicit_body_contract": True,
        "base_expressions_not_executed": [ast.unparse(node) for node in cls.bases],
        "receiver_dispatch_or_inheritance_proved": False, "module_or_source_bytecode_executed": False,
        "methods": [{"name": node.name, "line": node.lineno, "end_line": node.end_lineno} for node in selected]}
    return program, descriptor
