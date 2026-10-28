"""Read a selected string-valued caller-to-consumer argument handoff.

The call need not be the whole function. This descriptor models only its
argument expressions under supplied typed values at that boundary. It does
not execute or certify earlier guards, authentication, dispatch or side effects.
"""
import ast

from language import named
from native_casbin import AdmissionError, MAX_TEXT_BYTES
from python_wrapper import dotted


def extract_call_handoff(source, function, callee, formal_parameters):
    if len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("caller source exceeds extraction envelope", "inconclusive")
    if (not isinstance(formal_parameters, list) or not formal_parameters or
            not all(isinstance(name, str) and name.isidentifier() for name in formal_parameters) or
            len(set(formal_parameters)) != len(formal_parameters)):
        raise AdmissionError("callee parameters must be distinct names", "invalid")
    try:
        scope = ast.parse(source)
    except (SyntaxError, ValueError, UnicodeError, RecursionError) as error:
        raise AdmissionError("caller source does not parse", "invalid") from error
    for part in function.split("."):
        matches = [node for node in scope.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                   and node.name == part]
        if len(matches) != 1:
            raise AdmissionError("caller function path is missing or ambiguous")
        scope = matches[0]
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise AdmissionError("caller must be a function")
    # Exclude nested function/class bodies from this caller's call-site set.
    def local_nodes(node):
        yield node
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                yield from local_nodes(child)
    nodes = list(local_nodes(scope))
    calls = [node for node in nodes if isinstance(node, ast.Call) and dotted(node.func) == callee]
    if len(calls) != 1:
        raise AdmissionError("selected caller has no unique direct consumer call")
    call = calls[0]
    if len(call.args) > len(formal_parameters) or any(isinstance(node, ast.Starred) for node in call.args):
        raise AdmissionError("consumer call has unsupported positional expansion")
    values = dict(zip(formal_parameters, call.args))
    for item in call.keywords:
        if item.arg not in formal_parameters or item.arg in values:
            raise AdmissionError("consumer call has duplicate, unknown or unpacked keyword arguments")
        values[item.arg] = item.value
    if set(values) != set(formal_parameters):
        raise AdmissionError("consumer call does not supply all selected parameters")
    available = {arg.arg for arg in scope.args.posonlyargs + scope.args.args + scope.args.kwonlyargs}
    inputs = set()

    def expression(node):
        if isinstance(node, ast.Name) and node.id in available:
            inputs.add(node.id)
            return {"parameter": node.id, "prefix": "", "suffix": ""}
        if isinstance(node, ast.Constant) and type(node.value) is str and named(node.value):
            return {"literal": node.value}
        if isinstance(node, ast.JoinedStr):
            fields = [item for item in node.values if isinstance(item, ast.FormattedValue)]
            if (len(fields) != 1 or fields[0].conversion != -1 or fields[0].format_spec is not None or
                    not isinstance(fields[0].value, ast.Name) or fields[0].value.id not in available or
                    any(not isinstance(item, (ast.Constant, ast.FormattedValue)) or
                        isinstance(item, ast.Constant) and type(item.value) is not str for item in node.values)):
                raise AdmissionError("caller string formatting needs a separate translation")
            index = node.values.index(fields[0])
            inputs.add(fields[0].value.id)
            return {"parameter": fields[0].value.id,
                    "prefix": "".join(item.value for item in node.values[:index]),
                    "suffix": "".join(item.value for item in node.values[index + 1:])}
        raise AdmissionError("caller argument needs unsupported data flow")
    arguments = [expression(values[name]) for name in formal_parameters]
    # A parameter rebound anywhere in this function is not a declared string
    # input at this slice without additional reaching-definition analysis.
    if any(isinstance(node, ast.Name) and node.id in inputs and isinstance(node.ctx, (ast.Store, ast.Del)) for node in nodes):
        raise AdmissionError("caller rebinds a selected input; reaching definitions are unresolved")
    return {"caller": function, "callee": callee, "line": call.lineno, "end_line": call.end_lineno,
            "formal_parameters": formal_parameters, "input_parameters": sorted(inputs), "arguments": arguments,
            "source_module_executed": False, "caller_path_and_authentication_verified": False}


def project_handoff(descriptor, record):
    if not isinstance(record, dict) or set(record) != set(descriptor["input_parameters"]) or any(not named(value) for value in record.values()):
        raise AdmissionError("caller handoff needs exactly its bounded typed string inputs", "input_rejected")
    result = [item["literal"] if "literal" in item else item["prefix"] + record[item["parameter"]] + item["suffix"]
              for item in descriptor["arguments"]]
    if not all(named(value) for value in result):
        raise AdmissionError("projected consumer argument exceeds its identifier envelope", "input_rejected")
    return result
