"""Interpret an adjacent source dictionary-construction block on given data.

The block starts at the selected local dictionary assignment and ends at an
exact reviewed barrier. Earlier providers/guards and later consumers are not
executed. No hand-written field mapping, application import or source bytecode
is used. This is a local block contract, not general program slicing soundness.
"""
import ast
import argparse
import copy
import json
from pathlib import Path

from effect_slice import DataRecord, EffectInterpreter, PRIMITIVES, extract_effect_program, require_plain_data
from language import strict_json
from native_casbin import AdmissionError, MAX_TEXT_BYTES
from persistent_store import shape, strip_docstring
from source_bindings import require_static_definitions


def extract_record_projection(source, function_name, record_name, barrier):
    if (type(source) is not bytes or len(source) > MAX_TEXT_BYTES
            or type(function_name) is not str or not function_name.isidentifier()
            or type(record_name) is not str or not record_name.isidentifier()
            or record_name in PRIMITIVES or not isinstance(barrier, ast.stmt)):
        raise AdmissionError("record source selection is outside its envelope")
    try:
        tree = ast.parse(source)
    except (SyntaxError, UnicodeError, ValueError, RecursionError) as error:
        raise AdmissionError("record source does not parse", "invalid") from error
    require_static_definitions(tree, [function_name], PRIMITIVES)
    function = next(node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name)
    if function.decorator_list:
        raise AdmissionError("record source decorator requires a separate binding contract")
    arguments = function.args
    argument_names = {arg.arg for arg in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]}
    argument_names.update(arg.arg for arg in (arguments.vararg, arguments.kwarg) if arg is not None)
    if argument_names & PRIMITIVES:
        raise AdmissionError("record source parameters shadow a bound primitive")
    body = strip_docstring(function.body)
    matches = [i for i, node in enumerate(body) if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name) and node.targets[0].id == record_name and isinstance(node.value, ast.Dict)]
    if len(matches) != 1:
        raise AdmissionError("record block requires one unique direct dictionary declaration")
    start, end = matches[0], matches[0] + 1
    while end < len(body) and isinstance(body[end], ast.For):
        end += 1
    if end - start > 9 or end >= len(body) or shape(body[end]) != shape(barrier):
        raise AdmissionError("record block does not meet its exact adjacent barrier")
    selected = copy.deepcopy(function)
    selected.body = copy.deepcopy(body[start:end])
    if any(isinstance(node, (ast.Return, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            for statement in selected.body for node in ast.walk(statement)):
        raise AdmissionError("record block cannot return early or declare nested bindings")
    owned = ast.fix_missing_locations(ast.Module(body=[selected], type_ignores=[]))
    program = extract_effect_program(ast.unparse(owned).encode(), None, [], [function_name])
    if [shape(s) for s in program[function_name].body] != [shape(s) for s in selected.body]:
        raise AdmissionError("record construction AST changed during block transport")
    loads = {node.id for statement in selected.body for node in ast.walk(statement)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
    stores = {node.id for statement in selected.body for node in ast.walk(statement)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
    required = sorted(loads - stores - PRIMITIVES)
    descriptor = {"function": function_name, "record_variable": record_name,
        "block_first_line": body[start].lineno, "block_last_line": body[end - 1].end_lineno,
        "given_value_bindings": required, "earlier_statements_not_interpreted": start,
        "first_unexamined_tail_line": body[end].lineno, "remaining_tail_statements": len(body) - end,
        "field_mapping_hand_transcribed": False, "selected_executable_ast_preserved": True,
        "full_function_or_reachability_proved": False}
    return {"program": program, "function": function_name, "record": record_name,
        "required": required, "descriptor": descriptor}


def project_record(extracted, given_values, *, step_limit=50000):
    if type(given_values) is not dict or set(given_values) != set(extracted["required"]):
        raise AdmissionError("record block needs every given binding exactly once")
    require_plain_data(given_values)
    receiver = DataRecord("owned_record_block", {})
    instance = EffectInterpreter(extracted["program"], receiver, {}, step_limit)
    # Inputs are snapshots owned by this invocation, including nested mappings.
    env = {**instance.bindings, **copy.deepcopy(given_values)}
    returned = instance.statements(extracted["program"][extracted["function"]].body, env)
    if returned is not None or type(env.get(extracted["record"])) is not dict:
        raise AdmissionError("record block did not produce its declared plain mapping")
    value = env[extracted["record"]]
    require_plain_data(value, charge=instance.charge)
    return {"value": copy.deepcopy(value), "source_interpretation_steps": instance.steps,
        "field_mapping_hand_transcribed": False, "full_function_or_reachability_proved": False}


def plain_key(value):
    """Exact typed comparison; Python's True == 1 is not this contract."""
    if value is None:
        return ("null",)
    if type(value) in (bool, int, str):
        return (type(value).__name__, value)
    if type(value) in (list, tuple):
        return (type(value).__name__, tuple(plain_key(item) for item in value))
    if type(value) is dict and all(type(key) is str for key in value):
        return ("dict", tuple((key, plain_key(value[key])) for key in sorted(value)))
    raise AdmissionError("expected record contains an uncontracted type")


def compare_projection_cases(extracted, cases):
    if type(cases) is not list or not 1 <= len(cases) <= 128:
        raise AdmissionError("record comparison requires one to128 planned cases")
    if any(type(row) is not dict or set(row) != {"given_values", "expected_mapping"} for row in cases):
        raise AdmissionError("each record case requires explicit inputs and an independent expected mapping")
    rows, used_bytes, budget_exhausted = [], 0, False
    for index, row in enumerate(cases):
        if budget_exhausted:
            rows.append({"case_index": index, "status": "inconclusive", "accepted": None,
                "reason": "aggregate result envelope exhausted before this case"})
            continue
        try:
            require_plain_data(row["expected_mapping"])
            if type(row["expected_mapping"]) is not dict:
                raise AdmissionError("independent expected value must be a mapping")
            result = project_record(extracted, row["given_values"])
            agrees = plain_key(result["value"]) == plain_key(row["expected_mapping"])
            record = {"case_index": index, "status": "equivalent" if agrees else "mismatch",
                "accepted": agrees, "observed_mapping": result["value"],
                "source_interpretation_steps": result["source_interpretation_steps"]}
            size = len(json.dumps(record, ensure_ascii=True).encode())
            if used_bytes + size > 2_000_000:
                budget_exhausted = True
                raise AdmissionError("aggregate result envelope exhausted", "inconclusive")
            used_bytes += size
        except AdmissionError as error:
            record = {"case_index": index, "status": error.status, "accepted": None, "reason": str(error)}
        rows.append(record)
    mismatches = sum(row["accepted"] is False for row in rows)
    agreements = sum(row["accepted"] is True for row in rows)
    accepted = False if mismatches else True if agreements == len(rows) else None
    return {"accepted": accepted, "status": "mismatch" if mismatches else "equivalent" if accepted is True else "inconclusive",
        "cases": len(cases), "agreements": agreements, "mismatches": mismatches,
        "unresolved": len(cases) - agreements - mismatches, "case_results": rows,
        "source_projection": extracted["descriptor"], "whole_application_verified": False,
        "independent_expected_mappings_supplied_by_caller": True,
        "application_modules_or_source_bytecode_executed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source", type=Path)
    source.add_argument("--archive", type=Path)
    parser.add_argument("--member")
    parser.add_argument("--function", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--barrier", required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.receipt.exists():
        parser.error("receipt exists; an old success must not stand in for the current execution")
    try:
        if len(args.barrier) > 4096 or bool(args.archive) != bool(args.member):
            raise AdmissionError("one archive member or a direct source file and one bounded barrier are required")
        barrier = ast.parse(args.barrier).body
        if len(barrier) != 1:
            raise AdmissionError("record barrier must be exactly one statement")
        if args.archive:
            from rest_source_chain import SourceArchive
            bundle = SourceArchive(args.archive)
            try:
                raw = bundle.read(args.member)
            finally:
                bundle.close()
        else:
            with args.source.open("rb") as stream:
                raw = stream.read(MAX_TEXT_BYTES + 1)
        with args.cases.open("rb") as stream:
            encoded_cases = stream.read(1_048_577)
        if len(encoded_cases) > 1_048_576:
            raise AdmissionError("record input exceeds the byte envelope", "inconclusive")
        plan = extract_record_projection(raw, args.function, args.record, barrier[0])
        result = compare_projection_cases(plan, strict_json(encoded_cases.decode("utf-8-sig")))
    except (AdmissionError, OSError, ValueError, SyntaxError) as error:
        result = {"status": getattr(error, "status", "invalid"), "accepted": None,
            "error_type": type(error).__name__, "reason": str(error), "whole_application_verified": False}
    try:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        with args.receipt.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(result, ensure_ascii=True, indent=2) + "\n")
    except OSError as error:
        print(json.dumps({"status": "receipt_write_failed", "accepted": None, "error_type": type(error).__name__}))
        return 2
    print(json.dumps({"status": result["status"], "accepted": result["accepted"], "receipt": str(args.receipt)}, ensure_ascii=True))
    return 0 if result["accepted"] is True else 1 if result["accepted"] is False else 2


if __name__ == "__main__":
    raise SystemExit(main())
