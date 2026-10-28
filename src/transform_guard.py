"""A selected direct-lookup return guard on ordinary owned component records.

No FastMCP, tool, authentication provider, server or advisory example executes.
Only the source condition following a session transform is interpreted. The
provider and authorization Boolean contracts are supplied separately.
"""
import ast
from itertools import product

from effect_slice import Capability, DataRecord, EffectInterpreter
from native_casbin import AdmissionError, MAX_TEXT_BYTES
from observation_protocol import compare_observations
from persistent_store import shape, strip_docstring


def extract_transform_guard(source):
    if type(source) is not bytes or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("transform guard source exceeds envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("transform guard source does not parse", "invalid") from error
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "FastMCP"]
    if len(classes) != 1:
        raise AdmissionError("selected FastMCP declaration is ambiguous")
    functions = [node for node in classes[0].body if isinstance(node, ast.AsyncFunctionDef) and node.name == "get_tool"]
    if len(functions) != 1 or functions[0].decorator_list:
        raise AdmissionError("selected direct tool lookup is ambiguous")
    function = functions[0]
    args = function.args
    if (args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg
            or [arg.arg for arg in args.args] != ["self", "name", "version"]
            or len(args.defaults) != 1 or shape(args.defaults[0]) != shape(ast.Constant(None))):
        raise AdmissionError("selected direct-lookup signature changed")
    body = strip_docstring(function.body)
    expected_prefix = ast.parse("""
injected = self._get_injected_tool(name) if hashed_lookup_target(self) is None else None
if injected is not None:
    return injected if await AUTH(injected) else None
tool = await super().get_tool(name, version)
if tool is None:
    return None
tools = await apply_session_transforms([tool])
""").body
    if len(body) < 7:
        raise AdmissionError("selected direct-lookup path is incomplete")
    auth_name = None
    for name in ("_tool_auth_allows", "_component_auth_allows"):
        expected = ast.parse(ast.unparse(ast.Module(body=expected_prefix, type_ignores=[])).replace("AUTH(", name + "(")).body
        if [shape(node) for node in body[:5]] == [shape(node) for node in expected]:
            auth_name = name
    if auth_name is None:
        raise AdmissionError("injection/provider/absence/transform prefix requires another translation")
    guard = body[5]
    post_auth = False
    for expression, checked in (("tools and is_enabled(tools[0])", False),
                                ("tools and is_enabled(tools[0]) and await _component_auth_allows(tools[0])", True)):
        if isinstance(guard, ast.If) and shape(guard.test) == shape(ast.parse(expression, mode="eval").body):
            post_auth = checked
            break
    else:
        raise AdmissionError("transformed return guard is outside the admitted fragment")
    if (guard.orelse or len(guard.body) != 1 or shape(guard.body[0]) != shape(ast.parse("return tools[0]").body[0])
            or shape(body[6]) != shape(ast.parse("if version is not None:\n return None").body[0])):
        raise AdmissionError("return or explicit-version fallthrough semantics changed")
    return {"condition": guard.test, "function_line": function.lineno, "guard_line": guard.lineno,
            "post_transform_auth_present": post_auth, "original_auth_helper": auth_name,
            "excluded_fallback_statement_count": len(body) - 7}


def compare_transform_guard(source):
    descriptor = extract_transform_guard(source)
    expected, observed, cases = [], [], []
    for found, original_allowed, transformed_present, enabled, final_allowed in product((False, True), repeat=5):
        available = found and original_allowed
        eligible = available and transformed_present and enabled
        reference = eligible and final_allowed
        auth_calls = []
        actual = False
        if available:
            component = DataRecord("owned_component", {"enabled": enabled, "allowed": final_allowed})
            def authorize(record):
                auth_calls.append(True)
                return record.fields["allowed"]
            interpreter = EffectInterpreter({}, DataRecord("receiver", {}), {})
            environment = {"tools": [component] if transformed_present else [],
                "is_enabled": Capability("enabled", lambda record: record.fields["enabled"]),
                "_component_auth_allows": Capability("auth", authorize, True)}
            actual = interpreter.truth(interpreter.value(descriptor["condition"], environment))
        expected.append({"decision": "allow" if reference else "deny", "flags": {"post_auth_called": eligible}})
        observed.append({"decision": "allow" if actual else "deny", "flags": {"post_auth_called": bool(auth_calls)}})
        cases.append({"provider_found": found, "original_allowed": original_allowed,
                      "transformed_present": transformed_present, "enabled": enabled, "transformed_allowed": final_allowed,
                      "expected_return": reference, "observed_return": actual, "auth_calls": len(auth_calls)})
    result = compare_observations(expected, observed,
        "selected non-injected explicit-version direct lookup; supplied pre-authorized provider and final-component Boolean authorization contracts")
    return {"accepted": result["accepted"], "status": result["status"], "comparison": result, "cases": cases,
            "descriptor": {key: value for key, value in descriptor.items() if key != "condition"},
            "different_observations": sum(a != b for a, b in zip(expected, observed)),
            "unauthorized_return_contexts": sum(row["observed_return"] and not row["expected_return"] for row in cases),
            "component_or_server_or_advisory_example_executed": False,
            "actual_auth_predicate_provider_or_full_lookup_verified": False,
            "resource_shadowing_templates_prompts_and_version_fallback_not_compared": True}
