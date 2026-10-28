"""Data-only projections of two explicitly admitted source boundary shapes.

No source module, callback, coroutine, ORM, HTTP handler or exploit is run.
This is a syntactic source binding plus an owned finite observation model, not
unconditional Python extraction soundness or complete vulnerability execution.
"""
import ast
from itertools import product

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from observation_protocol import compare_observations
from source_bindings import require_import_bindings, require_static_class_members


def dump(node):
    return ast.dump(node, include_attributes=False)


def parse(source):
    if type(source) is not bytes or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("historical source exceeds reading envelope", "inconclusive")
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, UnicodeError, RecursionError) as error:
        raise AdmissionError("historical source does not parse", "invalid") from error


def method(tree, selector):
    scope = tree
    for part in selector.split("."):
        matches = [node for node in scope.body if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == part]
        if len(matches) != 1:
            raise AdmissionError("selected historical source method is not unique")
        scope = matches[0]
    if not isinstance(scope, ast.FunctionDef):
        raise AdmissionError("selected boundary must be synchronous")
    body = [node for node in scope.body if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str)]
    return scope, body


def statements(text):
    return ast.parse(text).body


def match_body(actual, expected):
    return [dump(node) for node in actual] == [dump(node) for node in expected]


def extract_session_filter(source):
    tree = parse(source)
    function, body = method(tree, "SessionFetcher._build_sessions_api_data")
    args = function.args
    if (function.decorator_list or [item.arg for item in args.args] != ["self", "sessions"] or args.posonlyargs
            or args.kwonlyargs or args.defaults or args.vararg or args.kwarg or len(body) != 3):
        raise AdmissionError("selected serialization boundary signature/body changed")
    if not match_body([body[0], body[2]], statements("session_blocks = []\nreturn session_blocks")):
        raise AdmissionError("serialization result binding changed")
    loop = body[1]
    if not isinstance(loop, ast.For) or loop.orelse or dump(loop.target) != dump(ast.Name(id="session_", ctx=ast.Store())) or dump(loop.iter) != dump(ast.Name(id="sessions", ctx=ast.Load())):
        raise AdmissionError("serialization loop binding is outside the admitted source shape")
    expected = statements('''can_manage = self.user is not None and session_.can_manage(self.user)
session_access_list = None
serialized_session = self._serialize_session(session_)
if self.user and session_.can_manage(self.user):
 session_access_list = self._serialize_access_list(session_)
session_blocks.extend(self._serialize_session_block(b, serialized_session, session_access_list, can_manage) for b in session_.blocks)
''')
    guards = {"none": [], "skip_inaccessible": statements("if not session_.can_access(self.user):\n continue"),
              "skip_accessible": statements("if session_.can_access(self.user):\n continue")}
    modes = [mode for mode, prefix in guards.items() if match_body(loop.body, prefix + expected)]
    if len(modes) != 1:
        raise AdmissionError("entire selected serialization loop is not the admitted filter/consumer shape")
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "SessionFetcher")
    require_static_class_members(cls, {"_build_sessions_api_data"})
    return {"shape": "session-block-filter", "guard": modes[0], "line": function.lineno, "end_line": function.end_lineno,
            "contract": "given session access Booleans and block slots; serialized parent metadata is carried into each block output",
            "opaque_callbacks_not_executed": ["can_access", "can_manage", "_serialize_session", "_serialize_access_list", "_serialize_session_block"]}


def compare_session_filter(source, sessions=3):
    if type(sessions) is not int or not 1 <= sessions <= 3:
        raise AdmissionError("session observation envelope is one to three rows", "inconclusive")
    descriptor = extract_session_filter(source)
    reference, observed, records = [], [], []
    # Each supplied row has zero/one/two block slots and a supplied access bit.
    # No actual session, user, database record or metadata body is accessed.
    for context in product(tuple(product((False, True), (0, 1, 2))), repeat=sessions):
        expected, actual = {}, {}
        for index, (access, blocks) in enumerate(context):
            keep = descriptor["guard"] == "none" or descriptor["guard"] == "skip_inaccessible" and access or descriptor["guard"] == "skip_accessible" and not access
            for slot in range(2):
                name = "session_" + str(index) + "_slot_" + str(slot)
                expected[name] = bool(access and slot < blocks)
                actual[name] = bool(keep and slot < blocks)
        reference.append({"decision": "allow" if any(expected.values()) else "deny", "flags": expected})
        observed.append({"decision": "allow" if any(actual.values()) else "deny", "flags": actual})
        records.append({"given_access_and_block_counts": context, "expected_visible_slots": expected, "source_projected_visible_slots": actual})
    result = compare_observations(reference, observed, "given session/block output-membership projection after an accessible parent-event boundary; not HTTP/ORM/full serialization execution")
    return {"descriptor": descriptor, "result": result, "contexts": records,
            "different_contexts": sum(left != right for left, right in zip(reference, observed)),
            "unverified": ["actual can_access/identity issuance and parent-event API admission", "real ORM, arbitrary serializer bodies/metadata values or output order", "extensions, deployment and endpoint execution"]}


def extract_sync_permissions(source):
    tree = parse(source)
    require_import_bindings(source, {"inspect": ("inspect", 0, None), "iscoroutinefunction": ("inspect", 0, "iscoroutinefunction")})
    function, body = method(tree, "PermissionExtension.resolve")
    args = function.args
    if (function.decorator_list or [item.arg for item in args.args] != ["self", "next_", "source", "info"] or args.posonlyargs
            or args.kwonlyargs or args.defaults or args.vararg or args.kwarg is None or args.kwarg.arg != "kwargs" or len(body) != 2):
        raise AdmissionError("synchronous permission resolver signature/body changed")
    loop = body[0]
    if (not isinstance(loop, ast.For) or loop.orelse or dump(loop.target) != dump(ast.Name(id="permission", ctx=ast.Store()))
            or dump(loop.iter) != dump(ast.parse("self.permissions", mode="eval").body)
            or dump(body[1]) != dump(statements("return next_(source, info, **kwargs)")[0])):
        raise AdmissionError("permission callback/next binding changed")
    before = statements("if not permission.has_permission(source, info, **kwargs):\n return self._on_unauthorized(permission)")
    after = statements('''has_permission = permission.has_permission(source, info, **kwargs)
if inspect.isawaitable(has_permission):
 if inspect.iscoroutine(has_permission):
  has_permission.close()
 raise PermissionReturnedAwaitableInSyncContextError(permission)
if not has_permission:
 return self._on_unauthorized(permission)
''')
    if match_body(loop.body, before):
        mode = "truth_test"
    elif match_body(loop.body, after):
        require_import_bindings(source, {"PermissionReturnedAwaitableInSyncContextError": ("strawberry.exceptions", 0, "PermissionReturnedAwaitableInSyncContextError")})
        mode = "reject_awaitable"
    else:
        raise AdmissionError("entire selected synchronous permission loop needs a separate translation")
    sync, sync_body = method(tree, "PermissionExtension.supports_sync")
    require_import_bindings(source, {"cached_property": ("functools", 0, "cached_property")})
    if ([dump(node) for node in sync.decorator_list] != [dump(ast.Name(id="cached_property", ctx=ast.Load()))]
            or [node.arg for node in sync.args.args] != ["self"] or sync.args.defaults or sync.args.kwonlyargs
            or sync.args.posonlyargs or sync.args.vararg or sync.args.kwarg):
        raise AdmissionError("sync-path eligibility property binding changed")
    expected_sync = statements("async_permissions = [True for permission in self.permissions if iscoroutinefunction(permission.has_permission)]\nreturn len(async_permissions) == 0")
    if not match_body(sync_body, expected_sync):
        raise AdmissionError("sync-path eligibility changed")
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "PermissionExtension")
    require_static_class_members(cls, {"resolve", "supports_sync"})
    return {"shape": "sync-permission-return-protocol", "mode": mode, "line": function.lineno, "end_line": function.end_lineno,
            "sync_path": "callbacks are plain def, not async def; return type is checked separately", "source_module_executed": False}


TOKENS = ("boolean_false", "boolean_true", "coroutine_false", "coroutine_true", "future_false", "future_true", "custom_falsy_awaitable")


def observe_permissions(tokens, mode):
    if (mode not in ("truth_test", "reject_awaitable") or type(tokens) not in (tuple, list) or len(tokens) > 2
            or any(token not in TOKENS for token in tokens)):
        raise AdmissionError("permission observation needs the declared typed return envelope")
    # These are owned typed records, not runnable coroutines or callbacks.
    flags = {"next_called": False, "unauthorized_called": False, "async_context_error": False, "coroutine_close_called": False}
    for token in tokens:
        awaitable = token not in ("boolean_false", "boolean_true")
        if mode == "reject_awaitable" and awaitable:
            flags["async_context_error"] = True
            flags["coroutine_close_called"] = token.startswith("coroutine_")
            return {"decision": "deny", "flags": flags}
        # Unlike the overly broad claim 'all awaitables are truthy', a custom
        # Awaitable can define false truthiness. Its case stays in the domain.
        truth = token not in ("boolean_false", "custom_falsy_awaitable")
        if not truth:
            flags["unauthorized_called"] = True
            return {"decision": "deny", "flags": flags}
    flags["next_called"] = True
    return {"decision": "allow", "flags": flags}


def reference_permissions(tokens):
    """Independent first-failure contract, not the source projection's loop."""
    first = next((token for token in tokens if token != "boolean_true"), None)
    expected = {"next_called": first is None, "unauthorized_called": first == "boolean_false",
                "async_context_error": first is not None and first != "boolean_false",
                "coroutine_close_called": first is not None and first.startswith("coroutine_")}
    return {"decision": "allow" if first is None else "deny", "flags": expected}


def compare_sync_permissions(source, maximum_permissions=2):
    if type(maximum_permissions) is not int or not 1 <= maximum_permissions <= 2:
        raise AdmissionError("permission return-family envelope is one or two callbacks", "inconclusive")
    descriptor = extract_sync_permissions(source)
    inputs = [list(tokens) for count in range(maximum_permissions + 1) for tokens in product(TOKENS, repeat=count)]
    # The reference is the published fail-closed sync-context contract. It
    # preserves an error and close event, rather than relabeling it plain deny.
    reference = [reference_permissions(tokens) for tokens in inputs]
    observed = [observe_permissions(tokens, descriptor["mode"]) for tokens in inputs]
    result = compare_observations(reference, observed, "given synchronous permission path and owned typed callback-return records; error/close/next observations retained")
    return {"descriptor": descriptor, "result": result, "given_return_records": inputs,
            "reference_observations": reference, "source_projected_observations": observed,
            "different_contexts": sum(left != right for left, right in zip(reference, observed)),
            "unverified": ["GraphQL field/extension dispatch and actual application callbacks", "arbitrary Python values or runtime rebinding", "whole package execution or exploit reproduction"]}
