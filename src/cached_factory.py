"""Recognize a cached native-engine factory and observe its component API.

Source functions are parsed, never imported. The admitted descriptor binds the
source's lru_cache/clear/acquire/enforce pattern to reviewed native primitives.
File location and default-configuration choice are explicit input contracts.
"""
from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path
import tempfile

from language import normalize
from native_casbin import AdmissionError, MAX_TEXT_BYTES, admit_configuration
from native_runtime import engine_identity
from protocol_check import verify_protocol


def _body(function):
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body.pop(0)
    return body


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return left + "." + node.attr if left else None
    return None


def _log(statement):
    if not (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
            and _dotted(statement.value.func) == "logger.info" and len(statement.value.args) == 1
            and not statement.value.keywords):
        return False
    return all(isinstance(n, (ast.Constant, ast.JoinedStr, ast.FormattedValue, ast.Name, ast.Load))
               for n in ast.walk(statement.value.args[0]))


def extract_cached_factory(source: bytes):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("cached factory source exceeds its envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("cached factory source is invalid", "invalid") from error
    functions = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in functions:
                raise AdmissionError("cached source has ambiguous function definitions")
            functions[node.name] = node
    if not all(name in functions for name in ("get_enforcer", "reload_enforcer", "check_permission")):
        raise AdmissionError("cached source is missing a factory, clearer or consumer")
    imports = {(n.module, n.level, alias.name, alias.asname) for n in tree.body if isinstance(n, ast.ImportFrom) for alias in n.names}
    if (("functools", 0, "lru_cache", None) not in imports or (None, 1, "get_auth_config", None) not in imports
            or not any(isinstance(n, ast.Import) and [(a.name, a.asname) for a in n.names] == [("casbin", None)] for n in tree.body)):
        raise AdmissionError("cached source primitives do not have their declared imports")
    factory, clearer, consumer = (functions[name] for name in ("get_enforcer", "reload_enforcer", "check_permission"))
    for function in (factory, clearer, consumer):
        a = function.args
        if not isinstance(function, ast.FunctionDef) or a.vararg or a.kwarg or a.posonlyargs or a.kwonlyargs or a.defaults:
            raise AdmissionError("cached component function interface is unsupported")
    if factory.args.args or clearer.args.args:
        raise AdmissionError("cached factory/clearer must not accept dynamic arguments")
    if len(factory.decorator_list) != 1:
        raise AdmissionError("cached factory needs exactly its reviewed lru_cache decorator")
    decorator = factory.decorator_list[0]
    if not (isinstance(decorator, ast.Call) and _dotted(decorator.func) == "lru_cache" and not decorator.args
            and len(decorator.keywords) == 1 and decorator.keywords[0].arg == "maxsize"
            and isinstance(decorator.keywords[0].value, ast.Constant) and type(decorator.keywords[0].value.value) is int
            and decorator.keywords[0].value.value == 1):
        raise AdmissionError("cached factory is not the reviewed maxsize-one pattern")
    body = [n for n in _body(factory) if not _log(n)]
    if len(body) != 5:
        raise AdmissionError("native cached factory contains unreviewed statements")
    required = ["config = get_auth_config()", "model_path = _get_config_path(config.rbac.model_path)",
                "policy_path = _get_config_path(config.rbac.policy_path)",
                "enforcer = casbin.Enforcer(model_path, policy_path)", "return enforcer"]
    if [ast.dump(n, include_attributes=False) for n in body] != [ast.dump(ast.parse(text).body[0], include_attributes=False) for text in required]:
        raise AdmissionError("cached factory data flow differs from its native-file descriptor")
    clear_body = [n for n in _body(clearer) if not _log(n)]
    if (clearer.decorator_list or len(clear_body) != 1 or not isinstance(clear_body[0], ast.Expr)
            or not isinstance(clear_body[0].value, ast.Call) or _dotted(clear_body[0].value.func) != "get_enforcer.cache_clear"
            or clear_body[0].value.args or clear_body[0].value.keywords):
        raise AdmissionError("cache reload does not directly clear the admitted factory")
    consumer_body = _body(consumer)
    if (consumer.decorator_list or [a.arg for a in consumer.args.args] != ["role", "resource", "action"]
            or [ast.dump(n, include_attributes=False) for n in consumer_body] !=
            [ast.dump(ast.parse(text).body[0], include_attributes=False) for text in
             ("enforcer = get_enforcer()", "return enforcer.enforce(role, resource, action)")]):
        raise AdmissionError("consumer does not have the admitted acquire-then-enforce ordering")
    # Rebinding a module primitive would invalidate the source/import contract.
    protected = {"casbin", "lru_cache", "get_auth_config", "get_enforcer", "reload_enforcer", "check_permission"}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in protected for t in targets):
                raise AdmissionError("cached source rebinds a protected module primitive")
    return {"factory": "get_enforcer", "factory_lines": [factory.lineno, factory.end_lineno],
            "clearer": "reload_enforcer", "clearer_lines": [clearer.lineno, clearer.end_lineno],
            "consumer": "check_permission", "consumer_lines": [consumer.lineno, consumer.end_lineno],
            "cache_maxsize": 1, "native_constructor": "casbin.Enforcer(model_path, policy_path)",
            "consumer_event_order": ["acquire", "authorize"], "source_module_executed": False,
            "configuration_resolution": "explicit selected default-file contract; alternate OS paths and overrides are not certified"}


def _policy_text(rows):
    return "\n".join(", ".join(row) for row in rows) or "# empty policy"


class NativeFileFactory:
    """Reviewed lru_cache and Casbin FileAdapter bound by a source descriptor."""
    def __init__(self, descriptor, model_text, rows):
        if descriptor.get("cache_maxsize") != 1 or descriptor.get("consumer_event_order") != ["acquire", "authorize"]:
            raise AdmissionError("native factory needs an admitted source descriptor")
        self.identity = engine_identity()
        self.model_text, self.last_engine = model_text, None
        self.engine_constructions, self.native_calls, self.file_writes, self.clear_calls = 0, 0, 0, 0
        self.directory = tempfile.TemporaryDirectory(prefix="authrefine-native-file-factory-")
        self.model_path, self.policy_path = Path(self.directory.name) / "model.conf", Path(self.directory.name) / "policy.csv"
        self.model_path.write_text(model_text, encoding="utf-8")
        self.replace(rows)

        @lru_cache(maxsize=1)
        def build():
            import casbin
            engine_identity()
            instance = casbin.Enforcer(str(self.model_path), str(self.policy_path))
            instance.enable_auto_save(False)
            self.engine_constructions += 1
            self.last_engine = instance
            self._validate_loaded(instance)
            return instance
        self.factory = build

    def close(self):
        self.factory.cache_clear()
        self.directory.cleanup()

    def replace(self, rows):
        configuration = admit_configuration(self.model_text, _policy_text(rows))
        if configuration.rows != [list(row) for row in rows] or len(rows) != len({tuple(row) for row in rows}):
            raise AdmissionError("native file rows change during loading or are duplicated")
        self.policy_path.write_text(configuration.policy_text, encoding="utf-8")
        self.rows = [list(row) for row in rows]
        self.file_writes += 1

    def _validate_loaded(self, instance):
        for section in ("p", "g"):
            for kind, assertion in instance.model.model.get(section, {}).items():
                if assertion.policy != [row[1:] for row in self.rows if row[0] == kind]:
                    raise AdmissionError("native file loader disagrees with the supplied source rows", "invalid")

    def acquire(self):
        return self.factory()

    def clear(self):
        self.factory.cache_clear()
        self.last_engine = None
        self.clear_calls += 1

    def sink(self, request):
        if self.factory.cache_info().currsize != 1 or self.last_engine is None:
            raise AdmissionError("native sink has no preceding engine acquisition", "input_rejected")
        decision = self.last_engine.enforce(*request)
        if type(decision) is not bool:
            raise AdmissionError("native sink returned a non-Boolean", "native_error")
        self.native_calls += 1
        return decision


def component_policy(initial_permission=True):
    action = lambda name: {"field": "action", "name": name, "negated": False}
    state = lambda name, value: {"field": "state", "name": name, "value": value}
    return normalize({"principals": ["api"], "resources": ["factory"],
        "actions": ["acquire", "authorize", "clear", "grant", "revoke"], "roles": [], "members": [],
        "state": [["cache_loaded", False], ["cache_permission", False], ["file_permission", initial_permission]], "aliases": [],
        "rules": [
            {"decision": "allow", "guard": [action("grant")], "updates": [{"name": "file_permission", "value": True}]},
            {"decision": "allow", "guard": [action("revoke")], "updates": [{"name": "file_permission", "value": False}]},
            {"decision": "allow", "guard": [action("clear")], "updates": [{"name": "cache_loaded", "value": False}, {"name": "cache_permission", "value": False}]},
            {"decision": "allow", "guard": [action("acquire"), state("cache_loaded", False)],
             "updates": [{"name": "cache_loaded", "value": True}, {"name": "cache_permission", "from": "file_permission", "negated": False}]},
            {"decision": "allow", "guard": [action("acquire"), state("cache_loaded", True)], "updates": []},
            {"decision": "allow", "guard": [action("authorize"), state("cache_loaded", True), state("cache_permission", True)], "updates": []}]})


def export_cached_component(descriptor, model_text, full_rows, selected_row, request):
    configuration = admit_configuration(model_text, _policy_text(full_rows))
    if configuration.family != "rbac" or selected_row not in full_rows or selected_row[0] != "p":
        raise AdmissionError("cached component needs one selected exact-RBAC permission row")
    # For this concrete permission, fixed non-selected policy must deny, and
    # restoring the selected row must allow. No hidden alternative grant is dropped.
    base = [row for row in full_rows if row != selected_row]
    source = component_policy(True)
    alphabet = [["api", "factory", action] for action in source["actions"]]
    observations = [0, 1, 3, 4, 5, 7]
    table, records = [], []
    totals = {"native_sink_calls": 0, "measured_engine_constructions": 0,
              "initialization_engine_constructions": 0, "measured_file_writes": 0,
              "measured_cache_clears": 0, "acquire_component_events": 0}

    def rows(present):
        return [list(row) for row in full_rows if row != selected_row or present]

    def observe(factory):
        file_rows = admit_configuration(model_text, factory.policy_path.read_text(encoding="utf-8")).rows
        present = selected_row in file_rows
        if [row for row in file_rows if row != selected_row] != base:
            raise AdmissionError("file observation hides an unrepresented fixed row", "invalid")
        loaded = factory.factory.cache_info().currsize == 1
        permission = False
        if loaded:
            if factory.last_engine is None:
                raise AdmissionError("native cache presence and instance observation disagree", "invalid")
            policy_rows = [[kind, *entry] for section in ("p", "g") for kind, assertion in factory.last_engine.model.model.get(section, {}).items() for entry in assertion.policy]
            expected_fixed = [row for row in full_rows if row != selected_row]
            if sorted(row for row in policy_rows if row != selected_row) != sorted(expected_fixed):
                raise AdmissionError("cache observation hides an unrepresented fixed row", "invalid")
            permission = selected_row in policy_rows
        return int(loaded) | (int(permission) << 1) | (int(present) << 2)

    # The selected native request itself is validated against both complete
    # policy alternatives before any cached abstraction is accepted.
    alternatives = []
    for present in (False, True):
        factory = NativeFileFactory(descriptor, model_text, rows(present))
        try:
            factory.acquire()
            alternatives.append(factory.sink(request))
        finally:
            factory.close()
    if alternatives != [False, True]:
        raise AdmissionError("selected request is not exactly controlled by the chosen policy row")

    for observation in observations:
        loaded, cached, stored = bool(observation & 1), bool(observation & 2), bool(observation & 4)
        edges = []
        for _, _, action in alphabet:
            if action == "authorize" and not loaded:
                edges.append(None)  # no acquired receiver; excluded by the source caller protocol
                continue
            factory = NativeFileFactory(descriptor, model_text, rows(cached if loaded else stored))
            try:
                if loaded:
                    factory.acquire()
                    factory.replace(rows(stored))
                if observe(factory) != observation:
                    raise AdmissionError("native component initialization disagrees with its observation", "invalid")
                before = (factory.engine_constructions, factory.file_writes, factory.clear_calls)
                totals["initialization_engine_constructions"] += before[0]
                if action == "acquire":
                    factory.acquire()
                    decision = True
                    totals["acquire_component_events"] += 1
                elif action == "authorize":
                    decision = factory.sink(request)
                    totals["native_sink_calls"] += 1
                elif action == "clear":
                    factory.clear()
                    decision = True
                else:
                    factory.replace(rows(action == "grant"))
                    decision = True  # successful file-write completion, not an administrative entitlement
                post = observe(factory)
                edges.append(["allow" if decision else "deny", observations.index(post)])
                totals["measured_engine_constructions"] += factory.engine_constructions - before[0]
                totals["measured_file_writes"] += factory.file_writes - before[1]
                totals["measured_cache_clears"] += factory.clear_calls - before[2]
                records.append({"observation": observation, "action": action, "decision": decision, "after": post})
            finally:
                factory.close()
        table.append(edges)
    machine = {"state_names": [name for name, _ in source["state"]], "alphabet": alphabet,
               "observations": observations, "initial": observations.index(4), "transitions": table}
    protocol_rows = [[None] * len(alphabet) for _ in range(2)]
    for index, (_, _, action) in enumerate(alphabet):
        if action == "authorize":
            protocol_rows[1][index] = 0
        else:
            protocol_rows[0][index] = 1 if action == "acquire" else 0
    protocol = {"initial": 0, "transitions": protocol_rows}
    comparison = verify_protocol(source, machine, protocol)
    return {"status": comparison["status"], "accepted": comparison["accepted"], "source_descriptor": descriptor,
            "selected_policy_row": selected_row, "native_request": request,
            "counts": totals, "policy": source, "machine": machine, "protocol": protocol,
            "comparison": comparison, "raw_component_observations": records,
            "scope": "source-bound sequential native file factory and consumer component events",
            "unconditional_external_api_refinement": False,
            "assumptions": ["source exact acquire-then-enforce ordering; no external retained engine references",
                            "no interleaving file mutation/cache clearing between acquisition and its sink",
                            "one varying permission row; all other policy and role rows observed and fixed",
                            "file writes, clears and acquisitions encode successful API completion, not authorization entitlement"]}
