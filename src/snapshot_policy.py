"""Selected DB-row producer / ready consumer comparison, not an ORM audit."""
import configparser
from copy import deepcopy
import re

from async_snapshot import SnapshotInterpreter, extract_snapshot_program
from checker import verify_reachable
from language import named, normalize
from native_casbin import AdmissionError, _schema
from native_runtime import engine_identity
from policy_slice import program_descriptor

MATCHER = 'g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act || g2(r.sub, "system_admin")'
FIELDS = {"ptype", *("v" + str(i) for i in range(6))}


def validate_snapshot(rules, owners):
    if type(rules) is not list or type(owners) is not list or len(rules) > 128 or len(owners) > 128:
        raise AdmissionError("database snapshots need bounded row lists", "inconclusive")
    for row in rules:
        if type(row) is not dict or set(row) != FIELDS or row["ptype"] not in ("p", "g", "g2"):
            raise AdmissionError("database policy row is outside the declared projection")
        size = {"p": 4, "g": 3, "g2": 2}[row["ptype"]]
        values = [row["v" + str(i)] for i in range(6)]
        if not all(named(value) for value in values[:size]) or any(value is not None for value in values[size:]):
            raise AdmissionError("nullable database row needs non-null declared fields and a null suffix")
    for row in owners:
        if (type(row) is not dict or set(row) != {"user_id", "resource_type", "resource_id"}
                or any(type(row[key]) is not int or not 0 <= row[key] <= 1_000_000 for key in ("user_id", "resource_id"))
                or not named(row["resource_type"])):
            raise AdmissionError("resource ownership rows need bounded typed keys", "input_rejected")
    # Keep within the native manager's bounded hierarchy. Reject long chains
    # rather than assuming an unbounded transitive closure equals that manager.
    for kind in ("g", "g2"):
        edges = [row for row in rules if row["ptype"] == kind]
        domains = {row["v2"] for row in edges} if kind == "g" else {None}
        for domain in domains:
            graph = {}
            for row in edges:
                if kind == "g" and row["v2"] != domain:
                    continue
                graph.setdefault(row["v0"], set()).add(row["v1"])
            for start in graph:
                visiting, memo = set(), {}
                def height(node):
                    if node in visiting:
                        raise AdmissionError("cyclic role snapshots require a separate hierarchy contract")
                    if node not in memo:
                        visiting.add(node)
                        memo[node] = 1 + max((height(child) for child in graph.get(node, set())), default=0)
                        visiting.remove(node)
                    return memo[node]
                if height(start) > 8:
                    raise AdmissionError("role chain exceeds native agreement envelope", "inconclusive")


def reference_rows(rules):
    return [list(row) for row in dict.fromkeys(tuple([kind, *[value["v" + str(i)] for i in range({"p": 4, "g": 3, "g2": 2}[kind])]])
            for kind in ("p", "g", "g2") for value in rules if value["ptype"] == kind)]


class NativeSnapshot:
    def __init__(self, model_text):
        self.identity = engine_identity()
        parsed = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=True)
        try:
            parsed.read_string(model_text)
        except configparser.Error as error:
            raise AdmissionError("snapshot model is not a valid static configuration", "invalid") from error
        actual = {key: dict(parsed.items(key)) for key in parsed.sections()}
        expected = _schema("rbac_with_domains")
        expected["role_definition"]["g2"] = "_, _"
        expected["matchers"]["m"] = MATCHER
        compact = lambda table: {key: {name: re.sub(r"\s+", "", value) for name, value in row.items()} for key, row in table.items()}
        if parsed.defaults() or compact(actual) != compact(expected):
            raise AdmissionError("snapshot model/global-role matcher changed")
        import casbin
        model = casbin.Model()
        model.load_model_from_text(model_text)
        self.engine = casbin.Enforcer(model)
        self.counts = {}

    def invoke(self, method, arguments):
        if method not in {"add_policy", "add_grouping_policy", "add_named_grouping_policy", "enforce"}:
            raise AdmissionError("snapshot native operation is unbound")
        arity = {"add_policy": 4, "add_grouping_policy": 3, "add_named_grouping_policy": 3, "enforce": 4}[method]
        if len(arguments) != arity or any(not named(value) for value in arguments):
            raise AdmissionError("snapshot native call has wrong arity or fields")
        if method == "add_named_grouping_policy" and arguments[0] != "g2":
            raise AdmissionError("snapshot named grouping call requires g2")
        self.counts[method] = self.counts.get(method, 0) + 1
        try:
            result = getattr(self.engine, method)(*arguments)
        except Exception as error:
            raise AdmissionError("native snapshot call failed: " + type(error).__name__, "native_error") from error
        if method == "enforce" and type(result) is not bool:
            raise AdmissionError("native snapshot decision is not Boolean", "native_error")
        return result

    def rows(self):
        return ([["p", *row] for row in self.engine.get_policy()]
                + [["g", *row] for row in self.engine.get_named_grouping_policy("g")]
                + [["g2", *row] for row in self.engine.get_named_grouping_policy("g2")])


def reachable(rows, start, kind, domain=None):
    waiting, result = [start], set()
    while waiting:
        current = waiting.pop()
        if current not in result:
            result.add(current)
            waiting.extend(row[2] for row in rows if row[0] == kind and row[1] == current and (kind != "g" or row[3] == domain))
    return result


def reference_decision(rules, owners, request, method):
    """Independent relation/graph contract, not obtained from native outputs."""
    rows = reference_rows(rules)
    principal = str(request["user_id"])
    if ["g2", principal, "system_admin"] in rows:
        return True
    if method == "check_permission":
        if any(row == {key: request[key] for key in ("user_id", "resource_type", "resource_id")} for row in owners):
            return True
        domain, resource = f'{request["resource_type"]}_{request["resource_id"]}', request["resource_type"]
    else:
        domain, resource = request["domain"], request["resource"]
    if "system_admin" in reachable(rows, principal, "g2"):
        return True
    roles = reachable(rows, principal, "g", domain)
    return any(row[0] == "p" and row[1] in roles and row[2:] == [domain, resource, request["action"]] for row in rows)


def compare_snapshot(source, model_text, rules, owners, requests, method="check_permission", ready=True,
                     *, class_name="PermissionService", model_import_module="app.models.permission"):
    validate_snapshot(rules, owners)
    if method not in ("check_permission", "enforce") or type(requests) is not list or not 1 <= len(requests) <= 4096:
        raise AdmissionError("snapshot method or finite request envelope is invalid", "input_rejected")
    fields = {"user_id", "resource_type", "resource_id", "action"} if method == "check_permission" else {"user_id", "domain", "resource", "action"}
    for request in requests:
        if (type(request) is not dict or set(request) != fields or type(request["user_id"]) is not int
                or not 0 <= request["user_id"] <= 1_000_000 or not all(named(value) for key, value in request.items() if key not in ("user_id", "resource_id"))
                or method == "check_permission" and (type(request["resource_id"]) is not int or not 0 <= request["resource_id"] <= 1_000_000)):
            raise AdmissionError("snapshot request has invalid typed fields", "input_rejected")
    original = deepcopy((rules, owners))
    program = extract_snapshot_program(source, class_name, model_import_module)
    native = NativeSnapshot(model_text)
    interpreter = SnapshotInterpreter(program, rules, owners, native, ready=ready)
    interpreter.run("_load_policy_from_db", [])
    expected, actual = reference_rows(rules), native.rows()
    cells = []
    for request in requests:
        args = ([request[key] for key in ("user_id", "resource_type", "resource_id", "action")] if method == "check_permission"
                else [request[key] for key in ("user_id", "domain", "resource", "action")])
        before = interpreter.native_calls
        outcome = interpreter.run(method, args)
        if type(outcome) is not bool:
            raise AdmissionError("snapshot consumer did not return a Boolean decision")
        cells.append({"request": request, "allow": outcome, "reference_allow": reference_decision(rules, owners, request, method),
                      "native_calls": interpreter.native_calls - before})
    # Reuse the original checker on a finite table, not merely a list equality.
    # request_N encodes a given complete input record; it is not a discovered
    # general resource abstraction or a second independent application sample.
    comparisons = []
    # The unchanged core allows at most 32 resources. Partition the finite,
    # stateless observation domain, not the supplied snapshot or a state trace.
    # All chunks must pass. No core limit is raised or silently bypassed.
    for start in range(0, len(cells), 32):
        chunk = cells[start:start + 32]
        resources = ["request_" + str(index) for index in range(start, start + len(chunk))]
        policy = {"principals": ["given_principal"], "resources": resources, "actions": ["given_action"],
                  "roles": [], "members": [], "state": [], "aliases": [], "rules": []}
        for resource, cell in zip(resources, chunk):
            if cell["reference_allow"]:
                policy["rules"].append({"decision": "allow", "guard": [{"field": "resource", "name": resource, "negated": False}], "updates": []})
        policy = normalize(policy)
        indexed = dict(zip(resources, chunk))
        machine = {"state_names": [], "alphabet": [["given_principal", resource, "given_action"] for resource in policy["resources"]],
                   "observations": [0], "initial": 0,
                   "transitions": [[["allow" if indexed[resource]["allow"] else "deny", 0] for resource in policy["resources"]]]}
        comparisons.append({"first_request_index": start, "request_count": len(chunk), "comparison": verify_reachable(policy, machine)})
    comparison = next((part["comparison"] for part in comparisons if not part["comparison"]["accepted"]),
                      {"accepted": True, "scope": "union of all finite immutable-snapshot observation chunks", "chunks": len(comparisons)})
    if (rules, owners) != original or native.rows() != actual:
        raise AdmissionError("consumer mutated the supplied snapshot or policy; immutable interface no longer sufficient")
    accepted = expected == actual and comparison["accepted"]
    return {"status": "equivalent" if accepted else "mismatch", "accepted": accepted, "producer_rows_agree": expected == actual,
            "expected_rows": expected, "observed_rows": actual, "cells": cells, "comparison": comparison, "all_core_comparisons": comparisons,
            "source_descriptor": program_descriptor(program), "native_runtime": native.identity,
            "counts": {"consumer_cells": len(cells), "native_operations": native.counts, "owned_query_operations": interpreter.query_counts},
            "scope": "selected row loader and ready consumers on supplied immutable policy/owner snapshots; native Casbin only",
            "initialization_admin_sync_transactions_or_orm_verified": False, "whole_application_verified": False}
