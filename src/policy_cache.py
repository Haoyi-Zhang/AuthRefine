"""A bounded producer/store/native-consumer interface with explicit reloads.

The producer is an owned set-store adapter, not a replacement certification of
any application's database. Only the consumer and its reload are native Casbin
operations. The exported observations keep store and consumer rows separate.
"""
from __future__ import annotations

from itertools import product

from checker import verify_reachable
from language import normalize
from native_casbin import AdmissionError, _engine, admit_configuration
from native_state_export import observe_store, policy_store_specification


def _text(rows):
    return "\n".join(", ".join(row) for row in rows) or "# empty policy"


class PolicySnapshot:
    """Owned persistence boundary; changes do not silently update the consumer."""
    def __init__(self, model_text, rows):
        self.model_text = model_text
        config = admit_configuration(model_text, _text(rows))
        if config.family not in ("basic", "rbac", "rbac_with_resource_roles"):
            raise AdmissionError("snapshot replay admits exact allow-only schemas")
        if len(config.rows) != len({tuple(row) for row in config.rows}):
            raise AdmissionError("snapshot set contract rejects duplicate initial rows", "invalid")
        if config.rows != [list(row) for row in rows]:
            raise AdmissionError("literal stored rows change during native text parsing", "unsupported")
        self.rows = [list(row) for row in config.rows]
        self.engine = _engine(config)
        self.native_enforce_calls = 0
        self.native_reload_calls = 0

    def update(self, operation, section, kind, fields):
        if operation not in ("add_policy", "remove_policy"):
            raise AdmissionError("unrecognized snapshot producer operation")
        if section not in ("p", "g") or not isinstance(kind, str) or not kind.startswith(section):
            raise AdmissionError("policy section and type disagree", "invalid")
        if not isinstance(fields, (tuple, list)) or any(not isinstance(value, str) for value in fields):
            raise AdmissionError("producer fields must be literal strings", "invalid")
        row = [kind, *fields]
        candidate = admit_configuration(self.model_text, _text([row]))
        if candidate.rows != [row]:
            raise AdmissionError("producer row changes during native parsing", "invalid")
        present = row in self.rows
        if operation == "add_policy" and not present:
            self.rows.append(row)
            return True
        if operation == "remove_policy" and present:
            self.rows.remove(row)
            return True
        return False

    def reload(self):
        # StringAdapter's stored input is changed, then the *actual* native
        # load_policy path must rebuild its own row tables and role links.
        self.engine.get_adapter().line = _text(self.rows)
        self.engine.load_policy()
        self.native_reload_calls += 1
        for section in ("p", "g"):
            for kind, assertion in self.engine.model.model.get(section, {}).items():
                if assertion.policy != [row[1:] for row in self.rows if row[0] == kind]:
                    raise AdmissionError("native reload disagrees with supplied snapshot", "invalid")

    def enforce(self, request):
        if not isinstance(request, (tuple, list)) or len(request) != 3 or any(not isinstance(v, str) for v in request):
            raise AdmissionError("snapshot consumer requires three strings", "invalid")
        decision = self.engine.enforce(*request)
        if type(decision) is not bool:
            raise AdmissionError("native snapshot decision is not Boolean", "native_error")
        self.native_enforce_calls += 1
        return decision


def _field(kind, name):
    return {"field": kind, "name": name, "negated": False}


def cache_specification(rows, initial_store=0, initial_cache=0):
    policy_store_specification(rows, initial_store)  # exact-name validation
    if len(rows) > 3:
        raise AdmissionError("two observed row sets exceed the declared state envelope", "inconclusive")
    if type(initial_cache) is not int or not 0 <= initial_cache < 2 ** len(rows):
        raise AdmissionError("invalid consumer initial snapshot", "invalid")
    bits = []
    for kind, initial in (("cache", initial_cache), ("store", initial_store)):
        bits.extend([[f"{kind}_{i}", bool(initial & (1 << i))] for i in range(len(rows))])
    policy = {"principals": ["api"], "resources": [f"permission_{i}" for i in range(len(rows))],
              "actions": ["add", "authorize", "refresh", "remove"], "roles": [], "members": [],
              "state": bits, "aliases": [], "rules": []}
    for i, label in enumerate(policy["resources"]):
        for action in ("add", "remove", "authorize"):
            state = f"cache_{i}" if action == "authorize" else f"store_{i}"
            guard = [_field("resource", label), _field("action", action),
                     {"field": "state", "name": state, "value": action != "add"}]
            updates = [] if action == "authorize" else [{"name": state, "value": action == "add"}]
            policy["rules"].append({"decision": "allow", "guard": guard, "updates": updates})
    policy["rules"].append({"decision": "allow", "guard": [_field("action", "refresh")],
                            "updates": [{"name": f"cache_{i}", "from": f"store_{i}", "negated": False}
                                        for i in range(len(rows))]})
    return normalize(policy)


def export_policy_cache(model_text, rows, initial_store=0, initial_cache=0):
    policy = cache_specification(rows, initial_store, initial_cache)
    count = len(rows)
    alphabet = [list(request) for request in product(policy["principals"], policy["resources"], policy["actions"])]
    table, enforces, reloads, producer_operations = [], 0, 0, 0
    for observation in range(2 ** (2 * count)):
        cache_mask = observation & ((1 << count) - 1)
        store_mask = observation >> count
        transitions = []
        for _, label, action in alphabet:
            snapshot = PolicySnapshot(model_text, [["p", *row] for i, row in enumerate(rows) if cache_mask & (1 << i)])
            snapshot.rows = [["p", *row] for i, row in enumerate(rows) if store_mask & (1 << i)]
            if observe_store(snapshot.engine, rows) != cache_mask:
                raise AdmissionError("native initial consumer observation differs", "invalid")
            row = rows[int(label.removeprefix("permission_"))]
            if action in ("add", "remove"):
                result = snapshot.update(action + "_policy", "p", "p", row)
                producer_operations += 1
            elif action == "refresh":
                snapshot.reload()
                result = True  # command completion, not an authorization grant
            else:
                result = snapshot.enforce(row)
            post_store = sum(1 << i for i, r in enumerate(rows) if ["p", *r] in snapshot.rows)
            post_cache = observe_store(snapshot.engine, rows)
            transitions.append(["allow" if result else "deny", post_cache | (post_store << count)])
            enforces += snapshot.native_enforce_calls
            reloads += snapshot.native_reload_calls
        table.append(transitions)
    machine = {"state_names": [name for name, _ in policy["state"]], "alphabet": alphabet,
               "observations": list(range(2 ** (2 * count))),
               "initial": initial_cache | (initial_store << count), "transitions": table}
    comparison = verify_reachable(policy, machine)
    return {"status": comparison["status"], "accepted": comparison["accepted"],
            "scope": "owned sequential persistence, explicit native reload and native exact-equality consumer",
            "application_database_or_cache_verified": False, "native_enforce_calls": enforces,
            "native_reload_calls": reloads, "owned_producer_operations": producer_operations,
            "policy": policy, "machine": machine, "comparison": comparison}
