"""Observe a bounded native policy store and its authorization consumer.

Only sequential in-memory exact-equality policies are admitted. Add/remove/has
return values are API results, not a decision that an administrator is entitled
to modify the store. The authorize command calls the actual native enforcer.
"""
from __future__ import annotations

from itertools import product

from checker import verify_reachable
from language import named, normalize
from native_casbin import AdmissionError, _engine, admit_configuration


def _field(kind: str, name: str) -> dict:
    return {"field": kind, "name": name, "negated": False}


def policy_store_specification(rows: list[list[str]], initial: int = 0) -> dict:
    """Build the specified set-API laws, independently of native observations."""
    if not isinstance(rows, list) or not 1 <= len(rows) <= 7:
        raise AdmissionError("store requires one through seven exact request rows")
    if any(not isinstance(row, list) or len(row) != 3 or
           any(not named(value) or any(c in value for c in ',\"[]()') for value in row) for row in rows):
        raise AdmissionError("store rows must contain three plain native names", "invalid")
    if len({tuple(row) for row in rows}) != len(rows):
        raise AdmissionError("store requires one through seven distinct exact request rows")
    if any(len(row) != 3 for row in rows) or type(initial) is not int or not 0 <= initial < 2 ** len(rows):
        raise AdmissionError("invalid exact-row store interface", "invalid")
    labels = [f"permission_{index}" for index in range(len(rows))]
    policy = {"principals": ["api"], "resources": labels,
              "actions": ["add", "authorize", "has", "remove"], "roles": [], "members": [],
              "state": [[label, bool(initial & (1 << index))] for index, label in enumerate(labels)],
              "aliases": [], "rules": []}
    for label in labels:
        for action in policy["actions"]:
            present = action != "add"
            updates = [{"name": label, "value": action == "add"}] if action in ("add", "remove") else []
            policy["rules"].append({"decision": "allow", "guard": [
                _field("resource", label), _field("action", action),
                {"field": "state", "name": label, "value": present}], "updates": updates})
    return normalize(policy)


def _native_store(model_text: str, universe: list[list[str]], mask: int):
    text = "\n".join("p, " + ", ".join(row) for index, row in enumerate(universe) if mask & (1 << index))
    configuration = admit_configuration(model_text, text)
    if configuration.family != "basic":
        raise AdmissionError("state export currently admits exact equality without roles or custom functions")
    return _engine(configuration)


def observe_store(engine, universe: list[list[str]]) -> int:
    actual = [tuple(row) for row in engine.get_policy()]
    if len(actual) != len(set(actual)):
        raise AdmissionError("native store has duplicate rows outside set-API contract")
    positions = {tuple(row): index for index, row in enumerate(universe)}
    if any(row not in positions for row in actual):
        raise AdmissionError("native store contains an unobserved policy row")
    return sum(1 << positions[row] for row in actual)


def export_policy_store(model_text: str, universe: list[list[str]], initial: int = 0) -> dict:
    source = policy_store_specification(universe, initial)
    # Admission also validates every supplied exact row when the initial store
    # is empty; otherwise an invalid row might reach a later add operation.
    whole = admit_configuration(model_text, "\n".join("p, " + ", ".join(row) for row in universe))
    if whole.family != "basic":
        raise AdmissionError("only the basic exact-equality store has a supplied state correspondence")
    alphabet = [list(request) for request in product(source["principals"], source["resources"], source["actions"])]
    table = []
    initial_observations, operations = 0, 0
    for mask in range(2 ** len(universe)):
        transitions = []
        for _, label, action in alphabet:
            # Each cell starts from the specified concrete store; a previous
            # cell's update cannot contaminate this one.
            engine = _native_store(model_text, universe, mask)
            observed = observe_store(engine, universe)
            if observed != mask:
                raise AdmissionError("native initial store does not match the complete observation", "invalid")
            initial_observations += 1
            row = universe[int(label.removeprefix("permission_"))]
            if action == "add":
                result = engine.add_policy(*row)
            elif action == "remove":
                result = engine.remove_policy(*row)
            elif action == "has":
                result = engine.has_policy(*row)
            else:
                result = engine.enforce(*row)
            if type(result) is not bool:
                raise AdmissionError("native API result is not Boolean", "invalid")
            post = observe_store(engine, universe)
            transitions.append(["allow" if result else "deny", post])
            operations += 1
        table.append(transitions)
    machine = {"state_names": [name for name, _ in source["state"]], "alphabet": alphabet,
               "observations": list(range(2 ** len(universe))), "initial": initial, "transitions": table}
    comparison = verify_reachable(source, machine)
    return {"status": comparison["status"], "accepted": comparison["accepted"],
            "scope": "sequential native set APIs and exact-equality consumer; complete bounded row universe",
            "application_project": False, "real_service_or_new_vulnerability": False,
            "rows": universe, "native_operations": operations,
            "native_initial_observations": initial_observations,
            "policy": source, "machine": machine, "comparison": comparison}
