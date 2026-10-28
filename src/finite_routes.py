"""Ground two common middleware policy schemas on an explicit request domain.

Unlike equality-only outside-name abstraction, a supplied route/request list is
not claimed to represent all URLs or all production requests. The model is built
from a separate interpretation of the admitted source policy, not engine output.
"""
from __future__ import annotations

from checker import verify_reachable
from language import PolicyError, named, normalize
from native_casbin import AdmissionError, EXTRA_MATCHERS, MAX_NATIVE_WORK, _engine, admit_configuration
from public_inputs import closure


def path_matches(path: str, pattern: str) -> bool:
    if "*" not in pattern:
        return path == pattern
    return path.startswith(pattern.split("*", 1)[0])


def compare_finite_routes(model_text: str, policy_text: str, domain: dict[str, list[str]]) -> dict:
    configuration = admit_configuration(model_text, policy_text)
    if configuration.family not in EXTRA_MATCHERS:
        raise AdmissionError("use the equality-fragment adapter for this model")
    if not isinstance(domain, dict) or set(domain) != {"principals", "resources", "actions"}:
        raise AdmissionError("provide explicit principal/resource/action domains", "invalid")
    for key, values in domain.items():
        bound = 16 if key == "principals" else 32
        if not isinstance(values, list) or not values or any(not named(value) for value in values):
            raise AdmissionError("invalid finite " + key, "invalid")
        if len(set(values)) != len(values) or len(values) > bound:
            raise AdmissionError("duplicate or oversized finite " + key, "inconclusive")
    work = len(domain["principals"]) * len(domain["resources"]) * len(domain["actions"]) * max(1, len(configuration.rows))
    if work > MAX_NATIVE_WORK:
        raise AdmissionError("finite native comparison exceeds work envelope", "inconclusive")
    source_rows = [row[1:] for row in configuration.rows if row[0] == "p"]
    edges = [(row[1], row[2]) for row in configuration.rows if row[0] == "g"]
    roles = sorted({row[0] for row in source_rows if row[0] != "*"})
    memberships = [[user, role] for user in domain["principals"] for role in roles if role in closure(edges, user)]
    policy = {**domain, "roles": roles, "members": memberships, "state": [], "aliases": [], "rules": []}
    for subject, pattern, action in source_rows:
        if action != "*" and action not in domain["actions"]:
            continue
        for resource in domain["resources"]:
            matches = (resource == pattern if configuration.family == "rbac_wildcards" else path_matches(resource, pattern))
            if not matches:
                continue
            guard = [{"field": "resource", "name": resource, "negated": False}]
            if subject != "*":
                guard.append({"field": "role", "name": subject, "negated": False})
            if action != "*":
                guard.append({"field": "action", "name": action, "negated": False})
            policy["rules"].append({"decision": "allow", "guard": guard, "updates": []})
    try:
        policy = normalize(policy)
    except PolicyError as error:
        raise AdmissionError(str(error), "inconclusive" if error.category == "LIMIT" else "invalid") from error
    native = _engine(configuration)
    alphabet = [[u, o, a] for u in policy["principals"] for o in policy["resources"] for a in policy["actions"]]
    transitions = []
    for request in alphabet:
        try:
            result = native.enforce(*request)
        except Exception as error:
            raise AdmissionError("native finite-route evaluation failed: " + type(error).__name__, "native_error") from error
        if type(result) is not bool:
            raise AdmissionError("native route decision is not Boolean", "invalid")
        transitions.append(["allow" if result else "deny", 0])
    machine = {"state_names": [], "alphabet": alphabet, "observations": [0], "initial": 0,
               "transitions": [transitions]}
    comparison = verify_reachable(policy, machine)
    return {"status": comparison["status"], "accepted": comparison["accepted"],
            "family": configuration.family, "scope": "explicit finite request domain only",
            "unlisted_url_equivalence_claimed": False, "application_entry_points_verified": False,
            "domain": domain, "native_enforce_calls": len(alphabet),
            "policy": policy, "machine": machine, "comparison": comparison}
