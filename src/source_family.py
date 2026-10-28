"""Connect admitted source/native observations to AuthRefine's binding profiles.

Candidate references are explicit fixed review hypotheses, not inferred user
intent. Every candidate is retained, with a replay under one fixed binding.
The same-information target-distance, product and diagram analyses must agree.
"""
from copy import deepcopy
import itertools
import json

from checker import Rejected, inspect_machine, inspect_policy
from extensions import binding_profile, normalize_family, _reference_replay
from language import normalize, named
from native_casbin import AdmissionError, admit_configuration
from oracle import product_oracle
from public_inputs import translate
from symbolic_profile import profile as diagram_profile
from token_roles import compare_claim_boundary


def _signature(report):
    return [(row["binding"], row["equivalent"], row["length"]) for row in report["profiles"]]


def diagnose_source_family(policy, machine, *, family_limit=128, work_budget=2_000_000):
    if (type(family_limit) is not int or not 1 <= family_limit <= 128
            or type(work_budget) is not int or not 1 <= work_budget <= 2_000_000):
        raise AdmissionError("source-family comparison budget is outside its declared envelope", "inconclusive")
    inspect_policy(policy)
    inspect_machine(policy, machine, compare_initial=False)
    # Bound outer graph/cell work as well as each existing algorithm's own cap.
    family = normalize_family(policy, budget=work_budget, family_limit=family_limit)
    if (len(machine["observations"]) > 256 or len(machine["alphabet"]) > 4096
            or len(family) * len(machine["observations"]) * len(machine["alphabet"]) > work_budget):
        raise AdmissionError("source-family graph/family work envelope exceeded", "inconclusive")
    local = binding_profile(policy, machine, budget=work_budget, family_limit=family_limit)
    product_rows, evaluations, replay_steps = [], 0, 0
    for binding in family:
        fixed = deepcopy(policy)
        for alias in fixed["aliases"]:
            alias["candidates"] = [binding[alias["name"]]]
        fixed = normalize(fixed)
        result = product_oracle(fixed, machine, budget=work_budget - evaluations - replay_steps)
        evaluations += result["transition_evaluations"]
        indices = None if result["equivalent"] else result["shortest"]["indices"]
        if indices is not None:
            replay_steps += len(indices)
            if evaluations + replay_steps > work_budget:
                raise AdmissionError("product witness replay exceeds shared work envelope", "inconclusive")
        trace = None if indices is None else _reference_replay(policy, machine, indices, [binding] * len(indices))
        if trace and (any(not row["compared_equal"] for row in trace[:-1]) or trace[-1]["compared_equal"]):
            raise AdmissionError("fixed-binding product replay is inconsistent", "invalid")
        product_rows.append({"binding": binding, "equivalent": result["equivalent"],
            "length": None if indices is None else len(indices), "indices": indices, "trace": trace})
    product = {"profiles": product_rows, "transition_evaluations": evaluations, "replay_steps": replay_steps,
               "semantic_step_budget": work_budget}
    diagram = diagram_profile(policy, machine, family_limit=family_limit, operation_limit=work_budget)
    if _signature(local) != _signature(product) or _signature(local) != _signature(diagram):
        raise AdmissionError("same-information fixed-family algorithms disagree", "invalid")
    return {"status": "diagnosed", "accepted": None, "classification": local["classification"],
            "all_candidate_bindings_agree": local["classification"] == "all", "bindings": len(family),
            "matching_bindings": local["matching_bindings"], "strata": local["strata"],
            "matching_interpretations": [row["binding"] for row in local["profiles"] if row["equivalent"]],
            "profiles": local["profiles"], "algorithms_agree": True,
            "algorithms": {"target_distance": local, "complete_product": product, "decision_diagram": diagram},
            "scope": "all supplied fixed interpretation hypotheses on the stated complete observation interface",
            "reference_intent_or_whole_application_verified": False}


def _direct_role_name(role):
    # A tagged injective name separates direct membership from policy hierarchy.
    return json.dumps(["direct-role", role], separators=(",", ":"), ensure_ascii=False)


def claim_reference_family(user_source, enum_source, model_text, policy_text, records,
                           actual_admin_role, candidates, admin_bypass=True):
    if (not isinstance(records, list) or not 1 <= len(records) <= 8 or not isinstance(candidates, list)
            or not 1 <= len(candidates) <= 8 or any(not named(value) for value in candidates)
            or len(set(candidates)) != len(candidates) or type(admin_bypass) is not bool):
        raise AdmissionError("claim family needs bounded explicit inputs and distinct review candidates", "invalid")
    config = admit_configuration(model_text, policy_text)
    if config.family != "rbac_with_deny":
        raise AdmissionError("claim family requires the admitted deny-overrides schema")
    observations = [compare_claim_boundary(user_source, enum_source, model_text, policy_text, record,
        actual_admin_role, admin_bypass, include_models=True) for record in records]
    principals = [row["preferred_username"] for row in records]
    if len(set(principals)) != len(principals):
        raise AdmissionError("one claim instance is required per distinct finite principal", "invalid")
    policy = translate(config.family, config.rows)
    policy["principals"] = principals
    policy["members"] = []
    direct_tags = {candidate: _direct_role_name(candidate) for candidate in candidates}
    if set(direct_tags.values()) & set(policy["roles"]):
        raise AdmissionError("direct-role observation namespace collides with the policy schema")
    policy["roles"].extend(direct_tags.values())
    policy["aliases"] = [{"name": "configured-admin-role", "kind": "role", "candidates": list(direct_tags.values())}]
    if admin_bypass:
        policy["rules"].insert(0, {"decision": "allow", "guard": [{"field": "role", "alias": "configured-admin-role", "negated": False}], "updates": []})
    cells = {}
    for principal, observed in zip(principals, observations):
        if (observed["policy"]["resources"] != policy["resources"] or observed["policy"]["actions"] != policy["actions"]):
            raise AdmissionError("claim records do not share a common declared request domain")
        # Per-instance membership comes from the independently converted record;
        # never merge engines' graphs and accidentally add cross-instance paths.
        policy["members"].extend(edge for edge in observed["policy"]["members"] if edge[0] == principal)
        direct = set(observed["reference_roles"]) | {row[2] for row in config.rows if row[0] == "g" and row[1] == principal}
        policy["members"].extend([principal, tag] for candidate, tag in direct_tags.items() if candidate in direct)
        for request, edge in zip(observed["machine"]["alphabet"], observed["machine"]["transitions"][0]):
            cells[tuple(request)] = list(edge)
    policy = normalize(policy)
    alphabet = [list(request) for request in itertools.product(policy["principals"], policy["resources"], policy["actions"])]
    if len(cells) != len(alphabet) or any(tuple(request) not in cells for request in alphabet):
        raise AdmissionError("native observations leave part of the family alphabet unmeasured", "missing_input")
    machine = {"state_names": [], "alphabet": alphabet, "observations": [0], "initial": 0,
               "transitions": [[cells[tuple(request)] for request in alphabet]]}
    diagnosis = diagnose_source_family(policy, machine)
    return {**diagnosis, "policy": policy, "machine": machine,
            "reference_candidates": [{"source_setting_value": value, "role_observation": tag} for value, tag in direct_tags.items()],
            "candidate_origin": "explicit mapping-review hypotheses; not inferred ambiguity in the upstream specification",
            "native_source_descriptor": observations[0]["source_descriptor"],
            "native_enforce_calls": sum(row["native_enforce_calls"] for row in observations),
            "native_direct_admin_checks": sum(row["native_direct_admin_checks"] for row in observations),
            "native_request_cells": len(cells), "whole_application_verified": False}
