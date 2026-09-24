"""Deterministic finite cross-checks for the executable derived constructions."""
from __future__ import annotations

import argparse
import copy
import itertools
import json
import resource
import time
from collections import Counter, deque
from pathlib import Path

from cases import blank, generated
from checker import Rejected, reference_step
from compiler import alphabet, compile_policy
from extensions import (
    binding_profile,
    normalize_family,
    observable_quotient,
    observation_cone,
    project_policy,
    project_state,
    switching_oracle,
    target_paths,
    verify_family,
)
from language import normalize
from oracle import all_bindings, product_oracle


def singleton_policy(policy, binding):
    fixed = copy.deepcopy(policy)
    for alias in fixed["aliases"]:
        alias["candidates"] = [binding[alias["name"]]]
    return normalize(fixed)


def profile_family():
    records = []
    obligations = 0
    binding_cases = 0
    for index in range(128):
        policy = generated(index)
        machine = compile_policy(policy)
        report = binding_profile(policy, machine)
        direct_lengths = []
        for row in report["profiles"]:
            direct = product_oracle(singleton_policy(policy, row["binding"]), machine)
            binding_cases += 1
            obligations += direct["transition_evaluations"]
            if direct["equivalent"] != row["equivalent"]:
                raise RuntimeError("binding profile verdict disagrees with singleton product")
            direct_length = None if direct["equivalent"] else direct["shortest"]["length"]
            if direct_length != row["length"]:
                raise RuntimeError("binding profile length disagrees with singleton product")
            direct_lengths.append(direct_length)
        obligations += report["transition_evaluations"]
        records.append({
            "generator_index": index,
            "classification": report["classification"],
            "bindings": report["bindings"],
            "matching": report["matching_bindings"],
            "lengths": direct_lengths,
        })
    return {
        "count": len(records),
        "binding_cases": binding_cases,
        "classifications": dict(Counter(row["classification"] for row in records)),
        "records": records,
        "obligations": obligations,
    }


def machine_signature(machine, state):
    return [(decision, machine["observations"][successor])
            for decision, successor in machine["transitions"][state]]


def independently_coherent(machine):
    paths = target_paths(machine)
    for left in paths:
        for right in paths:
            if machine["observations"][left] == machine["observations"][right]:
                if machine_signature(machine, left) != machine_signature(machine, right):
                    return False
    return True


def machine_trace_equivalent(left, right):
    if left["alphabet"] != right["alphabet"]:
        return False, 0
    initial = (left["initial"], right["initial"])
    if left["observations"][initial[0]] != right["observations"][initial[1]]:
        return False, 0
    seen = {initial}
    queue = deque([initial])
    evaluations = 0
    while queue:
        lstate, rstate = queue.popleft()
        for index in range(len(left["alphabet"])):
            evaluations += 1
            ld, ln = left["transitions"][lstate][index]
            rd, rn = right["transitions"][rstate][index]
            if ld != rd or left["observations"][ln] != right["observations"][rn]:
                return False, evaluations
            pair = (ln, rn)
            if pair not in seen:
                seen.add(pair)
                queue.append(pair)
    return True, evaluations


def quotient_family():
    interface = blank()
    interface["state"] = [["b", False]]
    interface = normalize(interface)
    edge_choices = list(itertools.product(("allow", "deny"), range(2)))
    records = []
    obligations = 0
    for observations in itertools.product(range(2), repeat=2):
        for edges in itertools.product(edge_choices, repeat=2):
            for initial in range(2):
                machine = {
                    "state_names": ["b"],
                    "alphabet": [["u", "o", "a"]],
                    "observations": list(observations),
                    "initial": initial,
                    "transitions": [[list(edge)] for edge in edges],
                }
                coherent = independently_coherent(machine)
                try:
                    result = observable_quotient(interface, machine)
                    constructed = True
                except Rejected as error:
                    if error.kind != "mismatch":
                        raise
                    constructed = False
                    result = None
                if constructed != coherent:
                    raise RuntimeError("observable quotient coherence disagreement")
                collapsed = None
                if constructed:
                    equivalent, checks = machine_trace_equivalent(machine, result["machine"])
                    obligations += checks
                    if not equivalent:
                        raise RuntimeError("observable quotient changes complete traces")
                    expected = len({machine["observations"][q] for q in target_paths(machine)})
                    if result["reachable_observations"] != expected:
                        raise RuntimeError("observable quotient state count disagreement")
                    collapsed = result["collapsed_states"]
                obligations += len(target_paths(machine)) ** 2
                records.append({
                    "observations": list(observations),
                    "edges": [list(edge) for edge in edges],
                    "initial": initial,
                    "coherent": coherent,
                    "collapsed": collapsed,
                })
    return {
        "count": len(records),
        "coherent": sum(row["coherent"] for row in records),
        "incoherent": sum(not row["coherent"] for row in records),
        "collapsed": sum((row["collapsed"] or 0) > 0 for row in records),
        "records": records,
        "obligations": obligations,
    }


def projection_fixture(index):
    policy = copy.deepcopy(generated(index))
    policy["state"].extend([["audit", bool(index & 1)], ["carry", bool(index & 2)]])
    for rule_index, rule in enumerate(policy["rules"]):
        if rule["decision"] == "allow":
            rule["updates"].append({"name": "audit", "from": "audit", "negated": True})
            if rule_index % 2:
                rule["updates"].append({"name": "carry", "from": "audit", "negated": bool(index & 4)})
            else:
                rule["updates"].append({"name": "carry", "value": bool((index + rule_index) & 1)})
    return normalize(policy)


def projection_family():
    records = []
    obligations = 0
    step_cases = 0
    for index in range(64):
        policy = projection_fixture(index)
        for required in ([], ["audit"], ["carry"]):
            result = project_policy(policy, required)
            reduced = result["policy"]
            retained = result["cone"]["retained"]
            if observation_cone(policy, required) != result["cone"]:
                raise RuntimeError("projection cone is not deterministic")
            bindings = list(all_bindings(policy))
            requests = alphabet(policy)
            for state in range(1 << len(policy["state"])):
                small_state = project_state(policy, retained, state)
                for request in requests:
                    for binding in bindings:
                        full = reference_step(policy, state, request, binding)
                        small = reference_step(reduced, small_state, request, binding)
                        expected = (full[0], project_state(policy, retained, full[1]))
                        if small != expected:
                            raise RuntimeError("one-step projection disagreement")
                        step_cases += 1
                        obligations += 2
            records.append({
                "generator_index": index,
                "required": required,
                "full_bits": len(policy["state"]),
                "retained": retained,
                "discarded": result["cone"]["discarded"],
            })
    return {
        "count": len(records),
        "step_cases": step_cases,
        "with_discarded_state": sum(bool(row["discarded"]) for row in records),
        "records": records,
        "obligations": obligations,
    }


def correlated_fixture():
    policy = blank()
    policy["roles"] = ["r", "t"]
    policy["members"] = [["u", "r"]]
    policy["aliases"] = [
        {"name": "z1", "kind": "role", "candidates": ["r", "t"]},
        {"name": "z2", "kind": "role", "candidates": ["r", "t"]},
    ]
    policy["rules"] = [
        {"decision": "allow", "guard": [
            {"field": "role", "alias": "z1", "negated": False},
            {"field": "role", "alias": "z2", "negated": False}], "updates": []},
        {"decision": "allow", "guard": [
            {"field": "role", "alias": "z1", "negated": True},
            {"field": "role", "alias": "z2", "negated": True}], "updates": []},
    ]
    machine = {
        "state_names": [],
        "alphabet": [["u", "o", "a"]],
        "observations": [0],
        "initial": 0,
        "transitions": [[['allow', 0]]],
    }
    return normalize(policy), machine


def restricted_family():
    policy, machine = correlated_fixture()
    bindings = list(all_bindings(policy))
    records = []
    obligations = 0
    for mask in range(1, 1 << len(bindings)):
        family = [binding for index, binding in enumerate(bindings) if (mask >> index) & 1]
        direct = [product_oracle(singleton_policy(policy, binding), machine) for binding in family]
        expected = all(result["equivalent"] for result in direct)
        obligations += sum(result["transition_evaluations"] for result in direct)
        try:
            result = verify_family(policy, machine, {"reachable": [0]}, family)
            accepted = True
            obligations += result["binding_evaluations"]
        except Rejected as error:
            if error.kind != "mismatch":
                raise
            accepted = False
            obligations += error.evaluations
            if error.binding not in normalize_family(policy, family):
                raise RuntimeError("restricted-family witness is not admitted")
        if accepted != expected:
            raise RuntimeError("restricted-family checker disagrees with singleton products")
        records.append({"mask": mask, "size": len(family), "accepted": accepted})
    return {
        "count": len(records),
        "accepted": sum(row["accepted"] for row in records),
        "rejected": sum(not row["accepted"] for row in records),
        "records": records,
        "obligations": obligations,
    }


def decision_switching_fixture():
    policy = blank()
    policy["roles"] = ["r", "s"]
    policy["members"] = [["u", "r"]]
    policy["state"] = [["b", False]]
    policy["aliases"] = [{"name": "z", "kind": "role", "candidates": ["r", "s"]}]
    policy["rules"] = [
        {"decision": "allow", "guard": [{"field": "role", "alias": "z", "negated": False}],
         "updates": [{"name": "b", "value": True}]},
        {"decision": "allow", "guard": [
            {"field": "role", "alias": "z", "negated": True},
            {"field": "state", "name": "b", "value": False}], "updates": []},
    ]
    machine = {
        "state_names": ["b"],
        "alphabet": [["u", "o", "a"]],
        "observations": [0],
        "initial": 0,
        "transitions": [[['allow', 0]]],
    }
    return normalize(policy), machine


def switching_family():
    records = []
    obligations = 0
    for index in range(128):
        policy = generated(index)
        machine = compile_policy(policy)
        fixed = product_oracle(policy, machine)
        switched = switching_oracle(policy, machine)
        obligations += fixed["transition_evaluations"] + switched["transition_evaluations"]
        if fixed["equivalent"] != switched["equivalent"]:
            raise RuntimeError("full-state switching disagrees with fixed-binding uniformity")
        records.append({
            "generator_index": index,
            "uniform": fixed["equivalent"],
            "switching_equivalent": switched["equivalent"],
            "length": switched["length"],
        })
    policy, machine = decision_switching_fixture()
    fixed_decisions = product_oracle(policy, machine, decisions_only=True)
    switched_decisions = switching_oracle(policy, machine, decisions_only=True)
    obligations += fixed_decisions["transition_evaluations"] + switched_decisions["transition_evaluations"]
    if not fixed_decisions["equivalent"] or switched_decisions["equivalent"] or switched_decisions["length"] != 2:
        raise RuntimeError("decision-only switching separation disagreement")
    records.append({
        "generator_index": None,
        "uniform": True,
        "switching_equivalent": False,
        "length": 2,
        "decisions_only": True,
    })
    return {
        "count": len(records),
        "full_state_cases": len(records) - 1,
        "full_state_uniform": sum(row["uniform"] for row in records[:-1]),
        "decision_only_separation": True,
        "records": records,
        "obligations": obligations,
    }


def run(destination):
    begin = time.process_time()
    wall = time.perf_counter()
    report = {
        "profiles": profile_family(),
        "quotients": quotient_family(),
        "projections": projection_family(),
        "restricted_families": restricted_family(),
        "switching": switching_family(),
    }
    names = tuple(report)
    report["count"] = sum(report[name]["count"] for name in names)
    report["obligations"] = sum(report[name]["obligations"] for name in names)
    report["cpu_seconds"] = time.process_time() - begin
    report["wall_seconds"] = time.perf_counter() - wall
    report["peak_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key not in names}, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    run(parser.parse_args().output)
