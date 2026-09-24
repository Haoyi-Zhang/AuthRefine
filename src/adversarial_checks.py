"""Deterministic adversarial and metamorphic checks for repaired boundaries.

The generator is deliberately small enough for complete products.  It covers all
four alias sorts, exact length-zero diagnostics, target mutations, the executable
derived constructions, and resource-boundary controls without external inputs.
"""
from __future__ import annotations

import argparse
import copy
import json
import random
import resource
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any

import checker
import compiler
import language
from cases import blank
from extensions import (
    binding_profile,
    normalize_family,
    observable_quotient,
    project_policy,
    project_state,
    switching_oracle,
    verify_family,
)
from oracle import all_bindings, product_oracle


BASE_SEED = 20260915
FULL_CASES = 1024
PILOT_CASES = 64
CAMPAIGN_OPERATION_LIMIT = 900_000
PROFILE_CASES = 512
STEP_CASES = 512
PROJECTION_CASES = 512


class CounterBudget:
    def __init__(self, limit: int):
        self.limit = limit
        self.total = 0
        self.parts: Counter[str] = Counter()

    def add(self, amount: int, part: str) -> None:
        if type(amount) is not int or amount < 0:
            raise RuntimeError("invalid adversarial operation charge")
        if self.total + amount > self.limit:
            raise RuntimeError("adversarial campaign operation ceiling exceeded")
        self.total += amount
        self.parts[part] += amount


def case_random(index: int) -> random.Random:
    return random.Random(BASE_SEED + 1_000_003 * index)


def make_policy(index: int) -> dict[str, Any]:
    rng = case_random(index)
    policy: dict[str, Any] = {
        "principals": ["u0", "u1"],
        "resources": ["o0", "o1"],
        "actions": ["a0", "a1"],
        "roles": ["r0", "r1"],
        "members": [],
        "state": [],
        "aliases": [],
        "rules": [],
    }
    policy["members"] = [
        [principal, role]
        for principal in policy["principals"]
        for role in policy["roles"]
        if rng.randrange(2)
    ]
    state_count = rng.randrange(3)
    # Observation and initial-state mutations need at least two observations.
    if index % 5 in (3, 4):
        state_count = max(1, state_count)
    policy["state"] = [[f"b{bit}", bool(rng.randrange(2))] for bit in range(state_count)]

    alias_count = index % 4
    kinds = ["principal", "resource", "action", "role"]
    start_kind = (index // 4) % len(kinds)
    for alias_index in range(alias_count):
        kind = kinds[(start_kind + alias_index) % len(kinds)]
        candidates = list(policy[language.DOMAINS[kind]])
        if rng.randrange(4) == 0:
            candidates = [candidates[rng.randrange(len(candidates))]]
        policy["aliases"].append({
            "name": f"z{alias_index}",
            "kind": kind,
            "candidates": candidates,
        })

    rule_count = rng.randrange(6)
    if policy["aliases"]:
        rule_count = max(1, rule_count)
    for rule_index in range(rule_count):
        decision = "allow" if rng.randrange(4) else "deny"
        guard: list[dict[str, Any]] = []
        if rule_index == 0 and policy["aliases"]:
            alias = policy["aliases"][0]
            guard.append({
                "field": alias["kind"],
                "alias": alias["name"],
                "negated": bool(rng.randrange(2)),
            })
        remaining = rng.randrange(max(1, 5 - len(guard)))
        for _ in range(remaining):
            fields = ["principal", "resource", "action", "role"]
            if policy["state"]:
                fields.append("state")
            field = rng.choice(fields)
            if field == "state":
                guard.append({
                    "field": "state",
                    "name": rng.choice(policy["state"])[0],
                    "value": bool(rng.randrange(2)),
                })
                continue
            compatible = [alias for alias in policy["aliases"] if alias["kind"] == field]
            if compatible and rng.randrange(2):
                guard.append({
                    "field": field,
                    "alias": rng.choice(compatible)["name"],
                    "negated": bool(rng.randrange(2)),
                })
            else:
                guard.append({
                    "field": field,
                    "name": rng.choice(policy[language.DOMAINS[field]]),
                    "negated": bool(rng.randrange(2)),
                })
        updates: list[dict[str, Any]] = []
        if decision == "allow" and policy["state"]:
            destinations = rng.sample(
                [entry[0] for entry in policy["state"]], rng.randrange(len(policy["state"]) + 1)
            )
            for destination in destinations:
                if rng.randrange(2):
                    updates.append({"name": destination, "value": bool(rng.randrange(2))})
                else:
                    updates.append({
                        "name": destination,
                        "from": rng.choice(policy["state"])[0],
                        "negated": bool(rng.randrange(2)),
                    })
        policy["rules"].append({"decision": decision, "guard": guard, "updates": updates})
    return language.normalize(policy)


def flip_decision(machine: dict[str, Any], rng: random.Random) -> str:
    state = rng.randrange(len(machine["transitions"]))
    request = rng.randrange(len(machine["alphabet"]))
    edge = machine["transitions"][state][request]
    edge[0] = "deny" if edge[0] == "allow" else "allow"
    return "decision"


def mutate_machine(policy: dict[str, Any], machine: dict[str, Any], index: int) -> tuple[dict[str, Any], str]:
    candidate = copy.deepcopy(machine)
    rng = random.Random(BASE_SEED ^ (index * 2_000_033 + 17))
    mode = index % 5
    if mode == 0:
        return candidate, "none"
    if mode == 1:
        return candidate, flip_decision(candidate, rng)
    if mode == 2:
        if len(candidate["transitions"]) == 1:
            return candidate, flip_decision(candidate, rng) + "-fallback"
        state = rng.randrange(len(candidate["transitions"]))
        request = rng.randrange(len(candidate["alphabet"]))
        old = candidate["transitions"][state][request][1]
        choices = [q for q in range(len(candidate["transitions"])) if q != old]
        candidate["transitions"][state][request][1] = rng.choice(choices)
        return candidate, "successor"
    if mode == 3:
        if not policy["state"]:
            return candidate, flip_decision(candidate, rng) + "-fallback"
        state = rng.randrange(len(candidate["observations"]))
        old = candidate["observations"][state]
        choices = [value for value in range(1 << len(policy["state"])) if value != old]
        candidate["observations"][state] = rng.choice(choices)
        return candidate, "observation"
    source_initial = language.initial(policy)
    choices = [q for q, observed in enumerate(candidate["observations"]) if observed != source_initial]
    if not choices:
        return candidate, flip_decision(candidate, rng) + "-fallback"
    candidate["initial"] = rng.choice(choices)
    return candidate, "initial"


def singleton_policy(policy: dict[str, Any], binding: dict[str, str]) -> dict[str, Any]:
    fixed = copy.deepcopy(policy)
    for alias in fixed["aliases"]:
        alias["candidates"] = [binding[alias["name"]]]
    return language.normalize(fixed)


def direct_paths(machine: dict[str, Any]) -> tuple[dict[int, list[int]], int]:
    paths = {machine["initial"]: []}
    queue = deque([machine["initial"]])
    operations = 0
    while queue:
        state = queue.popleft()
        for index, (_, successor) in enumerate(machine["transitions"][state]):
            operations += 1
            if successor not in paths:
                paths[successor] = paths[state] + [index]
                queue.append(successor)
    return paths, operations


def direct_coherence(machine: dict[str, Any]) -> tuple[bool, int]:
    paths, operations = direct_paths(machine)
    signatures: dict[int, list[tuple[str, int]]] = {}
    for state in paths:
        signature = []
        for decision, successor in machine["transitions"][state]:
            operations += 1
            signature.append((decision, machine["observations"][successor]))
        observed = machine["observations"][state]
        if observed in signatures and signatures[observed] != signature:
            return False, operations
        signatures.setdefault(observed, signature)
    return True, operations


def machine_trace_equivalent(left: dict[str, Any], right: dict[str, Any]) -> tuple[bool, int]:
    if left["alphabet"] != right["alphabet"]:
        return False, 0
    start = (left["initial"], right["initial"])
    if left["observations"][start[0]] != right["observations"][start[1]]:
        return False, 0
    seen = {start}
    queue = deque([start])
    operations = 0
    while queue:
        left_state, right_state = queue.popleft()
        for index in range(len(left["alphabet"])):
            operations += 1
            left_decision, left_next = left["transitions"][left_state][index]
            right_decision, right_next = right["transitions"][right_state][index]
            if (left_decision != right_decision or
                    left["observations"][left_next] != right["observations"][right_next]):
                return False, operations
            pair = (left_next, right_next)
            if pair not in seen:
                seen.add(pair)
                queue.append(pair)
    return True, operations


def check_core_case(
    index: int, policy: dict[str, Any], machine: dict[str, Any], operations: CounterBudget
) -> tuple[bool, int | None, int]:
    product = product_oracle(policy, machine)
    operations.add(product["transition_evaluations"], "product_semantic_steps")
    try:
        checked = checker.verify(policy, machine, compiler.certificate(machine))
        checker_equivalent = True
        operations.add(checked["binding_evaluations"], "checker_semantic_steps")
    except checker.Rejected as error:
        if error.kind != "mismatch":
            raise
        checker_equivalent = False
        operations.add(getattr(error, "evaluations", 0), "checker_semantic_steps")
    if checker_equivalent != product["equivalent"]:
        raise RuntimeError(f"checker/product verdict disagreement in case {index}")

    diagnostic = compiler.diagnose(policy, machine)
    operations.add(diagnostic.get("local_evaluations", 0), "diagnostic_semantic_steps")
    operations.add(len(diagnostic.get("trace", [])), "diagnostic_replay_steps")
    if diagnostic["equivalent"] != product["equivalent"]:
        raise RuntimeError(f"diagnostic/product verdict disagreement in case {index}")
    shortest = None if product["equivalent"] else product["shortest"]["length"]
    if not product["equivalent"] and diagnostic["length"] != shortest:
        raise RuntimeError(f"diagnostic/product length disagreement in case {index}")
    if shortest == 0:
        if diagnostic.get("reason") != "initial observation" or diagnostic["trace"] != []:
            raise RuntimeError(f"length-zero diagnostic malformed in case {index}")
    elif shortest is not None:
        if not diagnostic["trace"] or diagnostic["trace"][-1]["source"] == diagnostic["trace"][-1]["target"]:
            raise RuntimeError(f"positive diagnostic does not end in disagreement in case {index}")
    return product["equivalent"], shortest, product["transition_evaluations"]


def check_step_semantics(index: int, policy: dict[str, Any], operations: CounterBudget) -> int:
    comparisons = 0
    for state in range(1 << len(policy["state"])):
        for request in compiler.alphabet(policy):
            for binding in all_bindings(policy):
                left = compiler.step(policy, state, request, binding)
                right = checker.reference_step(policy, state, request, binding)
                operations.add(2, "source_semantic_steps")
                comparisons += 1
                if left != right:
                    raise RuntimeError(f"compiler/reference step disagreement in case {index}")
    return comparisons


def check_profile(
    index: int, policy: dict[str, Any], machine: dict[str, Any], operations: CounterBudget
) -> int:
    profile = binding_profile(policy, machine)
    operations.add(profile["work_operations"], "profile_work")
    checked = 0
    for row in profile["profiles"]:
        direct = product_oracle(singleton_policy(policy, row["binding"]), machine)
        operations.add(direct["transition_evaluations"], "profile_singleton_steps")
        expected_length = None if direct["equivalent"] else direct["shortest"]["length"]
        if row["equivalent"] != direct["equivalent"] or row["length"] != expected_length:
            raise RuntimeError(f"binding-profile disagreement in case {index}")
        if not row["equivalent"] and row["trace"]:
            if any(not step["compared_equal"] for step in row["trace"][:-1]):
                raise RuntimeError(f"binding-profile prefix malformed in case {index}")
            if row["trace"][-1]["compared_equal"]:
                raise RuntimeError(f"binding-profile suffix malformed in case {index}")
        checked += 1
    return checked


def check_projection(index: int, policy: dict[str, Any], operations: CounterBudget) -> int:
    rng = random.Random(BASE_SEED + index * 31 + 7)
    required = [name for name, _ in policy["state"] if rng.randrange(2)]
    result = project_policy(policy, required)
    reduced = result["policy"]
    retained = result["cone"]["retained"]
    comparisons = 0
    for state in range(1 << len(policy["state"])):
        small_state = project_state(policy, retained, state)
        for request in compiler.alphabet(policy):
            for binding in all_bindings(policy):
                full = checker.reference_step(policy, state, request, binding)
                small = checker.reference_step(reduced, small_state, request, binding)
                operations.add(2, "projection_semantic_steps")
                expected = (full[0], project_state(policy, retained, full[1]))
                if small != expected:
                    raise RuntimeError(f"projection commutation disagreement in case {index}")
                comparisons += 1
    return comparisons


def check_quotient(
    index: int, policy: dict[str, Any], machine: dict[str, Any], operations: CounterBudget
) -> tuple[bool, int | None]:
    coherent, direct_operations = direct_coherence(machine)
    operations.add(direct_operations, "quotient_direct_work")
    try:
        result = observable_quotient(policy, machine)
        constructed = True
        operations.add(result["work_operations"], "quotient_construct_work")
    except checker.Rejected as error:
        if error.kind != "mismatch":
            raise
        constructed = False
        result = None
        operations.add(getattr(error, "work_operations", 0), "quotient_construct_work")
    if constructed != coherent:
        raise RuntimeError(f"quotient coherence disagreement in case {index}")
    if not constructed:
        return False, None
    equivalent, traversal = machine_trace_equivalent(machine, result["machine"])
    operations.add(traversal, "quotient_trace_work")
    if not equivalent:
        raise RuntimeError(f"quotient trace disagreement in case {index}")
    return True, result["collapsed_states"]


def check_switching(
    index: int, policy: dict[str, Any], machine: dict[str, Any], equivalent: bool, operations: CounterBudget
) -> tuple[bool, int | None]:
    switched = switching_oracle(policy, machine)
    operations.add(switched["work_operations"], "switching_work")
    if switched["equivalent"] != equivalent:
        raise RuntimeError(f"full-state switching disagreement in case {index}")
    if not switched["equivalent"] and switched["trace"]:
        if any(not step["compared_equal"] for step in switched["trace"][:-1]):
            raise RuntimeError(f"switching prefix malformed in case {index}")
        if switched["trace"][-1]["compared_equal"]:
            raise RuntimeError(f"switching suffix malformed in case {index}")
    return switched["equivalent"], switched["length"]


def decision_switching_fixture() -> tuple[dict[str, Any], dict[str, Any]]:
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
        "transitions": [[["allow", 0]]],
    }
    return language.normalize(policy), machine


def boundary_controls(operations: CounterBudget) -> dict[str, Any]:
    controls: dict[str, Any] = {}

    wide = blank()
    wide["roles"] = ["r", "s"]
    wide["members"] = [["u", "r"]]
    wide["aliases"] = [
        {"name": f"z{index:02d}", "kind": "role", "candidates": ["r", "s"]}
        for index in range(16)
    ]
    wide = language.normalize(wide)
    try:
        normalize_family(wide, family_limit=1024)
        raise RuntimeError("wide family unexpectedly materialized")
    except checker.Rejected as error:
        if error.kind != "inconclusive":
            raise
        controls["wide_family_preflight"] = True
        operations.add(16, "boundary_preflight_work")

    single = blank()
    single["roles"] = ["r"]
    single["members"] = [["u", "r"]]
    single["aliases"] = [{"name": "z", "kind": "role", "candidates": ["r"]}]
    single = language.normalize(single)

    def duplicates():
        while True:
            yield {"z": "r"}

    try:
        normalize_family(single, duplicates(), budget=128, family_limit=32)
        raise RuntimeError("unbounded family unexpectedly terminated")
    except checker.Rejected as error:
        if error.kind != "inconclusive":
            raise
        controls["unbounded_iterable_stopped"] = True
        operations.add(33, "boundary_iterator_work")

    plain = language.normalize(blank())
    plain_machine = compiler.compile_policy(plain)
    zero_budget = 0
    for operation in (
        lambda: observable_quotient(plain, plain_machine, budget=0),
        lambda: verify_family(plain, plain_machine, compiler.certificate(plain_machine), [{}], budget=0),
    ):
        try:
            operation()
            raise RuntimeError("zero budget unexpectedly accepted")
        except checker.Rejected as error:
            if error.kind != "inconclusive":
                raise
            zero_budget += 1
    controls["zero_budget_preparation"] = zero_budget == 2

    policy, machine = decision_switching_fixture()
    result = switching_oracle(policy, machine, decisions_only=True)
    operations.add(result["work_operations"], "boundary_switching_work")
    if (result["equivalent"] or result["length"] != 2 or
            result["trace"][0]["state_equal"] or not result["trace"][0]["compared_equal"] or
            result["trace"][-1]["compared_equal"]):
        raise RuntimeError("decision-only trace distinction failed")
    controls["decision_only_trace"] = True
    return controls


def run(destination: str | Path, count: int = FULL_CASES) -> dict[str, Any]:
    if type(count) is not int or count <= 0 or count > FULL_CASES:
        raise ValueError("case count must be in 1..1024")
    begin_cpu = time.process_time()
    begin_wall = time.perf_counter()
    operations = CounterBudget(CAMPAIGN_OPERATION_LIMIT)
    records = []
    verdicts: Counter[str] = Counter()
    mutations: Counter[str] = Counter()
    alias_sorts: Counter[str] = Counter()
    action_alias_cases = 0
    initial_witnesses = 0
    positive_witnesses = 0
    profile_bindings = 0
    step_comparisons = 0
    projection_comparisons = 0
    coherent_quotients = 0
    collapsed_quotients = 0

    for index in range(count):
        policy = make_policy(index)
        for alias in policy["aliases"]:
            alias_sorts[alias["kind"]] += 1
        if any(alias["kind"] == "action" for alias in policy["aliases"]):
            action_alias_cases += 1
        base = compiler.compile_policy(policy)
        machine, mutation = mutate_machine(policy, base, index)
        mutations[mutation] += 1

        equivalent, shortest, _ = check_core_case(index, policy, machine, operations)
        verdicts["equivalent" if equivalent else "different"] += 1
        if shortest == 0:
            initial_witnesses += 1
        elif shortest is not None:
            positive_witnesses += 1

        if index < min(count, STEP_CASES):
            step_comparisons += check_step_semantics(index, policy, operations)
        profile_checked = index < min(count, PROFILE_CASES)
        if profile_checked:
            profile_bindings += check_profile(index, policy, machine, operations)
        switching_equivalent, switching_length = check_switching(
            index, policy, machine, equivalent, operations
        )
        quotient_coherent, collapsed = check_quotient(index, policy, machine, operations)
        coherent_quotients += int(quotient_coherent)
        collapsed_quotients += int(bool(collapsed))
        projection_checked = bool(policy["state"]) and index < min(count, PROJECTION_CASES)
        if projection_checked:
            projection_comparisons += check_projection(index, policy, operations)

        records.append({
            "case": f"adversarial-{index:04d}",
            "mutation": mutation,
            "state_bits": len(policy["state"]),
            "aliases": len(policy["aliases"]),
            "alias_sorts": [alias["kind"] for alias in policy["aliases"]],
            "rules": len(policy["rules"]),
            "equivalent": equivalent,
            "shortest_length": shortest,
            "profile_checked": profile_checked,
            "projection_checked": projection_checked,
            "quotient_coherent": quotient_coherent,
            "quotient_collapsed": collapsed,
            "switching_equivalent": switching_equivalent,
            "switching_length": switching_length,
        })

    controls = boundary_controls(operations)
    report = {
        "seed": BASE_SEED,
        "count": count,
        "full_case_target": FULL_CASES,
        "operation_limit": CAMPAIGN_OPERATION_LIMIT,
        "operations": operations.total,
        "operation_breakdown": dict(sorted(operations.parts.items())),
        "verdicts": dict(sorted(verdicts.items())),
        "mutations": dict(sorted(mutations.items())),
        "alias_sort_occurrences": dict(sorted(alias_sorts.items())),
        "action_alias_cases": action_alias_cases,
        "length_zero_witnesses": initial_witnesses,
        "positive_length_witnesses": positive_witnesses,
        "profile_cases": min(count, PROFILE_CASES),
        "profile_bindings": profile_bindings,
        "step_semantics_cases": min(count, STEP_CASES),
        "step_semantics_comparisons": step_comparisons,
        "projection_eligible_case_limit": min(count, PROJECTION_CASES),
        "projection_comparisons": projection_comparisons,
        "quotient_cases": count,
        "coherent_quotients": coherent_quotients,
        "collapsed_quotients": collapsed_quotients,
        "switching_cases": count,
        "boundary_controls": controls,
        "records": records,
        "cpu_seconds": time.process_time() - begin_cpu,
        "wall_seconds": time.perf_counter() - begin_wall,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "records"}, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--count", type=int, default=FULL_CASES)
    arguments = parser.parse_args()
    run(arguments.output, arguments.count)
