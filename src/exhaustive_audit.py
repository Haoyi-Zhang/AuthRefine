"""Complete tiny-domain cross-check with a third, direct source semantics.

The audit is exhaustive for the declared tiny family: one principal, resource,
action, request, and Boolean state bit; two roles; zero or one two-candidate role
alias; every role-membership pattern; every initial bit; zero, one, or two rules
from the finite template family below; and every total two-state target table.
Policies with the same complete tiny-domain transition function are represented
once.  The direct source evaluator in this file shares policy data but not the
compiler/checker stepping code.
"""
from __future__ import annotations

import argparse
import copy
import itertools
import json
import resource
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Iterable

import checker
import compiler
import language
import oracle
import symbolic
from extensions import binding_profile, switching_oracle

REQUEST = ["u", "o", "a"]


def direct_step(policy: dict[str, Any], state: int, request: list[str], binding: dict[str, str]) -> tuple[str, int]:
    """Evaluate one source step without calling the implementation semantics."""
    bit_names = [name for name, _ in policy["state"]]
    old = {name: bool((state >> index) & 1) for index, name in enumerate(bit_names)}
    fields = {"principal": request[0], "resource": request[1], "action": request[2]}
    members = {tuple(pair) for pair in policy["members"]}

    for rule in policy["rules"]:
        enabled = True
        for atom in rule["guard"]:
            field = atom["field"]
            if field == "state":
                value = old[atom["name"]] == atom["value"]
            else:
                referent = atom["name"] if "name" in atom else binding[atom["alias"]]
                if field == "role":
                    value = (request[0], referent) in members
                else:
                    value = fields[field] == referent
                if atom["negated"]:
                    value = not value
            if not value:
                enabled = False
                break
        if not enabled:
            continue

        post = dict(old)
        for effect in rule["updates"]:
            if "value" in effect:
                post[effect["name"]] = effect["value"]
            else:
                source = old[effect["from"]]
                post[effect["name"]] = (not source) if effect["negated"] else source
        new_state = sum(1 << index for index, name in enumerate(bit_names) if post[name])
        return rule["decision"], new_state

    return "deny", state


def complete_bindings(policy: dict[str, Any]) -> Iterable[dict[str, str]]:
    aliases = [alias["name"] for alias in policy["aliases"]]
    candidates = [alias["candidates"] for alias in policy["aliases"]]
    for values in itertools.product(*candidates):
        yield dict(zip(aliases, values))


def direct_product(
    policy: dict[str, Any], machine: dict[str, Any], binding: dict[str, str]
) -> tuple[int | None, list[int] | None]:
    """Return the shortest mismatch length/path for one fixed binding."""
    source_initial = sum(
        1 << index for index, (_, value) in enumerate(policy["state"]) if value
    )
    target_initial = machine["initial"]
    if source_initial != machine["observations"][target_initial]:
        return 0, []

    start = (source_initial, target_initial)
    queue: deque[tuple[tuple[int, int], list[int]]] = deque([(start, [])])
    seen = {start}
    while queue:
        (source_state, target_state), prefix = queue.popleft()
        for request_index, request in enumerate(machine["alphabet"]):
            source_decision, source_next = direct_step(
                policy, source_state, request, binding
            )
            target_decision, target_next = machine["transitions"][target_state][request_index]
            if (
                source_decision != target_decision
                or source_next != machine["observations"][target_next]
            ):
                return len(prefix) + 1, prefix + [request_index]
            successor = (source_next, target_next)
            if successor not in seen:
                seen.add(successor)
                queue.append((successor, prefix + [request_index]))
    return None, None


def direct_uniform(
    policy: dict[str, Any], machine: dict[str, Any]
) -> tuple[int, dict[str, str], list[int]] | None:
    best: tuple[int, dict[str, str], list[int]] | None = None
    for binding in complete_bindings(policy):
        length, path = direct_product(policy, machine, binding)
        if length is not None and (best is None or length < best[0]):
            assert path is not None
            best = (length, binding, path)
    return best


def direct_switching(policy: dict[str, Any], machine: dict[str, Any]) -> int | None:
    """Return shortest mismatch when a binding may be reselected each step."""
    bindings = list(complete_bindings(policy))
    source_initial = sum(
        1 << index for index, (_, value) in enumerate(policy["state"]) if value
    )
    target_initial = machine["initial"]
    if source_initial != machine["observations"][target_initial]:
        return 0

    start = (source_initial, target_initial)
    queue: deque[tuple[tuple[int, int], int]] = deque([(start, 0)])
    seen = {start}
    while queue:
        (source_state, target_state), depth = queue.popleft()
        for request_index, request in enumerate(machine["alphabet"]):
            target_decision, target_next = machine["transitions"][target_state][request_index]
            for binding in bindings:
                source_decision, source_next = direct_step(
                    policy, source_state, request, binding
                )
                if (
                    source_decision != target_decision
                    or source_next != machine["observations"][target_next]
                ):
                    return depth + 1
                successor = (source_next, target_next)
                if successor not in seen:
                    seen.add(successor)
                    queue.append((successor, depth + 1))
    return None


def guard_templates(has_alias: bool) -> list[list[dict[str, Any]]]:
    guards: list[list[dict[str, Any]]] = [
        [],
        [{"field": "state", "name": "b", "value": False}],
        [{"field": "state", "name": "b", "value": True}],
        [{"field": "role", "name": "r", "negated": False}],
        [{"field": "role", "name": "r", "negated": True}],
        [{"field": "role", "name": "s", "negated": False}],
        [{"field": "role", "name": "s", "negated": True}],
    ]
    if has_alias:
        for negated in (False, True):
            alias_atom = {"field": "role", "alias": "z", "negated": negated}
            guards.append([alias_atom])
            for state_value in (False, True):
                state_atom = {"field": "state", "name": "b", "value": state_value}
                guards.append([state_atom, alias_atom])
                guards.append([alias_atom, state_atom])
    return guards


def rule_templates(has_alias: bool) -> list[dict[str, Any]]:
    updates: list[list[dict[str, Any]]] = [
        [],
        [{"name": "b", "value": False}],
        [{"name": "b", "value": True}],
        [{"name": "b", "from": "b", "negated": True}],
    ]
    rules: list[dict[str, Any]] = []
    for guard in guard_templates(has_alias):
        rules.append({"decision": "deny", "guard": copy.deepcopy(guard), "updates": []})
        for update in updates:
            rules.append(
                {
                    "decision": "allow",
                    "guard": copy.deepcopy(guard),
                    "updates": copy.deepcopy(update),
                }
            )
    return rules


def semantic_signature(policy: dict[str, Any]) -> tuple[Any, ...]:
    return (
        language.initial(policy),
        tuple(
            (
                tuple(sorted(binding.items())),
                tuple(direct_step(policy, state, REQUEST, binding) for state in (0, 1)),
            )
            for binding in complete_bindings(policy)
        ),
    )


def policy_representatives() -> list[dict[str, Any]]:
    """One policy for every distinct transition function in the tiny templates."""
    representatives: dict[tuple[Any, ...], dict[str, Any]] = {}
    for membership_mask in range(4):
        members = []
        if membership_mask & 1:
            members.append(["u", "r"])
        if membership_mask & 2:
            members.append(["u", "s"])
        for initial_value in (False, True):
            for has_alias in (False, True):
                base = {
                    "principals": ["u"],
                    "resources": ["o"],
                    "actions": ["a"],
                    "roles": ["r", "s"],
                    "members": members,
                    "state": [["b", initial_value]],
                    "aliases": (
                        [{"name": "z", "kind": "role", "candidates": ["r", "s"]}]
                        if has_alias
                        else []
                    ),
                    "rules": [],
                }
                templates = rule_templates(has_alias)
                sequences: Iterable[tuple[dict[str, Any], ...]] = itertools.chain(
                    [()],
                    ((rule,) for rule in templates),
                    itertools.product(templates, repeat=2),
                )
                for sequence in sequences:
                    policy = copy.deepcopy(base)
                    policy["rules"] = [copy.deepcopy(rule) for rule in sequence]
                    policy = language.normalize(policy)
                    representatives.setdefault(semantic_signature(policy), policy)
    return list(representatives.values())


def target_machines() -> Iterable[dict[str, Any]]:
    """All total two-state, one-request targets with one observed bit."""
    for observations in itertools.product((0, 1), repeat=2):
        for initial_state in (0, 1):
            for transition_zero in itertools.product(("allow", "deny"), (0, 1)):
                for transition_one in itertools.product(("allow", "deny"), (0, 1)):
                    yield {
                        "state_names": ["b"],
                        "alphabet": [REQUEST],
                        "observations": list(observations),
                        "initial": initial_state,
                        "transitions": [[list(transition_zero)], [list(transition_one)]],
                    }


def audit(output: Path) -> dict[str, Any]:
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    policies = policy_representatives()
    machines = list(target_machines())

    source_step_cross_checks = 0
    policy_machine_pairs = 0
    uniform_verdict_cross_checks = 0
    shortest_length_cross_checks = 0
    profile_binding_cross_checks = 0
    switching_cross_checks = 0
    diagnostic_trace_cells = 0
    verdicts: Counter[str] = Counter()
    shortest_lengths: Counter[int] = Counter()
    binding_multiplicities: Counter[int] = Counter()

    # Compare three source-step implementations once for every policy, binding,
    # and complete tiny source state.  This check is independent of target tables.
    for policy_index, policy in enumerate(policies):
        bindings = list(complete_bindings(policy))
        binding_multiplicities[len(bindings)] += 1
        for binding in bindings:
            for source_state in (0, 1):
                expected = direct_step(policy, source_state, REQUEST, binding)
                compiled = compiler.step(policy, source_state, REQUEST, binding)
                checked = checker.reference_step(policy, source_state, REQUEST, binding)
                if expected != compiled or expected != checked:
                    raise AssertionError(
                        {
                            "kind": "source-step",
                            "policy": policy_index,
                            "binding": binding,
                            "source_state": source_state,
                            "direct": expected,
                            "compiler": compiled,
                            "checker": checked,
                        }
                    )
                source_step_cross_checks += 1

    for policy_index, policy in enumerate(policies):
        bindings = list(complete_bindings(policy))
        for machine_index, machine in enumerate(machines):
            pair = (policy_index, machine_index)
            direct_result = direct_uniform(policy, machine)
            expected_equivalent = direct_result is None

            try:
                checker.verify(policy, machine, compiler.certificate(machine), budget=1_000_000)
                checker_equivalent = True
            except checker.Rejected as error:
                if error.kind != "mismatch":
                    raise
                checker_equivalent = False

            product = oracle.product_oracle(policy, machine, budget=1_000_000)
            symbolic_result = symbolic.check(policy, machine)
            diagnosis = compiler.diagnose(policy, machine, limit=1_000_000)
            observed_verdicts = (
                checker_equivalent,
                product["equivalent"],
                symbolic_result["equivalent"],
                diagnosis["equivalent"],
            )
            if observed_verdicts != (expected_equivalent,) * len(observed_verdicts):
                raise AssertionError(
                    {
                        "kind": "uniform-verdict",
                        "pair": pair,
                        "expected": expected_equivalent,
                        "observed": observed_verdicts,
                    }
                )
            uniform_verdict_cross_checks += 1
            verdicts["equivalent" if expected_equivalent else "different"] += 1

            if direct_result is not None:
                expected_length = direct_result[0]
                observed_lengths = (
                    product["shortest"]["length"],
                    symbolic_result["length"],
                    diagnosis["length"],
                )
                if observed_lengths != (expected_length,) * len(observed_lengths):
                    raise AssertionError(
                        {
                            "kind": "shortest-length",
                            "pair": pair,
                            "expected": expected_length,
                            "observed": observed_lengths,
                        }
                    )
                shortest_length_cross_checks += 1
                shortest_lengths[expected_length] += 1
                trace = diagnosis["trace"]
                if expected_length == 0:
                    if trace != []:
                        raise AssertionError({"kind": "empty-trace", "pair": pair})
                else:
                    if len(trace) != expected_length:
                        raise AssertionError({"kind": "trace-length", "pair": pair})
                    for row in trace[:-1]:
                        if row["source"] != row["target"]:
                            raise AssertionError({"kind": "early-trace-mismatch", "pair": pair})
                    if trace[-1]["source"] == trace[-1]["target"]:
                        raise AssertionError({"kind": "missing-final-mismatch", "pair": pair})
                    diagnostic_trace_cells += len(trace)

            profile = binding_profile(policy, machine, budget=1_000_000)
            rows = {
                tuple(sorted(row["binding"].items())): row for row in profile["profiles"]
            }
            for binding in bindings:
                direct_length, _ = direct_product(policy, machine, binding)
                row = rows[tuple(sorted(binding.items()))]
                if row["equivalent"] != (direct_length is None) or row["length"] != direct_length:
                    raise AssertionError(
                        {
                            "kind": "binding-profile",
                            "pair": pair,
                            "binding": binding,
                            "expected_length": direct_length,
                            "observed": row,
                        }
                    )
                profile_binding_cross_checks += 1

            switching = switching_oracle(policy, machine, budget=1_000_000)
            direct_switch_length = direct_switching(policy, machine)
            if (
                switching["equivalent"] != (direct_switch_length is None)
                or switching["length"] != direct_switch_length
            ):
                raise AssertionError(
                    {
                        "kind": "switching",
                        "pair": pair,
                        "expected_length": direct_switch_length,
                        "observed": switching,
                    }
                )
            switching_cross_checks += 1
            policy_machine_pairs += 1

    comparisons = {
        "source_step_cross_checks": source_step_cross_checks,
        "uniform_verdict_cross_checks": uniform_verdict_cross_checks,
        "shortest_length_cross_checks": shortest_length_cross_checks,
        "profile_binding_cross_checks": profile_binding_cross_checks,
        "switching_cross_checks": switching_cross_checks,
        "diagnostic_trace_cells": diagnostic_trace_cells,
    }
    operations = sum(comparisons.values())
    report = {
        "scope": {
            "principals": 1,
            "resources": 1,
            "actions": 1,
            "requests": 1,
            "state_bits": 1,
            "roles": 2,
            "aliases": "zero or one two-candidate role alias",
            "membership_patterns": 4,
            "initial_valuations": 2,
            "rule_count": "zero through two",
            "target_states": 2,
            "target_tables": "all total tables in the declared target shape",
            "deduplication": "one policy per complete tiny-domain transition function",
        },
        "policy_semantic_representatives": len(policies),
        "binding_multiplicities": {str(key): value for key, value in sorted(binding_multiplicities.items())},
        "machines_per_policy": len(machines),
        "policy_machine_pairs": policy_machine_pairs,
        "verdicts": dict(sorted(verdicts.items())),
        "shortest_lengths": {str(key): value for key, value in sorted(shortest_lengths.items())},
        "comparisons": comparisons,
        "operations": operations,
        "status": "pass",
        "cpu_seconds": time.process_time() - cpu_start,
        "wall_seconds": time.perf_counter() - wall_start,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.output), indent=2))


if __name__ == "__main__":
    main()
