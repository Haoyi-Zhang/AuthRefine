"""Executable reference constructions for the paper's derived characterizations.

The main checker remains the small Cartesian full-state validator in ``checker.py``.
This module makes five separately proved consequences executable for inspection and
finite cross-checking: binding-wise failure profiles, explicitly restricted binding
families, observable quotients, dependence-closed state projection, and stepwise
binding switching.  It uses only the typed JSON interface and the checker's named-
environment reference semantics; it does not parse controlled-language text.

Every potentially expansive public routine has an explicit work budget.  Binding
families are consumed incrementally and have a separate cardinality cap, so a wide
or unbounded iterable is rejected inconclusively before it can be materialized.
"""
from __future__ import annotations

from collections import deque
from copy import deepcopy
from itertools import product
from typing import Any, Iterable

from checker import (
    Rejected,
    ensure,
    inspect_machine,
    inspect_policy,
    integer,
    reference_step,
    support,
)
from language import normalize


DEFAULT_WORK_BUDGET = 2_000_000
DEFAULT_FAMILY_LIMIT = 65_536


class _WorkBudget:
    """One monotone counter shared by all phases of a derived construction."""

    def __init__(self, limit: int):
        ensure(integer(limit) and limit >= 0, "extension work budget", "inconclusive")
        self.limit = limit
        self.total = 0
        self.categories: dict[str, int] = {}

    def charge(self, amount: int = 1, category: str = "other") -> None:
        ensure(integer(amount) and amount >= 0, "extension work charge")
        ensure(self.total + amount <= self.limit, "extension work budget", "inconclusive")
        self.total += amount
        self.categories[category] = self.categories.get(category, 0) + amount

    def report(self) -> dict[str, Any]:
        return {
            "work_operations": self.total,
            "work_budget": self.limit,
            "work_breakdown": dict(sorted(self.categories.items())),
        }


def _initial(p: dict[str, Any]) -> int:
    return sum(2 ** i for i, (_, value) in enumerate(p["state"]) if value)


def _validate_family_limit(family_limit: int) -> None:
    ensure(integer(family_limit) and family_limit > 0, "binding family limit", "inconclusive")


def _validate_binding(p: dict[str, Any], binding: Any) -> dict[str, str]:
    ensure(isinstance(binding, dict), "binding shape")
    aliases = {alias["name"]: alias for alias in p["aliases"]}
    ensure(set(binding) == set(aliases), "binding domain")
    for name, value in binding.items():
        ensure(isinstance(value, str) and value in aliases[name]["candidates"], "binding candidate")
    return {name: binding[name] for name in sorted(binding)}


def _normalize_family(
    p: dict[str, Any],
    family: Iterable[dict[str, str]] | None,
    work: _WorkBudget,
    family_limit: int,
) -> list[dict[str, str]]:
    """Stream, validate, and deduplicate a bounded nonempty binding family."""
    _validate_family_limit(family_limit)
    if family is None:
        cardinality = 1
        for alias in p["aliases"]:
            cardinality *= len(alias["candidates"])
            ensure(cardinality <= family_limit, "binding family cardinality", "inconclusive")
        names = [alias["name"] for alias in p["aliases"]]
        values: Iterable[dict[str, str]] = (
            dict(zip(names, choices))
            for choices in product(*(alias["candidates"] for alias in p["aliases"]))
        )
    else:
        try:
            values = iter(family)
        except TypeError as error:
            raise Rejected("binding family iterable") from error

    result: list[dict[str, str]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    raw_count = 0
    for binding in values:
        raw_count += 1
        ensure(raw_count <= family_limit, "binding family cardinality", "inconclusive")
        work.charge(category="family_members")
        canonical = _validate_binding(p, binding)
        key = tuple(canonical.items())
        if key not in seen:
            seen.add(key)
            result.append(canonical)
    ensure(raw_count > 0 and result, "empty binding family")
    return result


def normalize_family(
    p: dict[str, Any],
    family: Iterable[dict[str, str]] | None = None,
    budget: int = DEFAULT_WORK_BUDGET,
    family_limit: int = DEFAULT_FAMILY_LIMIT,
) -> list[dict[str, str]]:
    """Validate and deduplicate a nonempty family without unbounded materialization."""
    inspect_policy(p)
    work = _WorkBudget(budget)
    return _normalize_family(p, family, work, family_limit)


def _target_paths(machine: dict[str, Any], work: _WorkBudget) -> dict[int, list[int]]:
    first = machine["initial"]
    paths = {first: []}
    queue = deque([first])
    while queue:
        state = queue.popleft()
        for index, (_, successor) in enumerate(machine["transitions"][state]):
            work.charge(category="graph_edges")
            if successor not in paths:
                paths[successor] = paths[state] + [index]
                queue.append(successor)
    return paths


def target_paths(machine: dict[str, Any], budget: int = DEFAULT_WORK_BUDGET) -> dict[int, list[int]]:
    """Return one breadth-first shortest input-index path to each reachable state."""
    return _target_paths(machine, _WorkBudget(budget))


def _reference_replay(
    p: dict[str, Any],
    machine: dict[str, Any],
    indices: list[int],
    bindings: list[dict[str, str]],
    *,
    decisions_only: bool = False,
    work: _WorkBudget | None = None,
) -> list[dict[str, Any]]:
    ensure(len(indices) == len(bindings), "replay binding count")
    source = _initial(p)
    target = machine["initial"]
    rows = []
    for index, binding in zip(indices, bindings):
        if work is not None:
            work.charge(category="replay_steps")
        request = machine["alphabet"][index]
        source_decision, source_next = reference_step(p, source, request, binding)
        target_decision, target_next = machine["transitions"][target][index]
        observed = machine["observations"][target_next]
        decision_equal = source_decision == target_decision
        state_equal = source_next == observed
        rows.append({
            "request": request,
            "binding": binding,
            "source": [source_decision, source_next],
            "target": [target_decision, observed],
            "decision_equal": decision_equal,
            "state_equal": state_equal,
            "compared_equal": decision_equal and (decisions_only or state_equal),
        })
        source = source_next
        target = target_next
    return rows


def binding_profile(
    p: dict[str, Any],
    machine: dict[str, Any],
    family: Iterable[dict[str, str]] | None = None,
    budget: int = DEFAULT_WORK_BUDGET,
    family_limit: int = DEFAULT_FAMILY_LIMIT,
) -> dict[str, Any]:
    """Classify each fixed binding by its exact shortest disagreement length.

    The search scans target states in breadth-first distance order and evaluates all
    cells under one fixed binding.  The paper's prefix-reconstruction theorem makes
    the first bad target layer replayable from the initial source state.  The result
    retains that replay so finite validation can compare it with an explicit product.
    """
    inspect_policy(p)
    inspect_machine(p, machine, compare_initial=False)
    work = _WorkBudget(budget)
    bindings = _normalize_family(p, family, work, family_limit)
    paths = _target_paths(machine, work)
    source_initial = _initial(p)
    target_initial = machine["observations"][machine["initial"]]
    evaluations = 0
    rows: list[dict[str, Any]] = []
    for binding in bindings:
        if source_initial != target_initial:
            rows.append({
                "binding": binding,
                "equivalent": False,
                "length": 0,
                "indices": [],
                "trace": [],
                "reason": "initial observation",
            })
            continue
        witness = None
        for q, prefix in paths.items():
            state = machine["observations"][q]
            for index, request in enumerate(machine["alphabet"]):
                work.charge(category="semantic_steps")
                evaluations += 1
                actual = reference_step(p, state, request, binding)
                edge = machine["transitions"][q][index]
                expected = (edge[0], machine["observations"][edge[1]])
                if actual != expected:
                    indices = prefix + [index]
                    replay = _reference_replay(
                        p, machine, indices, [binding] * len(indices), work=work
                    )
                    ensure(replay and not replay[-1]["compared_equal"], "profile replay disagreement")
                    ensure(all(row["compared_equal"] for row in replay[:-1]), "profile replay prefix")
                    witness = {
                        "binding": binding,
                        "equivalent": False,
                        "length": len(indices),
                        "indices": indices,
                        "trace": replay,
                        "target_state": q,
                        "request": index,
                    }
                    break
            if witness is not None:
                break
        rows.append(witness if witness is not None else {
            "binding": binding,
            "equivalent": True,
            "length": None,
            "indices": None,
            "trace": None,
        })
    matching = sum(row["equivalent"] for row in rows)
    classification = "all" if matching == len(rows) else "none" if matching == 0 else "some"
    strata: dict[str, int] = {}
    for row in rows:
        key = "infinity" if row["equivalent"] else str(row["length"])
        strata[key] = strata.get(key, 0) + 1
    finite = [row["length"] for row in rows if not row["equivalent"]]
    return {
        "classification": classification,
        "bindings": len(rows),
        "matching_bindings": matching,
        "failing_bindings": len(rows) - matching,
        "shortest_failure": min(finite) if finite else None,
        "strata": strata,
        "target_reachable_states": len(paths),
        "transition_evaluations": evaluations,
        "profiles": rows,
        **work.report(),
    }


def verify_family(
    p: dict[str, Any],
    machine: dict[str, Any],
    certificate: dict[str, Any],
    family: Iterable[dict[str, str]],
    budget: int = DEFAULT_WORK_BUDGET,
    family_limit: int = DEFAULT_FAMILY_LIMIT,
) -> dict[str, Any]:
    """Check a certificate against exactly an explicitly listed binding family.

    Per cell, only distinct support projections induced by legal family members are
    evaluated.  Projection representatives are cached by support set.  A retained
    family member witnesses every projection and is also a legal binding for any
    reported mismatch.
    """
    aliases = inspect_policy(p)
    inspect_machine(p, machine)
    work = _WorkBudget(budget)
    bindings = _normalize_family(p, family, work, family_limit)
    ensure(isinstance(certificate, dict) and set(certificate) == {"reachable"}, "certificate fields")
    states = certificate["reachable"]
    ensure(isinstance(states, list) and all(integer(q) and 0 <= q < len(machine["observations"]) for q in states), "certificate states")
    ensure(len(states) == len(set(states)) and machine["initial"] in states, "certificate initial or duplicate")
    region = set(states)
    for q in states:
        for edge in machine["transitions"][q]:
            work.charge(category="certificate_edges")
            ensure(edge[1] in region, "certificate closure")

    evaluations = 0
    maximum_width = 0
    cells = []
    projection_cache: dict[tuple[str, ...], dict[tuple[str, ...], dict[str, str]]] = {}
    for q in states:
        state = machine["observations"][q]
        for index, request in enumerate(machine["alphabet"]):
            work.charge(category="local_cells")
            dependencies = support(p, state, request)
            maximum_width = max(maximum_width, len(dependencies))
            dependency_key = tuple(dependencies)
            if dependency_key not in projection_cache:
                representatives: dict[tuple[str, ...], dict[str, str]] = {}
                for binding in bindings:
                    work.charge(category="family_projections")
                    key = tuple(binding[name] for name in dependencies)
                    representatives.setdefault(key, binding)
                projection_cache[dependency_key] = representatives
            representatives = projection_cache[dependency_key]
            edge = machine["transitions"][q][index]
            expected = (edge[0], machine["observations"][edge[1]])
            for binding in representatives.values():
                work.charge(category="semantic_steps")
                evaluations += 1
                actual = reference_step(p, state, request, binding)
                if actual != expected:
                    error = Rejected(f"family refinement mismatch at state {q}, request {index}", "mismatch")
                    error.evaluations = evaluations
                    error.maximum_width = maximum_width
                    error.binding = binding
                    error.work_operations = work.total
                    error.work_breakdown = dict(sorted(work.categories.items()))
                    raise error
            cells.append({
                "state": q,
                "request": index,
                "support": dependencies,
                "family_projections": len(representatives),
            })
    return {
        "accepted": True,
        "family_size": len(bindings),
        "states": len(states),
        "local_cells": len(cells),
        "binding_evaluations": evaluations,
        "maximum_width": maximum_width,
        "cells": cells,
        "alias_count": len(aliases),
        **work.report(),
    }


def observable_quotient(
    p: dict[str, Any], machine: dict[str, Any], budget: int = DEFAULT_WORK_BUDGET
) -> dict[str, Any]:
    """Construct the canonical reachable quotient by complete observations.

    Raises a semantic mismatch when two reachable states in one observation fiber
    have different decision/successor-observation rows.
    """
    inspect_policy(p)
    inspect_machine(p, machine, compare_initial=False)
    work = _WorkBudget(budget)
    paths = _target_paths(machine, work)
    representatives: dict[int, int] = {}
    signatures: dict[int, list[tuple[str, int]]] = {}
    state_map: dict[int, int] = {}
    observations: list[int] = []
    for q in paths:
        observed = machine["observations"][q]
        signature = []
        for decision, successor in machine["transitions"][q]:
            work.charge(category="fiber_cells")
            signature.append((decision, machine["observations"][successor]))
        if observed in signatures:
            if signatures[observed] != signature:
                error = Rejected("reachable observation fiber is incoherent", "mismatch")
                error.work_operations = work.total
                error.work_breakdown = dict(sorted(work.categories.items()))
                raise error
        else:
            representatives[observed] = q
            signatures[observed] = signature
            state_map[observed] = len(observations)
            observations.append(observed)
    transitions = []
    for observed in observations:
        row = []
        for decision, successor_observation in signatures[observed]:
            work.charge(category="quotient_edges")
            row.append([decision, state_map[successor_observation]])
        transitions.append(row)
    quotient = {
        "state_names": list(machine["state_names"]),
        "alphabet": deepcopy(machine["alphabet"]),
        "observations": observations,
        "initial": state_map[machine["observations"][machine["initial"]]],
        "transitions": transitions,
    }
    inspect_machine(p, quotient, compare_initial=False)
    ensure(len(_target_paths(quotient, work)) == len(observations), "quotient contains unreachable state")
    return {
        "machine": quotient,
        "reachable_original_states": len(paths),
        "reachable_observations": len(observations),
        "collapsed_states": len(paths) - len(observations),
        "representatives": {str(state_map[observation]): representatives[observation] for observation in observations},
        **work.report(),
    }


def observation_cone(p: dict[str, Any], required: Iterable[str] = ()) -> dict[str, Any]:
    """Compute the least syntactic guard/update dependence closure."""
    inspect_policy(p)
    state_names = [name for name, _ in p["state"]]
    required_set = set(required)
    ensure(all(isinstance(name, str) and name in state_names for name in required_set), "required observation bit")
    guard_bits = {atom["name"] for rule in p["rules"] for atom in rule["guard"] if atom["field"] == "state"}
    predecessors: dict[str, set[str]] = {name: set() for name in state_names}
    dependencies = []
    for rule in p["rules"]:
        for effect in rule["updates"]:
            if "from" in effect:
                predecessors[effect["name"]].add(effect["from"])
                dependencies.append([effect["from"], effect["name"]])
    retained = set(guard_bits) | required_set
    queue = deque(name for name in state_names if name in retained)
    while queue:
        destination = queue.popleft()
        for source in predecessors[destination]:
            if source not in retained:
                retained.add(source)
                queue.append(source)
    ordered = [name for name in state_names if name in retained]
    return {
        "required": [name for name in state_names if name in required_set],
        "guard_bits": [name for name in state_names if name in guard_bits],
        "dependencies": dependencies,
        "retained": ordered,
        "discarded": [name for name in state_names if name not in retained],
    }


def project_state(p: dict[str, Any], retained: Iterable[str], state: int) -> int:
    """Restrict one encoded full valuation to the retained state-name order."""
    names = [name for name, _ in p["state"]]
    selected = list(retained)
    ensure(len(selected) == len(set(selected)) and all(name in names for name in selected), "projection names")
    ensure(integer(state) and 0 <= state < 2 ** len(names), "projection state")
    positions = {name: i for i, name in enumerate(names)}
    return sum(2 ** j for j, name in enumerate(selected) if (state >> positions[name]) & 1)


def project_policy(p: dict[str, Any], required: Iterable[str] = ()) -> dict[str, Any]:
    """Construct the dependence-closed reduced policy and return its cone metadata."""
    inspect_policy(p)
    cone = observation_cone(p, required)
    retained = set(cone["retained"])
    reduced = deepcopy(p)
    reduced["state"] = [declaration for declaration in reduced["state"] if declaration[0] in retained]
    for rule in reduced["rules"]:
        rule["updates"] = [effect for effect in rule["updates"] if effect["name"] in retained]
    reduced = normalize(reduced)
    inspect_policy(reduced)
    return {"policy": reduced, "cone": cone}


def project_machine(p: dict[str, Any], machine: dict[str, Any], retained: Iterable[str]) -> dict[str, Any]:
    """Project every target observation while preserving its hidden transition graph."""
    inspect_policy(p)
    inspect_machine(p, machine, compare_initial=False)
    selected = list(retained)
    ensure(selected == sorted(selected), "canonical projection state names")
    projected = deepcopy(machine)
    projected["state_names"] = selected
    projected["observations"] = [project_state(p, selected, state) for state in machine["observations"]]
    return projected


def _unwind_switching(
    parents: dict[tuple[int, int], tuple[tuple[int, int], int, dict[str, str]] | None],
    pair: tuple[int, int],
) -> tuple[list[int], list[dict[str, str]]]:
    indices: list[int] = []
    bindings: list[dict[str, str]] = []
    while parents[pair] is not None:
        previous, index, binding = parents[pair]
        indices.append(index)
        bindings.append(binding)
        pair = previous
    indices.reverse()
    bindings.reverse()
    return indices, bindings


def switching_oracle(
    p: dict[str, Any],
    machine: dict[str, Any],
    family: Iterable[dict[str, str]] | None = None,
    decisions_only: bool = False,
    budget: int = DEFAULT_WORK_BUDGET,
    family_limit: int = DEFAULT_FAMILY_LIMIT,
) -> dict[str, Any]:
    """Exact finite search where the reference binding may change at every step."""
    inspect_policy(p)
    inspect_machine(p, machine, compare_initial=False)
    ensure(type(decisions_only) is bool, "switching observation mode")
    work = _WorkBudget(budget)
    bindings = _normalize_family(p, family, work, family_limit)
    source_initial = _initial(p)
    target_initial = machine["initial"]
    if not decisions_only and source_initial != machine["observations"][target_initial]:
        return {
            "equivalent": False,
            "length": 0,
            "indices": [],
            "bindings": [],
            "trace": [],
            "transition_evaluations": 0,
            "visited_pairs": 1,
            **work.report(),
        }
    start = (source_initial, target_initial)
    queue = deque([start])
    parents: dict[tuple[int, int], tuple[tuple[int, int], int, dict[str, str]] | None] = {start: None}
    evaluations = 0
    while queue:
        source, target = queue.popleft()
        for index, request in enumerate(machine["alphabet"]):
            target_decision, target_next = machine["transitions"][target][index]
            for binding in bindings:
                work.charge(category="semantic_steps")
                evaluations += 1
                source_decision, source_next = reference_step(p, source, request, binding)
                different = source_decision != target_decision
                if not decisions_only:
                    different = different or source_next != machine["observations"][target_next]
                if different:
                    prefix, history = _unwind_switching(parents, (source, target))
                    indices = prefix + [index]
                    used = history + [binding]
                    replay = _reference_replay(
                        p, machine, indices, used, decisions_only=decisions_only, work=work
                    )
                    ensure(replay and not replay[-1]["compared_equal"], "switching replay disagreement")
                    ensure(all(row["compared_equal"] for row in replay[:-1]), "switching replay prefix")
                    return {
                        "equivalent": False,
                        "length": len(indices),
                        "indices": indices,
                        "bindings": used,
                        "trace": replay,
                        "transition_evaluations": evaluations,
                        "visited_pairs": len(parents),
                        **work.report(),
                    }
                pair = (source_next, target_next)
                if pair not in parents:
                    parents[pair] = ((source, target), index, binding)
                    queue.append(pair)
    return {
        "equivalent": True,
        "length": None,
        "indices": None,
        "bindings": None,
        "trace": None,
        "transition_evaluations": evaluations,
        "visited_pairs": len(parents),
        **work.report(),
    }
