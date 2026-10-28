"""Finite refinement on an explicit regular component-caller protocol.

Protocol-disabled cells are not checked or called. A missing machine edge on a
reachable, protocol-enabled cell is INCONCLUSIVE, never replaced by a denial.
This is not an unconditional external-API trace refinement result.
"""
from collections import deque

from checker import Rejected, inspect_policy, inspect_machine, reference_step


def verify_protocol(policy, machine, protocol, budget=2_000_000):
    if type(budget) is not int or budget < 0:
        raise Rejected("invalid protocol work envelope")
    inspect_policy(policy)
    if policy["aliases"]:
        raise Rejected("protocol checker currently requires a fixed interpretation", "unsupported")
    if not isinstance(machine, dict) or not isinstance(machine.get("transitions"), list):
        raise Rejected("protocol machine needs explicit rows")
    filled = []
    for state, row in enumerate(machine["transitions"]):
        if not isinstance(row, list):
            raise Rejected("invalid partial machine row")
        filled.append([["deny", state] if edge is None else edge for edge in row])
    # This copy is used for schema checking only, never semantic traversal.
    inspect_machine(policy, {**machine, "transitions": filled}, compare_initial=False)
    if (not isinstance(protocol, dict) or set(protocol) != {"initial", "transitions"}
            or not isinstance(protocol["transitions"], list) or not 1 <= len(protocol["transitions"]) <= 16
            or type(protocol["initial"]) is not int or not 0 <= protocol["initial"] < len(protocol["transitions"])):
        raise Rejected("invalid finite caller protocol")
    for row in protocol["transitions"]:
        if not isinstance(row, list) or len(row) != len(machine["alphabet"]):
            raise Rejected("caller protocol alphabet differs")
        if any(value is not None and (type(value) is not int or not 0 <= value < len(protocol["transitions"])) for value in row):
            raise Rejected("caller protocol destination is invalid")
    initial_source = sum(1 << i for i, (_, value) in enumerate(policy["state"]) if value)
    initial = (initial_source, machine["initial"], protocol["initial"])
    if machine["observations"][initial[1]] != initial_source:
        return {"status": "mismatch", "accepted": False, "length": 0, "trace": [], "reason": "initial observation differs"}
    waiting, parents = deque([initial]), {initial: None}
    work, checked, missing_excluded = 0, 0, 0
    charge_per_cell = 2 + sum(1 + len(rule["guard"]) + len(rule["updates"]) for rule in policy["rules"])
    while waiting:
        source_state, target_state, protocol_state = current = waiting.popleft()
        for index, request in enumerate(machine["alphabet"]):
            next_protocol = protocol["transitions"][protocol_state][index]
            if next_protocol is None:
                missing_excluded += int(machine["transitions"][target_state][index] is None)
                continue
            if work + charge_per_cell > budget:
                raise Rejected("protocol refinement work exhausted", "inconclusive")
            work += charge_per_cell
            target_edge = machine["transitions"][target_state][index]
            if target_edge is None:
                raise Rejected("missing machine edge on an admitted component trace", "inconclusive")
            source_result = reference_step(policy, source_state, request, {})
            target_result = (target_edge[0], machine["observations"][target_edge[1]])
            checked += 1
            step = {"request": request, "protocol_state": protocol_state,
                    "source": list(source_result), "target": list(target_result)}
            if source_result != target_result:
                prefix, cursor = [], current
                while parents[cursor] is not None:
                    predecessor, earlier = parents[cursor]
                    prefix.append(earlier)
                    cursor = predecessor
                prefix.reverse()
                trace = prefix + [step]
                return {"status": "mismatch", "accepted": False, "length": len(trace), "trace": trace,
                        "checked_cells": checked, "work_operations": work,
                        "scope": "given regular component-caller protocol and fixed interpretation"}
            following = (source_result[1], target_edge[1], next_protocol)
            if following not in parents:
                parents[following] = (current, step)
                waiting.append(following)
    if checked == 0:
        raise Rejected("caller protocol admits no checked component event", "inconclusive")
    return {"status": "equivalent", "accepted": True, "product_states": len(parents),
            "checked_cells": checked, "work_operations": work,
            "protocol_excluded_missing_cells": missing_excluded,
            "scope": "given regular component-caller protocol and fixed interpretation",
            "unconditional_external_api_refinement": False}
