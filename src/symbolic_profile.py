"""Complete fixed-binding failure families using existing finite-domain diagrams.

This is a same-information symbolic baseline for the explicit binding profile,
not a new symbolic-equivalence algorithm. It partitions bindings by the first
bad BFS cell and retains one fixed-binding replay per materialized member.
"""
from collections import deque
from itertools import product
from checker import ensure, inspect_policy, inspect_machine
from extensions import _reference_replay
from symbolic import Diagram, cell


def profile(policy, machine, family_limit=65536, node_limit=100000,
            operation_limit=2000000):
    inspect_policy(policy)
    inspect_machine(policy, machine, compare_initial=False)
    ensure(type(family_limit) is int and family_limit > 0, "symbolic family limit", "inconclusive")
    ensure(type(node_limit) is int and node_limit >= 2, "symbolic node limit", "inconclusive")
    ensure(type(operation_limit) is int and operation_limit >= 0, "symbolic operation limit", "inconclusive")
    cardinality = 1
    for alias in policy["aliases"]:
        cardinality *= len(alias["candidates"])
        ensure(cardinality <= family_limit, "symbolic profile materialization cap", "inconclusive")
    diagram = Diagram(policy["aliases"], node_limit, operation_limit)
    source_initial = sum(int(v) << i for i, (_, v) in enumerate(policy["state"]))
    initial_bad = source_initial != machine["observations"][machine["initial"]]
    paths = {machine["initial"]: []}
    queue = deque(paths)
    while queue:
        q = queue.popleft()
        for index, (_, successor) in enumerate(machine["transitions"][q]):
            if successor not in paths:
                paths[successor] = paths[q] + [index]
                queue.append(successor)
    seen_bad, cells, partitions = diagram.false, 0, []
    if initial_bad:
        seen_bad = diagram.true
        partitions.append({"root": diagram.true, "indices": [], "length": 0})
    else:
        for q, prefix in paths.items():
            for index, request in enumerate(machine["alphabet"]):
                function = cell(diagram, policy, machine["observations"][q], request)
                decision, successor = machine["transitions"][q][index]
                expected = (decision, machine["observations"][successor])
                cache = {}
                def mismatch(root):
                    if root in cache:
                        return cache[root]
                    level, value = diagram.nodes[root]
                    result = (diagram.leaf(value != expected) if level is None else
                              diagram.node(level, [mismatch(child) for child in value]))
                    cache[root] = result
                    return result
                bad = mismatch(function)
                # First-cell regions are disjoint. BFS order makes every member
                # of one region share this shortest target-prefix length.
                fresh = diagram.ite(seen_bad, diagram.false, bad)
                if fresh != diagram.false:
                    partitions.append({"root": fresh, "indices": prefix + [index],
                                       "length": len(prefix) + 1})
                seen_bad = diagram.ite(seen_bad, diagram.true, bad)
                cells += 1
    good = diagram.ite(seen_bad, diagram.false, diagram.true)
    rows, strata = [], {}
    for values in product(*(a["candidates"] for a in policy["aliases"])):
        binding = dict(zip((a["name"] for a in policy["aliases"]), values))
        selected = [part for part in partitions if diagram.evaluate(part["root"], binding)]
        ensure(len(selected) <= 1, "symbolic disjoint failure regions")
        equivalent = bool(diagram.evaluate(good, binding))
        ensure(equivalent == (not selected), "symbolic family complement")
        if selected:
            part = selected[0]
            indices = part["indices"]
            trace = _reference_replay(policy, machine, indices, [binding] * len(indices))
            if not initial_bad:
                ensure(all(r["compared_equal"] for r in trace[:-1])
                       and trace and not trace[-1]["compared_equal"], "symbolic fixed-binding replay")
            row = {"binding": binding, "equivalent": False, "length": part["length"],
                   "indices": indices, "trace": trace}
        else:
            row = {"binding": binding, "equivalent": True, "length": None,
                   "indices": None, "trace": None}
        rows.append(row)
        key = "infinity" if equivalent else str(row["length"])
        strata[key] = strata.get(key, 0) + 1
    matching = sum(r["equivalent"] for r in rows)
    return {"classification": "all" if matching == len(rows) else "some" if matching else "none",
            "bindings": len(rows), "matching_bindings": matching, "strata": strata,
            "profiles": rows, "symbolic": {"nodes": diagram.nodes, "good_root": good,
                "first_bad_cell_regions": partitions, "cells": cells,
                "conditional_operations": diagram.operations,
                "alias_order": [a["name"] for a in policy["aliases"]]}}
