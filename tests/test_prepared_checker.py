"""Portable finite regression: literal Cartesian oracle, no saved-run inputs."""
import copy
import io
import itertools
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import checker
import compiler
import language
from cases import blank, curated, generated, width_case, negative_case, NEGATIVE_KINDS
from oracle import product_oracle
import symbolic

FIELDS = ("principal", "resource", "action")
KINDS = ("principal", "resource", "action", "role")


def bindings(policy):
    names = [a["name"] for a in policy["aliases"]]
    for values in itertools.product(*(a["candidates"] for a in policy["aliases"])):
        yield dict(zip(names, values))


def literal_atom(policy, bits, request, binding, atom):
    if atom["field"] == "state":
        index = [row[0] for row in policy["state"]].index(atom["name"])
        return bits[index] == atom["value"]
    value = atom["name"] if "name" in atom else binding[atom["alias"]]
    if atom["field"] == "role":
        truth = any(u == request[0] and r == value for u, r in policy["members"])
    else:
        truth = request[FIELDS.index(atom["field"])] == value
    return truth != atom["negated"]


def literal_step(policy, state, request, binding):
    """Evaluate typed finite data using Boolean tuples and literal scans."""
    names = tuple(row[0] for row in policy["state"])
    bits = tuple(bool(state & (1 << i)) for i in range(len(names)))
    enabled = [rule for rule in policy["rules"]
               if all(literal_atom(policy, bits, request, binding, atom)
                      for atom in rule["guard"])]
    if not enabled:
        return "deny", state
    selected = enabled[0]
    next_bits = list(bits)
    for effect in selected["updates"]:
        value = effect.get("value")
        if "value" not in effect:
            value = bits[names.index(effect["from"])] != effect["negated"]
        next_bits[names.index(effect["name"])] = value
    return selected["decision"], sum(1 << i for i, value in enumerate(next_bits) if value)


def literal_support(policy, state, request):
    bits = tuple(bool(state & (1 << i)) for i in range(len(policy["state"])))
    viable = [rule for rule in policy["rules"]
              if all(literal_atom(policy, bits, request, {}, atom)
                     for atom in rule["guard"] if "alias" not in atom)]
    return sorted({atom["alias"] for rule in viable for atom in rule["guard"] if "alias" in atom})


def capture(call):
    try:
        return {"result": call()}
    except (ValueError, TypeError, KeyError, IndexError, OverflowError) as error:
        return {"error": type(error).__name__, "message": str(error), "attributes": vars(error)}


def rejected(message, kind, **attributes):
    return {"error": "Rejected", "message": message, "attributes": dict(kind=kind, **attributes)}


def literal_report(policy, machine, certificate, budget=2_000_000):
    """Oracle for structurally valid closed regions; validates no shared code."""
    initial = sum(1 << i for i, (_, value) in enumerate(policy["state"]) if value)
    if machine["observations"][machine["initial"]] != initial:
        return rejected("initial observation mismatch", "mismatch")
    count, maximum, cells = 0, 0, []
    choices = {a["name"]: a["candidates"] for a in policy["aliases"]}
    filler = {name: candidates[0] for name, candidates in choices.items()}
    for q in certificate["reachable"]:
        state = machine["observations"][q]
        for index, request in enumerate(machine["alphabet"]):
            deps = literal_support(policy, state, request)
            maximum = max(maximum, len(deps))
            projections = list(itertools.product(*(choices[name] for name in deps)))
            if count + len(projections) > budget:
                return rejected("checker obligation budget", "inconclusive")
            edge = machine["transitions"][q][index]
            for values in projections:
                count += 1
                binding = dict(filler, **dict(zip(deps, values)))
                if literal_step(policy, state, request, binding) != (edge[0], machine["observations"][edge[1]]):
                    return rejected(f"refinement mismatch at state {q}, request {index}", "mismatch",
                                    evaluations=count, maximum_width=maximum)
            cells.append({"state": q, "request": index, "support": deps, "bindings": len(projections)})
    return {"result": {"accepted": True, "states": len(certificate["reachable"]),
                       "local_cells": len(cells), "binding_evaluations": count,
                       "maximum_width": maximum, "cells": cells}}


def multiwrite_policies():
    for count in (2, 3):
        for sources in itertools.permutations(range(count)):
            for negations in itertools.product((False, True), repeat=count):
                p = blank()
                p["state"] = [[f"b{i}", bool(i % 2)] for i in range(count)]
                p["roles"], p["members"] = ["r", "s"], [["u", "r"]]
                p["aliases"] = [{"name": "z", "kind": "role", "candidates": ["r", "s"]}]
                updates = [{"name": f"b{i}", "from": f"b{source}", "negated": negations[i]}
                           for i, source in enumerate(sources)]
                p["rules"] = [{"decision": "allow",
                               "guard": [{"field": "role", "alias": "z", "negated": polarity}],
                               "updates": copy.deepcopy(updates)} for polarity in (False, True)]
                yield language.normalize(p)


def all_sort_policies():
    for mask in range(4):
        for negated in (False, True):
            p = blank()
            p["principals"], p["resources"], p["actions"], p["roles"] = (
                ["u", "v"], ["o", "p"], ["a", "b"], ["r", "s"])
            p["members"] = [["u", role] for i, role in enumerate(p["roles"]) if mask & (1 << i)]
            p["state"] = [["x", False], ["y", True]]
            p["aliases"] = [{"name": f"z{i}", "kind": kind, "candidates": p[key][:]}
                            for i, (kind, key) in enumerate(zip(KINDS,
                                ("principals", "resources", "actions", "roles")))]
            guard = [{"field": kind, "alias": f"z{i}", "negated": negated}
                     for i, kind in enumerate(KINDS)]
            p["rules"] = [{"decision": "allow", "guard": guard, "updates": [
                {"name": "x", "from": "y", "negated": True},
                {"name": "y", "from": "x", "negated": False}]},
                {"decision": "deny", "guard": [], "updates": []}]
            yield language.normalize(p)


def fixtures():
    return (curated() + [(f"generated-{i}", generated(i)) for i in range(96)]
            + [(f"width-{i}", width_case(i)) for i in range(1, 9)]
            + [(f"multiwrite-{i}", p) for i, p in enumerate(multiwrite_policies())]
            + [(f"all-sort-{i}", p) for i, p in enumerate(all_sort_policies())])


def read_owned_json(text, module=checker):
    # No filesystem destination: exercise the real bounded decoder on owned bytes.
    with patch.object(module.Path, "open", return_value=io.BytesIO(text.encode("utf-8"))):
        return module.load("owned-memory-fixture.json")


class PreparedCheckerTests(unittest.TestCase):
    def test_complete_steps_against_literal_cartesian_oracle(self):
        tuples = 0
        for name, p in fixtures():
            snapshot = copy.deepcopy(p)
            for state in range(1 << len(p["state"])):
                for request in itertools.product(p["principals"], p["resources"], p["actions"]):
                    for binding in bindings(p):
                        expected = literal_step(p, state, request, binding)
                        with self.subTest(fixture=name, state=state, request=request, binding=binding):
                            self.assertEqual(checker.reference_step(p, state, request, binding), expected)
                            self.assertEqual(compiler.step(p, state, request, binding), expected)
                        tuples += 1
            self.assertEqual(p, snapshot)
        self.assertGreater(tuples, 10000)
        self.assertLessEqual(tuples, 50000)

    def test_complete_reports_order_caps_and_mismatch_counters(self):
        for name, p in fixtures():
            machine = compiler.compile_policy(p)
            region = compiler.certificate(machine)
            for certificate in (region, {"reachable": list(reversed(region["reachable"]))},
                                {"reachable": list(range(len(machine["observations"])))}):
                baseline = literal_report(p, machine, certificate)
                needed = (baseline.get("result") or baseline["attributes"]).get("binding_evaluations",
                          baseline.get("attributes", {}).get("evaluations", 1))
                for budget in sorted({0, 1, max(0, needed - 1), needed, needed + 1, 50000}):
                    with self.subTest(fixture=name, region=certificate, budget=budget):
                        self.assertEqual(capture(lambda: checker.verify(p, machine, certificate, budget)),
                                         literal_report(p, machine, certificate, budget))
            bad = copy.deepcopy(machine)
            first = bad["initial"]
            bad["transitions"][first][0][0] = (
                "deny" if bad["transitions"][first][0][0] == "allow" else "allow")
            self.assertEqual(capture(lambda: checker.verify(p, bad, region)),
                             literal_report(p, bad, region))

    def test_preparation_is_cell_local_without_skipping_bindings(self):
        p = width_case(3)
        m = compiler.compile_policy(p)
        c = compiler.certificate(m)
        calls = []
        step = checker._reference_step_prepared
        def observe(*args):
            calls.append(args)
            return step(*args)
        with patch.object(checker, "_reference_step_prepared", side_effect=observe):
            report = checker.verify(p, m, c)
        self.assertEqual(len(calls), report["binding_evaluations"])
        self.assertEqual(len({id(row[5]) for row in calls}), 1)
        self.assertIsInstance(calls[0][5], frozenset)
        self.assertEqual(len({id(row[4]) for row in calls}), report["local_cells"])
        self.assertEqual(len({id(row[6]) for row in calls}), report["local_cells"])
        for group in (calls[i:i + 2] for i in range(0, len(calls), 2)):
            self.assertIs(group[0][4], group[1][4])
            self.assertIs(group[0][6], group[1][6])
            self.assertNotEqual(group[0][3], group[1][3])
            self.assertEqual(group[0][4], group[1][4])
        with patch.object(checker, "_reference_step_prepared", side_effect=observe):
            before = len(calls)
            self.assertEqual(capture(lambda: checker.verify(p, m, c, 0)),
                             rejected("checker obligation budget", "inconclusive"))
            self.assertEqual(len(calls), before)

    def test_public_step_retains_full_scan_and_error_precedence(self):
        p = blank()
        p["rules"] = [{"decision": "allow", "guard": [], "updates": []},
                      {"decision": "deny", "guard": [
                          {"field": "role", "alias": "missing", "negated": False}], "updates": []}]
        with self.assertRaisesRegex(KeyError, "missing"):
            checker.reference_step(p, 0, ["u", "o", "a"], {})
        p["rules"][1]["guard"] = [{"field": "principal", "name": "v", "negated": False},
                                {"field": "state", "name": "absent", "value": False}]
        with self.assertRaisesRegex(KeyError, "absent"):
            checker.reference_step(p, 0, ["u", "o", "a"], {})
        p["state"], p["members"] = [["b", False]], [[[]]]
        with self.assertRaises(TypeError) as error:
            checker.reference_step(p, None, None, {})
        self.assertIn("unsupported operand", str(error.exception))
        p["state"] = []
        with self.assertRaisesRegex(TypeError, "unhashable"):
            checker.reference_step(p, 0, None, {})

    def test_successive_mutation_does_not_share_context_or_modify_inputs(self):
        p = dict(curated())["meaningful-reference-choice"]
        for edit in ("members", "state", "requests", "aliases"):
            if edit == "members":
                p["members"] = [["u", "r"], ["u", "s"]]
            elif edit == "state":
                p["state"][0][1] = True
            elif edit == "requests":
                p["principals"] = ["u", "v"]
            else:
                p["aliases"][0]["candidates"] = ["s"]
            p = language.normalize(p)
            m = compiler.compile_policy(p)
            c = compiler.certificate(m)
            snapshot = copy.deepcopy((p, m, c))
            self.assertEqual(capture(lambda: checker.verify(p, m, c)), literal_report(p, m, c))
            self.assertEqual((p, m, c), snapshot)

    def test_invalid_certificates_and_initial_boundary(self):
        for kind in NEGATIVE_KINDS:
            p, m, c = negative_case(kind)
            answer = capture(lambda: read_owned_json(c) if isinstance(c, str) else checker.verify(p, m, c))
            self.assertEqual(answer["error"], "Rejected")
            self.assertEqual(answer["attributes"]["kind"],
                             "mismatch" if kind == "wrong-initial-observation" else "invalid")
        p = language.normalize(blank())
        m = compiler.compile_policy(p)
        c = compiler.certificate(m)
        for budget in (-1, False, True, 1.0, None):
            self.assertEqual(capture(lambda: checker.verify(p, m, c, budget)),
                             rejected("checker obligation budget", "inconclusive"))
        for text in ('{"reachable":[],"reachable":[0]}', '{"x":NaN}', '{"x":Infinity}'):
            self.assertEqual(capture(lambda: read_owned_json(text))["error"], "Rejected")

    def test_unreachable_closed_superset_is_not_trace_counterexample(self):
        p = blank()
        p["state"] = [["b", False]]
        p["rules"] = [{"decision": "allow", "guard": [], "updates": []}]
        p = language.normalize(p)
        m = compiler.compile_policy(p)
        m["transitions"][0][0][0] = "deny"
        self.assertEqual(capture(lambda: checker.verify(p, m, {"reachable": [m["initial"]]})),
                         literal_report(p, m, {"reachable": [m["initial"]]}))
        self.assertEqual(capture(lambda: checker.verify(p, m, {"reachable": [0, 1]})),
                         literal_report(p, m, {"reachable": [0, 1]}))
        self.assertTrue(product_oracle(p, m)["equivalent"])

    def test_unchanged_product_symbolic_diagnostic_and_replay_agree(self):
        for name, p in curated() + [(f"generated-{i}", generated(i)) for i in range(32)]:
            m = compiler.compile_policy(p)
            answer = capture(lambda: checker.verify(p, m, compiler.certificate(m)))
            accepted = "result" in answer
            product = product_oracle(p, m)
            diagram = symbolic.check(p, m)
            diagnostic = compiler.diagnose(p, m)
            self.assertEqual(accepted, product["equivalent"])
            self.assertEqual(accepted, diagram["equivalent"])
            self.assertEqual(accepted, diagnostic["equivalent"])
            if not accepted:
                self.assertEqual(diagnostic["length"], product["shortest"]["length"])
                self.assertEqual(diagnostic["length"], diagram["length"])
                trace = compiler.replay(p, m, diagnostic["indices"], diagnostic["binding"])
                self.assertEqual(trace, diagnostic["trace"])
                self.assertTrue(all(row["source"] == row["target"] for row in trace[:-1]))
                self.assertNotEqual(trace[-1]["source"], trace[-1]["target"])


if __name__ == "__main__":
    unittest.main()
