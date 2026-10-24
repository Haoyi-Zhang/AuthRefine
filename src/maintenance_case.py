"""Source-bound node-casbin batch-add model; never imports/runs upstream code.

The tuple-store operations below are an owned, bounded adaptation of the
Apache-2.0 source identified in external_inputs/node-casbin/NOTICE.md.
Boolean outputs encode API returns, not authorization judgments.
"""
import argparse
from itertools import combinations
import json
from pathlib import Path
import re

from checker import ensure, reference_step, verify_reachable
from compiler import alphabet, compile_policy, reachable
from language import normalize, parse, pretty
from stateful_review import compare, signature

INPUT = Path(__file__).resolve().parents[1] / "external_inputs" / "node-casbin"
SHA = "d8a7cbabb4de50f04261c04eb7551c1f25e13fc7"


def inputs(root=INPUT):
    """Admit only the two selected literal-array tests and the frozen p store."""
    text = (root / "test/managementAPI.test.ts").read_text(encoding="utf-8")
    ensure("beforeEach(async () => {\n  e = await newEnforcer('examples/rbac_model.conf', 'examples/rbac_policy.csv');\n});" in text,
           "unrecognized upstream initializer")
    initial = []
    for line in (root / "examples/rbac_policy.csv").read_text(encoding="utf-8").splitlines():
        fields = [v.strip() for v in line.split(",")]
        if fields[0] == "p":
            ensure(len(fields) == 4, "unsupported policy row")
            initial.append(tuple(fields[1:]))
        else:
            ensure(fields == ["g", "alice", "data2_admin"], "unsupported frozen role row")
    cases = []
    for title in ("addPoliciesEx", "addPoliciesEx - all existing rules"):
        match = re.search(r"test\('" + re.escape(title) + r"', async \(\) => \{\n(.*?)\n\}\);", text, re.S)
        ensure(match is not None, "missing selected upstream test")
        block = match.group(1)
        array = re.search(r"const rules = \[\n(.*?)\n  \];", block, re.S)
        ensure(array is not None, "unsupported upstream batch")
        rows = []
        for line in array.group(1).splitlines():
            row = re.fullmatch(r"\s*\['([^']+)', '([^']+)', '([^']+)'\],\s*// (?:already exists|new rule)", line)
            ensure(row is not None, "nonliteral/unsupported upstream row")
            rows.append(row.groups())
        ensure("const added = await e.addPoliciesEx(rules);" in block, "different upstream operation")
        returned = re.findall(r"expect\(added\)\.toBe\((true|false)\);", block)
        ensure(len(returned) == 1, "missing upstream return assertion")
        checks = [(tuple(m[:3]), m[3] == "true") for m in re.findall(
            r"expect\(await e\.hasPolicy\('([^']+)', '([^']+)', '([^']+)'\)\)\.toBe\((true|false)\);", block)]
        ensure(block.count("expect(") == 1 + len(checks), "unparsed upstream expectation")
        ensure(len(rows) == len(set(rows)), "duplicate batch rows are outside admission")
        cases.append({"title": title, "batch": rows, "returned": returned[0] == "true", "checks": checks})
    universe = sorted(set(initial).union(*(set(c["batch"]) for c in cases)))
    ensure(len(initial) == 4 and len(universe) == 6 and [len(c["checks"]) for c in cases] == [4, 0],
           "changed selected source domain")
    return frozenset(initial), universe, cases


def decode(store, universe):
    """Complete six-row membership decoder, rejecting unrepresented rows."""
    ensure(isinstance(store, frozenset) and store <= set(universe), "store outside admitted row universe")
    return {f"row-{i}": row in store for i, row in enumerate(universe)}


def encode(store, universe):
    return sum(int(v) << i for i, v in enumerate(decode(store, universe).values()))


def stores(universe):
    return [frozenset(s) for k in range(len(universe) + 1) for s in combinations(universe, k)]


def step(store, action, mode, universe, cases):
    """Sequential, no-adapter/no-watcher tuple-store API, reviewed from source."""
    decode(store, universe)
    ensure(mode in ("legacy", "ex"), "unsupported API mode")
    if action.startswith("has-row-"):
        index = int(action[len("has-row-"):])
        ensure(0 <= index < len(universe), "unrepresented query")
        return universe[index] in store, store
    ensure(action in ("add-mixed", "add-existing"), "unrepresented command")
    batch = cases[action == "add-existing"]["batch"]
    # Both selected batches contain distinct rows; no priority column is present.
    if mode == "legacy":
        if any(row in store for row in batch):
            return False, store
        return True, store.union(batch)
    new = frozenset(row for row in batch if row not in store)
    return bool(new), store.union(new)


def policy(mode, initial, universe, cases):
    rules = []
    def action(name):
        return {"field": "action", "name": name, "negated": False}
    def bit(i, value):
        return {"field": "state", "name": f"row-{i}", "value": value}
    for command, case in zip(("add-mixed", "add-existing"), cases):
        indices = sorted(universe.index(row) for row in case["batch"])
        updates = [{"name": f"row-{i}", "value": True} for i in indices]
        guards = ([[bit(i, False) for i in indices]] if mode == "legacy" else
                  [[bit(i, False)] for i in indices])
        for guard in guards:
            rules.append({"decision": "allow", "guard": [action(command)] + guard, "updates": updates})
    for i in range(len(universe)):
        rules.append({"decision": "allow", "guard": [action(f"has-row-{i}"), bit(i, True)], "updates": []})
    return normalize({"principals": ["caller"], "resources": ["policy-store"],
                      "actions": ["add-mixed", "add-existing"] + [f"has-row-{i}" for i in range(len(universe))],
                      "roles": [], "members": [], "state": [[k, v] for k, v in decode(initial, universe).items()],
                      "aliases": [], "rules": rules})


def export(mode, p, initial, universe, cases):
    """Enumerate the owned store model, not the CNL compiler's transition table."""
    domain = sorted(stores(universe), key=lambda s: encode(s, universe), reverse=True)
    positions = {s: q for q, s in enumerate(domain)}
    table = []
    for store in domain:
        row = []
        for request in alphabet(p):
            returned, post = step(store, request[2], mode, universe, cases)
            row.append(["allow" if returned else "deny", positions[post]])
        table.append(row)
    return {"state_names": [name for name, _ in p["state"]], "alphabet": alphabet(p),
            "initial": positions[initial], "observations": [encode(s, universe) for s in domain],
            "transitions": table}


def study():
    initial, universe, cases = inputs()
    source_assertions = []
    for case in cases:
        returned, post = step(initial, "add-existing" if "all existing" in case["title"] else "add-mixed",
                              "ex", universe, cases)
        ensure(returned == case["returned"], "source return assertion disagrees")
        ensure(all((row in post) == expected for row, expected in case["checks"]), "source membership assertion disagrees")
        source_assertions.append({"title": case["title"], "assertions": 1 + len(case["checks"]),
                                  "returned": returned, "post": sorted(post)})
    policies, machines, counts = {}, {}, {}
    for mode in ("legacy", "ex"):
        p = policy(mode, initial, universe, cases)
        ensure(parse(pretty(p)) == p, "CNL round trip")
        m = export(mode, p, initial, universe, cases)
        ensure(m == compile_policy(p), "compiler disagrees with source-bound store export")
        comparisons = 0
        for store in stores(universe):
            valuation = encode(store, universe)
            decoded = decode(store, universe)
            restored = frozenset(row for i, row in enumerate(universe) if decoded[f"row-{i}"])
            ensure(restored == store, "complete decoder round trip")
            for request in alphabet(p):
                returned, post = step(store, request[2], mode, universe, cases)
                ensure(reference_step(p, valuation, request, {}) == ("allow" if returned else "deny", encode(post, universe)),
                       "store/CNL one-step mismatch")
                comparisons += 1
        policies[mode], machines[mode] = p, m
        counts[mode] = {"one_step_tuples": comparisons, "states": len(m["observations"]),
                        "reachable_states": len(reachable(m)), "actions": len(p["actions"])}
    comparisons = []
    for spec, candidate in (("legacy", "legacy"), ("ex", "ex"), ("legacy", "ex"), ("ex", "legacy")):
        outputs = compare(policies[spec], machines[candidate])
        direct = verify_reachable(policies[spec], machines[candidate])
        expected = spec == candidate
        ensure(direct["equivalent"] == expected, "API comparison verdict")
        ensure(signature(outputs["target_distance_profile"])[0][1:] == (expected, None if expected else 1),
               "API comparison shortest length")
        comparisons.append({"specification": spec, "candidate": candidate,
                            "outputs": outputs, "list_free": direct})
    # Downstream consumer: after mixed add, the newly added Jack row is visible.
    _, old = step(initial, "add-mixed", "legacy", universe, cases)
    _, new = step(initial, "add-mixed", "ex", universe, cases)
    jack = universe.index(("jack", "data4", "read"))
    old_answer, _ = step(old, f"has-row-{jack}", "legacy", universe, cases)
    new_answer, _ = step(new, f"has-row-{jack}", "ex", universe, cases)
    ensure(not old_answer and new_answer, "maintenance consumer")
    return {"source_commit": SHA, "release": "v5.46.0", "scope": "source-bound owned tuple-store execution; no upstream engine execution",
            "row_universe": universe, "initial_store": sorted(initial), "source_test_data": cases,
            "source_assertions": source_assertions,
            "decoder_states": len(stores(universe)), "modes": counts,
            "policies": policies, "machines": machines, "comparisons": comparisons,
            "consumer": {"word": ["add-mixed", f"has-row-{jack}"], "legacy_membership": old_answer,
                         "ex_membership": new_answer, "meaning": "hasPolicy membership, not an Enforce call"}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    ensure(not args.output.exists(), "fresh output required")
    result = study()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "PASS", "source_assertions": sum(r["assertions"] for r in result["source_assertions"]),
                      "one_step_tuples": sum(r["one_step_tuples"] for r in result["modes"].values()),
                      "complete_family_comparisons": len(result["comparisons"]), "native_engine_executed": False}))
