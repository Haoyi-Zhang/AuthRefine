"""Finite reviews of externally specified stateful authorization requirements.

The requirements come from RFCs; models, candidate mappings and defects are
owned. This does not execute an OAuth server, perform requests, or find exploits.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path

from checker import ensure
from compiler import compile_policy
from extensions import binding_profile, _reference_replay
from language import normalize, pretty
from oracle import all_bindings, product_oracle
from symbolic_profile import profile as symbolic_profile


def field(kind, name=None, alias=None, negated=False):
    return {"field": kind, "negated": negated, **({"name": name} if alias is None else {"alias": alias})}


def state(name, value):
    return {"field": "state", "name": name, "value": value}


def rule(guard, updates=None, decision="allow"):
    return {"guard": guard, "updates": updates or [], "decision": decision}


def examples():
    code = {"principals": ["client-a", "client-b"], "resources": ["redirect-a", "redirect-b"],
            "actions": ["redeem"], "roles": [], "members": [], "state": [["used", False]],
            "aliases": [{"name": "client", "kind": "principal", "candidates": ["client-a", "client-b"]},
                        {"name": "redirect", "kind": "resource", "candidates": ["redirect-a", "redirect-b"]}],
            "rules": [rule([field("principal", alias="client"), field("resource", alias="redirect"),
                            state("used", False)], [{"name": "used", "value": True}])]}
    revocation = {"principals": ["authenticated-client"],
                  "resources": ["token-a", "token-b", "token-c"], "actions": ["revoke", "use"],
                  "roles": [], "members": [], "state": [["revocation_seen", False]],
                  "aliases": [{"name": "same-grant", "kind": "resource", "candidates": ["token-b", "token-c"]}],
                  "rules": [
                      rule([field("action", "revoke"), field("resource", "token-a")],
                           [{"name": "revocation_seen", "value": True}]),
                      rule([field("action", "use"), state("revocation_seen", True), field("resource", "token-a")], decision="deny"),
                      rule([field("action", "use"), state("revocation_seen", True), field("resource", alias="same-grant")], decision="deny"),
                      rule([field("action", "use")])]}
    for name, policy, binding, provenance in (
        ("authorization-code", code, {"client": "client-a", "redirect": "redirect-a"},
         {"url": "https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2",
          "requirement": "One-use authorization code bound to client identifier and redirect URI",
          "decoder": "Model exporter supplies the consumed flag for one unexpired code; client authentication/URI parsing already resolved",
          "candidates": "Two unresolved client-record mappings and two redirect-record mappings supplied as review hypotheses, not source-text ambiguity",
          "excluded": "Expiry, PKCE, cryptography, HTTP errors, concurrent redemption, and the recommended token revocation after replay"}),
        ("token-revocation", revocation, {"same-grant": "token-b"},
         {"url": "https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1",
          "requirement": "Invalidate the actual token and optionally related tokens under the declared server policy",
          "decoder": "Exporter supplies the revocation record for token-a; one related token is identified by an unresolved same-grant mapping",
          "candidates": "Related token is token-b or token-c under the fixed revoke-related policy; issuer metadata must settle this, not the RFC",
          "excluded": "Authentication, propagation delay, network protocol, arbitrary token population and HTTP 200 versus access denial"})):
        policy = normalize(policy)
        machine = compile_policy(policy, binding)
        yield name, policy, machine, provenance


def product_family(policy, machine):
    """Same-information family BFS: retain every fixed-binding result, no early
    stop after the first failing configuration. Uses the explicit product oracle.
    """
    rows = []
    transitions = 0
    for binding in all_bindings(policy):
        fixed = deepcopy(policy)
        for alias in fixed["aliases"]:
            alias["candidates"] = [binding[alias["name"]]]
        result = product_oracle(normalize(fixed), machine)
        transitions += result["transition_evaluations"]
        indices = None if result["equivalent"] else result["shortest"]["indices"]
        trace = (None if indices is None else
                 _reference_replay(policy, machine, indices, [binding] * len(indices)))
        if indices:
            ensure(all(row["compared_equal"] for row in trace[:-1])
                   and not trace[-1]["compared_equal"], "product fixed-binding replay")
        rows.append({"binding": binding, "equivalent": result["equivalent"],
                     "length": None if result["equivalent"] else result["shortest"]["length"],
                     "indices": indices, "trace": trace})
    return {"profiles": rows, "transition_evaluations": transitions}


def signature(result):
    return [(r["binding"], r["equivalent"], r["length"]) for r in result["profiles"]]


def compare(policy, machine):
    local, product, symbolic = binding_profile(policy, machine), product_family(policy, machine), symbolic_profile(policy, machine)
    ensure(signature(local) == signature(product) == signature(symbolic), "complete-family comparator disagreement")
    return {"target_distance_profile": local, "parametric_product_bfs": product,
            "symbolic_profile": symbolic}


def run(output, tex):
    ensure(not output.exists(), "fresh output required")
    records, lines = [], []
    for name, policy, machine, provenance in examples():
        correct = compare(policy, machine)
        broken = deepcopy(machine)
        # A benign owned state-update fault; no network/service is contacted.
        first = broken["initial"]
        for edge in broken["transitions"][first]:
            if edge[0] == "allow":
                edge[1] = first
        faulty = compare(policy, broken)
        repaired = compare(policy, deepcopy(machine))
        ensure(signature(correct["symbolic_profile"]) == signature(repaired["symbolic_profile"]), "repair changed family")
        ensure(faulty["target_distance_profile"]["classification"] == "none", "lost state update must implement no declared interpretation")
        if name == "token-revocation":
            ensure(correct["target_distance_profile"]["strata"] == {"infinity": 1, "2": 1}, "revocation horizon")
        records.append({"id": name, "provenance": provenance, "policy": policy,
                        "canonical_sentence": pretty(policy), "machine": machine,
                        "state_update_fault_machine": broken, "correct": correct, "fault": faulty,
                        "repair": repaired,
                        "review_action": "Restore the state-update edge when no binding matches; settle issuer record mapping separately when a proper family matches. Do not shrink the admitted family to hide a failure."})
        p = correct["target_distance_profile"]
        lines.append(f"{name.replace('-', ' ')} & {p['bindings']} & {p['matching_bindings']} & "
                     + ", ".join(f"{k}: {v}" for k, v in sorted(p["strata"].items())) + r"\\")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"status": "PASS", "scope": "Normative-source finite models, not independently observed implementation reviews",
                                  "records": records}, indent=2) + "\n", encoding="utf-8", newline="\n")
    tex.write_text("% Generated by stateful_review.py; length: binding count.\n" + "\n".join(lines)
                   + "\n\\bottomrule\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": "PASS", "policies": len(records), "all_three_family_outputs_agree": True}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tex", required=True, type=Path)
    args = parser.parse_args()
    run(args.output, args.tex)
