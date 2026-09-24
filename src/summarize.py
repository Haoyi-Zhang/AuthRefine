"""Reconcile complete deterministic case records and write claim-linked tables."""
from __future__ import annotations
import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from cases import generated
from language import pretty

TIMING = {"cpu_seconds", "wall_seconds", "peak_rss_kib"}
def scientific(value):
    if isinstance(value, dict):
        return {k: scientific(v) for k, v in value.items() if k not in TIMING}
    if isinstance(value, list):
        return [scientific(v) for v in value]
    return value

def read_rows(directory):
    paths = sorted((Path(directory) / "chunks").glob("*.jsonl"))
    rows = [json.loads(line) for path in paths for line in path.read_text().splitlines()]
    expected = [f"case-{i:05d}" for i in range(10000)]
    if [r["case"] for r in rows] != expected:
        raise ValueError("missing, repeated, or out-of-order primary cases")
    return rows

def summarize(directory, baseline=None):
    directory = Path(directory)
    rows = read_rows(directory)
    metrics = [json.loads(p.read_text()) for p in sorted((directory / "chunks").glob("*.metrics.json"))]
    if len(metrics) != 40 or sum(x["count"] for x in metrics) != 10000:
        raise ValueError("incomplete chunk metrics")
    theory = json.loads((directory / "theory.json").read_text())
    extensions = json.loads((directory / "extensions.json").read_text())
    adversarial = json.loads((directory / "adversarial.json").read_text())
    exhaustive = json.loads((directory / "exhaustive.json").read_text())
    references = json.loads((directory / "reference_verification.json").read_text())
    pilot = json.loads((directory / "pilot" / "pilot.json").read_text())
    groups = {}
    for kind in ("public", "generated", "width", "chain", "schema-negative"):
        g = [r for r in rows if r["kind"] == kind]
        groups[kind] = {"cases": len(g), "accepted": sum(r["accepted"] for r in g),
            "not_accepted": sum(not r["accepted"] for r in g),
            "global_oracle_cases": sum(r.get("global_oracle_executed", False) for r in g),
            "obligations": sum(r["obligations"] for r in g),
            "cpu_seconds": sum(r["cpu_seconds"] for r in g)}
    g = [r for r in rows if r["kind"] == "generated"]
    structural = Counter(pretty(generated(i)) for i in range(9936))
    syntax_semantics = {str((unique, accepted)): sum(r["syntax_unique"] == unique and r["accepted"] == accepted for r in g)
                        for unique in (False, True) for accepted in (False, True)}
    obligations = (sum(m["obligations"] for m in metrics) + theory["obligations"]
                   + extensions["obligations"] + adversarial["operations"]
                   + exhaustive["operations"] + pilot["obligations"])
    if obligations > 2000000:
        raise ValueError("campaign obligation ceiling exceeded")
    result = {"primary_cases": 10000, "groups": groups,
        "auxiliary_cases": theory["count"], "extension_cases": extensions["count"],
        "extension_obligations": extensions["obligations"],
        "adversarial_cases": adversarial["count"], "adversarial_operations": adversarial["operations"],
        "exhaustive_pairs": exhaustive["policy_machine_pairs"],
        "exhaustive_operations": exhaustive["operations"],
        "reference_verification": {
            "references": references["references"],
            "identifier_distribution": references["identifier_distribution"],
            "unique_publication_identifiers": references["unique_publication_identifiers"],
            "all_references_cited": references["all_references_cited"],
            "citation_occurrences": references["citation_occurrences"],
            "audit_access_date": references["audit_access_date"],
        },
        "pilot_cases": pilot["case_count"],
        "generated_distinct_canonical_asts": len(structural),
        "generated_duplicate_occurrences": 9936 - len(structural),
        "largest_structural_multiplicity": max(structural.values()),
        "generated_syntax_semantics": syntax_semantics,
        "detected_reachable_mutations": sum("mutation" in r for r in rows),
        "witness_lengths": dict(sorted(Counter(r["witness_length"] for r in rows if r.get("witness_length") is not None).items())),
        "primary_cpu_seconds": sum(m["cpu_seconds"] for m in metrics),
        "primary_wall_seconds": sum(m["wall_seconds"] for m in metrics),
        "experimental_cpu_seconds": (sum(m["cpu_seconds"] for m in metrics) + theory["cpu_seconds"]
                                    + extensions["cpu_seconds"] + adversarial["cpu_seconds"]
                                    + exhaustive["cpu_seconds"] + pilot["cpu_seconds"]),
        "peak_rss_kib": max([m["peak_rss_kib"] for m in metrics]
                            + [theory["peak_rss_kib"], extensions["peak_rss_kib"],
                               adversarial["peak_rss_kib"], exhaustive["peak_rss_kib"],
                               pilot["peak_rss_kib"]]),
        "counted_obligations": obligations,
        "all_internal_comparisons_agree": True,
        "public": pilot["public"],
        "symbolic_cases": sum("symbolic" in r for r in rows),
        "symbolic_operations": sum(r["symbolic"]["operations"] for r in rows if "symbolic" in r),
        "symbolic_cells": sum(r["symbolic"]["cells"] for r in rows if "symbolic" in r),
        "symbolic_maximum_nodes": max(r["symbolic"]["nodes"] for r in rows if "symbolic" in r),
        "symbolic_cpu_seconds": sum(r["symbolic"]["cpu_seconds"] for r in rows if "symbolic" in r),
        "reification": dict(Counter(r["reification"] for r in rows if "reification" in r)),
        "extensions": {
            "profiles": {k: extensions["profiles"][k] for k in ("count", "binding_cases", "classifications")},
            "quotients": {k: extensions["quotients"][k] for k in ("count", "coherent", "incoherent", "collapsed")},
            "projections": {k: extensions["projections"][k] for k in ("count", "step_cases", "with_discarded_state")},
            "restricted_families": {k: extensions["restricted_families"][k] for k in ("count", "accepted", "rejected")},
            "switching": {k: extensions["switching"][k] for k in ("count", "full_state_cases", "full_state_uniform", "decision_only_separation")},
        },
        "exhaustive": {
            "policy_semantic_representatives": exhaustive["policy_semantic_representatives"],
            "machines_per_policy": exhaustive["machines_per_policy"],
            "policy_machine_pairs": exhaustive["policy_machine_pairs"],
            "verdicts": exhaustive["verdicts"],
            "shortest_lengths": exhaustive["shortest_lengths"],
            "comparisons": exhaustive["comparisons"],
        },
        "adversarial": {
            "verdicts": adversarial["verdicts"],
            "mutations": adversarial["mutations"],
            "alias_sort_occurrences": adversarial["alias_sort_occurrences"],
            "action_alias_cases": adversarial["action_alias_cases"],
            "length_zero_witnesses": adversarial["length_zero_witnesses"],
            "positive_length_witnesses": adversarial["positive_length_witnesses"],
            "profile_cases": adversarial["profile_cases"],
            "profile_bindings": adversarial["profile_bindings"],
            "step_semantics_comparisons": adversarial["step_semantics_comparisons"],
            "projection_comparisons": adversarial["projection_comparisons"],
            "coherent_quotients": adversarial["coherent_quotients"],
            "collapsed_quotients": adversarial["collapsed_quotients"],
            "boundary_controls": adversarial["boundary_controls"],
        }}
    if baseline is not None:
        prior = read_rows(baseline)
        if scientific(prior) != scientific(rows):
            raise ValueError("primary scientific records differ from baseline")
        for relative in ("theory.json", "extensions.json", "adversarial.json",
                         "exhaustive.json", "reference_verification.json", "pilot/pilot.json"):
            if scientific(json.loads((Path(baseline) / relative).read_text())) != scientific(json.loads((directory / relative).read_text())):
                raise ValueError("auxiliary scientific records differ: " + relative)
        result["baseline_scientific_records_match"] = True
    (directory / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    fields = ["kind", "cases", "accepted", "not_accepted", "global_oracle_cases", "obligations", "cpu_seconds"]
    with (directory / "families.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader()
        for kind, values in groups.items(): writer.writerow({"kind": kind, **values})
    wf = ["aliases", "reachable_states", "requests", "maximum_width", "total_bindings", "local_binding_evaluations", "global_evaluations", "global_complete_work_bound", "global_oracle_executed", "symbolic_operations", "symbolic_nodes"]
    with (directory / "width.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=wf); writer.writeheader()
        for r in rows:
            if r["kind"] == "width":
                values = {k: r[k] for k in wf if not k.startswith("symbolic_")}
                values.update(symbolic_operations=r["symbolic"]["operations"], symbolic_nodes=r["symbolic"]["nodes"])
                writer.writerow(values)
    return result

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("directory"); ap.add_argument("--baseline")
    args = ap.parse_args(); print(json.dumps(summarize(args.directory, args.baseline), indent=2))
