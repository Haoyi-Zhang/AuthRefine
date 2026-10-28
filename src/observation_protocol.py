"""Check finite typed outcomes without erasing exceptions as plain denials.

The caller supplies independent reference and source-projection observations.
Flags retain declared observable effects; the regular protocol ends after one
component invocation. This is not execution of a source service or arbitrary
stateful histories.
"""
from language import normalize
from native_casbin import AdmissionError
from protocol_check import verify_protocol


def encode_observation(flag_names, row):
    """Little-endian packing on the caller's already validated fixed schema."""
    values = {**row["flags"], "result_allowed": row["decision"] == "allow"}
    return sum(1 << index for index, field in enumerate(flag_names) if values[field])


def compare_observations(reference, observed, scope):
    if (type(reference) is not list or type(observed) is not list or not 1 <= len(reference) <= 4096
            or len(reference) != len(observed) or type(scope) is not str):
        raise AdmissionError("finite observation tables have incompatible envelopes", "input_rejected")
    fields = None
    for row in reference + observed:
        if type(row) is not dict or set(row) != {"decision", "flags"} or row["decision"] not in ("allow", "deny") or type(row["flags"]) is not dict:
            raise AdmissionError("observation requires a decision and typed flag record")
        if any(type(key) is not str for key in row["flags"]):
            raise AdmissionError("observation field names must be strings")
        if fields is None:
            fields = sorted(row["flags"])
        if (sorted(row["flags"]) != fields or len(fields) > 6 or "result_allowed" in fields
                or any(type(key) is not str or not key.isidentifier() or type(row["flags"][key]) is not bool for key in row["flags"])):
            raise AdmissionError("observation flags must use one bounded Boolean schema")
    parts = []
    for start in range(0, len(reference), 16):
        expected = reference[start:start + 16]
        actual = observed[start:start + 16]
        names = ["case_" + str(index).zfill(4) for index in range(start, start + len(expected))]
        policy = {"principals": names, "resources": ["boundary"], "actions": ["invoke"], "roles": [], "members": [],
                  "state": [[field, False] for field in [*fields, "result_allowed"]], "aliases": [], "rules": []}
        for name, row in zip(names, expected):
            values = {**row["flags"], "result_allowed": row["decision"] == "allow"}
            policy["rules"].append({"decision": "allow", "guard": [{"field": "principal", "name": name, "negated": False}],
                                    "updates": [{"name": field, "value": value} for field, value in values.items()]})
        policy = normalize(policy)
        flags = [name for name, _ in policy["state"]]
        mask = lambda row: encode_observation(flags, row)
        observations = sorted({0, *(mask(row) for row in actual)})
        by_name = dict(zip(names, actual))
        alphabet = [[name, "boundary", "invoke"] for name in policy["principals"]]
        first = [["allow", observations.index(mask(by_name[name]))] for name in policy["principals"]]
        machine = {"state_names": flags, "alphabet": alphabet, "observations": observations, "initial": observations.index(0),
                   "transitions": [first if value == 0 else [None for _ in alphabet] for value in observations]}
        # There is precisely one component call. An exception/abort does not
        # magically admit a later permission request in the same invocation.
        protocol = {"initial": 0, "transitions": [[1 for _ in alphabet], [None for _ in alphabet]]}
        result = verify_protocol(policy, machine, protocol)
        parts.append({"start": start, "cases": len(expected), "comparison": result, "policy": policy, "machine": machine, "protocol": protocol})
    accepted = all(part["comparison"]["accepted"] for part in parts)
    return {"status": "equivalent" if accepted else "mismatch", "accepted": accepted, "scope": scope,
            "decision_encoding": "the core event acknowledges observation capture, not permission grant; result_allowed and explicit flags carry the domain outcome",
            "cases": len(reference), "all_parts": parts,
            "first_counterexample": next((part["comparison"] for part in parts if not part["comparison"]["accepted"]), None),
            "source_or_exploit_executed": False, "whole_application_verified": False}
