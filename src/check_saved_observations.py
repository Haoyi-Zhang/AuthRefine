"""Reconcile retained comparison evidence offline; never execute application code."""
import json
from collections import Counter
from pathlib import Path

RESULTS = Path(__file__).resolve().parents[1] / "results"
FIELDS = {
    "healthchecks_read": {"status", "boundary_fields", "record_identity", "serializer_arguments"},
    "healthchecks_resume": {"status", "records", "events", "event_delta", "store_changed"},
    "pretix_read": {"decision", "event", "organizer", "grants"},
    "wger_creation": {"persisted_rows"},
}
BOOL = {"decision", "store_changed"}
CONTROL_FIELDS = {
    "identity_relation": ("healthchecks_read", "record_identity"),
    "serializer_version": ("healthchecks_read", "serializer_arguments"),
    "missing_selected_event": ("pretix_read", "event"),
    "missing_recorded_grant": ("pretix_read", "grants"),
    "stale_timing_field": ("healthchecks_resume", "records"),
    "missing_event": ("healthchecks_resume", "events"),
    "duplicate_event_record": ("healthchecks_resume", "events"),
}
PROFILE_LABELS = {"healthchecks_read": "Healthchecks read",
                  "healthchecks_resume": "Healthchecks write", "pretix_read": "Pretix read"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def reconcile(data, summary, controls):
    rows = data["profiles"]
    profiles = summary["profiles"]
    require(set(rows) == set(profiles) == set(FIELDS), "unexpected profiles")
    for profile, entries in rows.items():
        require(len(entries) == profiles[profile]["pairs"], f"wrong count: {profile}")
        mismatches = 0
        for i, row in enumerate(entries, 1):
            a, b = row["direct"], row["retained"]
            require(row["case"] == i and set(a) == set(b) == FIELDS[profile],
                    f"unexpected fields: {profile} {i}")
            for side in (a, b):
                require(all(type(value) is (bool if field in BOOL else int)
                            for field, value in side.items()),
                        f"unexpected observation type: {profile} {i}")
            mismatches += a != b
        require(mismatches == profiles[profile]["disagreements"], f"disagreement count: {profile}")

    read = rows["healthchecks_read"]
    read_summary = profiles["healthchecks_read"]
    require(Counter(r["direct"]["status"] for r in read) == {
        200: read_summary["serializer_boundary_reached"], 403: read_summary["ownership_denials"],
    }, "read status counts")
    intro = [r for r in read if "figure1_read" in r]
    require(len(intro) == 2 and {r["figure1_read"]: r["direct"]["status"] for r in intro}
            == {"owned": 200, "other": 403}, "missing opening observations")
    write_summary = profiles["healthchecks_resume"]
    require(Counter((r["direct"]["status"], r["direct"]["event_delta"],
                     r["direct"]["store_changed"]) for r in rows["healthchecks_resume"]) == {
        (200, 1, True): write_summary["first_resume_changed_record_and_inserted_event"],
        (409, 0, False): write_summary["repeat_left_store_unchanged"],
    }, "write readback counts")
    wger = profiles["wger_creation"]
    trials = data["wger_date_trials"]
    require(len(trials) == wger["direct_date_trials_including_paired_cases"], "date trial count")
    require(sum(r["accepted"] for r in trials) == wger["accepted"] and
            sum(not r["accepted"] and r["rows_before"] == r["rows_after"]
                for r in trials) == wger["rejected_without_insertion"], "date trial outcomes")
    control = summary["saved_record_controls"]
    outcomes = data["recorded_control_outcomes"]
    require(all(type(r[k]) is bool for r in outcomes
                for k in ("field_comparison_detects", "status_only_detects")),
            "unexpected control flag type")
    clean = sum(len(rows[k]) for k in control["profiles"])
    require(clean == control["unmodified_pairs"] == control["unmodified_field_agreements"] and
            all(profiles[k]["disagreements"] == 0 for k in control["profiles"]),
            "unmodified comparison totals")
    require(len(outcomes) == len(controls) == control["edited_records_with_same_response"],
            "control count differs")
    seen = set()
    fields = responses = 0
    for item, recorded in zip(controls, outcomes):
        profile, case, name, field = (item[k] for k in ("profile", "case", "control", "field"))
        require(CONTROL_FIELDS.get(name) == (profile, field), "wrong control profile or field")
        require(type(case) is int and 1 <= case <= len(rows[profile]), "unknown control case")
        key = (profile, case, name)
        require(key not in seen, "duplicate control")
        seen.add(key)
        pair = rows[profile][case - 1]
        response = "decision" if profile == "pretix_read" else "status"
        edited_value, edited_response = item["edited_value"], item["edited_response"]
        require(type(edited_value) is int and edited_value > 0 and
                type(edited_response) is type(pair["direct"][response]), "invalid edited value")
        modified = dict(pair["retained"], **{field: edited_value, response: edited_response})
        differing = {k for k, val in pair["direct"].items() if modified[k] != val}
        require(differing == {field}, "control must differ in exactly the named field")
        field_detect = bool(differing)
        response_detect = response in differing
        require(recorded["profile"] == PROFILE_LABELS[profile] and recorded["control"] == name and
                recorded["field_comparison_detects"] is field_detect and
                recorded["status_only_detects"] is response_detect, "saved control outcome differs")
        fields += field_detect
        responses += response_detect
    require(fields == control["field_differences_detected"] and
            responses == control["response_differences_detected"], "recomputed control totals differ")
    return {"paired_records": sum(map(len, rows.values())), "control_outcomes": len(outcomes),
            "wger_date_trials": len(trials)}


if __name__ == "__main__":
    load = lambda name: json.loads((RESULTS / name).read_text(encoding="utf-8"))
    print(json.dumps(reconcile(load("direct-observation-pairs.json"),
                               load("direct-observation-summary.json"),
                               load("direct-observation-controls.json")), sort_keys=True))
