"""Draw retained read observations and one recorded contract comparison."""
from pathlib import Path
import gzip
import json

from figure_typography import ACCENT, INK, SECONDARY

DATA = Path(__file__).resolve().parents[1] / "source_study" / "data"
IDS = ("plain-read-1r-header-GET-v1-1", "plain-read-1r-header-GET-v1-2")


def read(name):
    with gzip.open(DATA / (name + ".json.gz"), "rt", encoding="utf-8") as stream:
        return json.load(stream)


def observations():
    inputs = {r["id"]: r for r in read("credential-input")["owned_inputs"]}
    observed = {r["id"]: r for r in read("credential-observations")["rows"]}
    family = next(row for row in read("credential-family")["cases"] if row["id"] == "plain-read-GET")
    records = []
    fixed = ("profile", "mode", "keychoice", "carrier", "method", "version")
    assert all(inputs[IDS[0]][k] == inputs[IDS[1]][k] for k in fixed)
    for case_id in IDS:
        request = inputs[case_id]
        row = observed[case_id]
        value = row["observed"]
        obj = request["target"]
        owner = family["correct_binding"][f"owner-of-check-{obj}"]
        assert case_id in family["measured_cases"]
        assert row["agrees"] and row["exact_resolved_project_identity_transferred"]
        assert value["project"] == 1 and value["readonly"] and value["version"] == 1
        hits = row["serializer_transfers"]
        if hits:
            assert value["consumer"] == "serializer_boundary" and len(hits) == 1
            assert hits[0]["readonly"] is True and hits[0]["v"] == 1
        else:
            assert value["consumer"] is None
        records.append((obj, int(owner.removeprefix("project-")), value["status"], bool(hits)))
    assert records == [(1, 1, 200, True), (2, 2, 403, False)]
    result = family["diagnosis"]
    correct = family["correct_binding"]
    alternative = {**correct, "owner-of-check-2": "project-1"}
    assert result["matching_interpretations"] == [correct]
    assert result["strata"] == {"1": 26, "infinity": 1}
    witness = next(row for row in result["profiles"] if row["binding"] == alternative)
    assert witness["length"] == 1 and not witness["equivalent"]
    (step,) = witness["trace"]
    assert step["request"] == ["1r", "check-2", "header-first-v1"]
    assert step["target"] == ["deny", 0] and step["source"] == ["allow", 0]
    assert not step["decision_equal"] and step["state_equal"]
    contrast = [(2, step["target"][0], True), (1, step["source"][0], False)]
    return records, contrast, result["strata"]["infinity"], result["strata"]["1"]


def draw(output):
    from draw_schematics import Diagram, math

    rows, contrast, _, _ = observations()
    _, denied = rows
    d = Diagram(output, "credential-handoff", 202)

    def index(s, n):
        return [math(s), math(str(n), 7, -2)]

    def label(s, font="Body"):
        return [(s, font, 9.8, 0)]

    d.text(14, 15, "Observed reads", font="Bold", align="left")
    d.icon(39, 65, "mechanism-plate", 25, cell=0)
    d.runs(39, 89, index("p", rows[0][1]))
    d.text(39, 104, "Project record", color=SECONDARY)
    d.connectors([
        ([(57, 65), (74, 65)], False, SECONDARY),
        ([(74, 65), (74, 43), (101, 43)], True, INK),
        ([(74, 65), (74, 91), (101, 91)], True, ACCENT),
    ])
    d.mark(74, 65, True, "shared project record", radius=1.2, joined=True)
    for y, (obj, owner, status, hit) in zip((47, 95), rows):
        tone = INK if hit else ACCENT
        with d.outline(147, y-4, 84, 24, f"read object {obj}", tone=tone):
            d.icon(120, y-4, "mechanism-plate", 17, cell=1)
            d.runs(133, y, [*label("Read "), *index("o", obj)], color=tone, align="left")
        d.runs(132, y+19, [("Owner ", "Body", 9.8, 0), *index("p", owner)],
               color=SECONDARY, align="left")
        d.arrow(193, y-4, 207, y-4, tone)
        d.node(246, y-4, 70, 21, label(f"{status} / {'allow' if hit else 'deny'}", "Bold"),
               tone=tone, color=tone, tinted=not hit)
        d.text(295, y, "Reaches serializer" if hit else "Before serializer",
               color=SECONDARY, align="left")

    d.runs(14, 134, [*label("Reference for ", "Bold"), *index("o", denied[0])],
           align="left")
    d.text(177, 134, "Prediction", font="Bold")
    d.text(246, 134, "Agreement", font="Bold")
    d.text(339, 134, "Shortest witness", font="Bold")
    d.icon(39, 169, "mechanism-plate", 24, cell=2)
    d.connectors([
        ([(54, 169), (73, 169)], False),
        ([(73, 169), (73, 153), (93, 153)], True),
        ([(73, 169), (73, 183), (93, 183)], True),
    ], SECONDARY)
    d.mark(73, 169, True, "alternative owner readings", radius=1.2, joined=True)
    for y, (owner, predicted, agrees) in zip((157, 187), contrast):
        tone = INK if agrees else ACCENT
        d.node(122, y-4, 50, 20,
               [*index("z", denied[0]), math(" = "), *index("p", owner)])
        d.text(177, y, predicted.capitalize(), color=tone)
        with d.outline(244, y-4, 56, 18, "comparison result", tone=tone):
            d.mark(224, y-4, not agrees, "verdict", radius=2.4)
            d.text(233, y, "Agrees" if agrees else "Differs",
                   font="Body" if agrees else "Bold", color=tone, align="left")
        if not agrees:
            d.arrow(276, y-4, 307, y-4, tone)
            d.node(339, y-4, 56, 20, [*label("Read "), *index("o", denied[0])],
                   tone=tone, color=tone, tinted=True)

    d.save()
