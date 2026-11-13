"""Render the checked two-stage example; no experimental results are regenerated."""
from pathlib import Path
import sys

from figure_typography import ACCENT, INK, SECONDARY

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from diagnostic_example import run


def draw(output):
    example = run()
    machine = example["machine"]
    assert example["all_lengths_agree"]
    observations = machine["observations"]
    assert sorted(observations) == [0, 1] and observations[machine["initial"]] == 0
    assert [item[-1] for item in machine["alphabet"]] == ["a", "b"]
    by_observation = {
        before: [(decision, observations[successor]) for decision, successor in outgoing]
        for before, outgoing in zip(observations, machine["transitions"])
    }
    assert by_observation == {0: [("allow", 1), ("deny", 0)],
                              1: [("deny", 1), ("allow", 0)]}
    rows = {(row["binding"]["z_a"], row["binding"]["z_b"]): row
            for row in example["profiles"]}
    assert set(rows) == {("r", "r"), ("r", "t"), ("t", "r"), ("t", "t")}
    from draw_schematics import Diagram, math

    stages = {}
    for binding, item in rows.items():
        trace = "".join(step["request"][-1] for step in (item["trace"] or ()))
        if not item["equivalent"] and len(trace) != item["length"]:
            raise ValueError("Witness label does not match the trace length")
        stages.setdefault(trace, []).append(binding)
    if stages != {"": [("r", "r")], "ab": [("r", "t")], "a": [("t", "r"), ("t", "t")]}:
        raise ValueError("Illustrated prefixes do not match the synthetic profile")

    d = Diagram(output, "analysis-workflow", 135)
    d.text(13, 17, "(a)  Target machine", font="Bold", align="left")
    d.text(204, 17, "(b)  Prefix checks", font="Bold", align="left")
    # These are the only two observed states. The arrows show the two
    # changing transitions; denial leaves the current state unchanged.
    cy = 77
    for x, state in ((44, 0), (144, 1)):
        d.runs(x, cy+3, [math(f"p={state}")])
        d.c.setLineWidth(.7)
        d.c.setStrokeColor(INK)
        d.c.circle(x, d.h-cy, 17, fill=0, stroke=1)
    d.arrow(8, cy, 25, cy, SECONDARY)
    d.connectors([
        ([(45, 59), (45, 48), (143, 48), (143, 58)], True, ACCENT),
        ([(143, 95), (143, 108), (45, 108), (45, 96)], True, ACCENT),
    ], ACCENT)
    d.text(94, 41, "a / allow")
    d.text(94, 125, "b / allow")

    # One binding per row, carried unchanged through the two prefixes.
    # Leave the second column blank when a shorter witness already exists.
    d.text(221, 42, "Binding", font="Bold")
    d.runs(268, 42, [math("a")])
    d.runs(313, 42, [math("ab")])
    d.text(365, 42, "Witness", font="Bold")
    for y, (a, b) in zip((66, 83, 100, 117), sorted(rows)):
        binding = (a, b)
        first = next(word for word, group in stages.items() if binding in group)
        d.runs(221, y, [math(f"({a}, {b})")])
        d.mark(268, y-3, first == "a", f"{binding}: a differs" if first == "a" else f"{binding}: a agrees")
        if first != "a":
            d.mark(313, y-3, first == "ab", f"{binding}: ab differs" if first == "ab" else f"{binding}: ab agrees")
        if first:
            d.runs(365, y, [math(first)], color=ACCENT)
        else:
            d.text(365, y, "None")
    d.save()
