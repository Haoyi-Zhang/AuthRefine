"""Render five vector evaluation figures from retained AuthRefine results."""

import argparse
from collections import Counter
import csv
import gzip
import json
import math
from pathlib import Path
from statistics import median

from reportlab.lib.colors import HexColor, white
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen.canvas import Canvas

from figure_typography import register_fonts

ARTIFACT = Path(__file__).resolve().parents[1]
WIDTH = 396
INK = HexColor("#1b2f3d")
NAVY = HexColor("#28465c")
TEAL = HexColor("#326e65")
RUST = HexColor("#a6553c")
PALE = HexColor("#e1e8ec")
GRID = HexColor("#c7d2da")


def chart(output, name, height):
    c = Canvas(str(output / f"{name}.pdf"), pagesize=(WIDTH, height),
               invariant=True, initialFontName="Body")
    c.setTitle(name.replace("-", " ").capitalize())
    c.setCreator("")
    c.chart_height = height
    c.chart_labels = []
    return c


def text(c, x, y, value, align="center", size=10.5, color=INK, font="Body"):
    value = str(value)
    w = pdfmetrics.stringWidth(value, font, size)
    x0 = x - {"center": w / 2, "left": 0, "right": w}[align]
    y0, y1 = y - .23 * size, y + .76 * size
    if x0 < 4 or x0 + w > WIDTH - 4 or y0 < 2 or y1 > c.chart_height - 3:
        raise ValueError(f"Label outside plot safe area: {value}")
    for a, b, d, e, other in c.chart_labels:
        if x0 < d + 1 and a < x0 + w + 1 and y0 < e + 1 and b < y1 + 1:
            raise ValueError(f"Chart labels collide: {value!r} and {other!r}")
    c.chart_labels.append((x0, y0, x0 + w, y1, value))
    c.setFont(font, size)
    c.setFillColor(color)
    {"center": c.drawCentredString, "left": c.drawString,
     "right": c.drawRightString}[align](x, y, value)


def rect(c, x, y, w, h, color):
    c.setFillColor(color)
    c.rect(x, y, w, h, fill=1, stroke=0)


def legend(c, x, y, color, label):
    rect(c, x, y - 0.1, 8, 7, color)
    text(c, x + 13, y, label, "left", 10.2)


def finish(c):
    c.showPage()
    c.save()


def load_study(name):
    with gzip.open(ARTIFACT / "source_study/data" / name, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def coverage(output):
    rows = load_study("source-transfer.json.gz")["rows"]
    modes = ("baseline", "guarded")
    counts = [
        (sum(r[mode]["declared_routes"] for r in rows),
         sum(r[mode]["routes_with_all_declared_direct_dependencies_linked"] for r in rows))
        for mode in modes
    ]
    if len(rows) != 48 or counts != [(1591, 564), (1591, 757)]:
        raise ValueError("The matched source cohort no longer matches the manuscript")
    c = chart(output, "source-interface-coverage", 102)
    legend(c, 89, 84, NAVY, "All direct dependencies linked")
    legend(c, 258, 84, PALE, "Not completely linked")
    left, right = 89, 382
    for y, label, (total, complete) in zip((55, 24), ("Baseline", "Guarded"), counts):
        cut = left + (right - left) * complete / total
        rect(c, left, y, cut - left, 18, NAVY)
        rect(c, cut + 1, y, right - cut - 1, 18, PALE)
        text(c, left - 9, y + 5.6, label, "right", font="Bold")
        text(c, (left + cut) / 2, y + 5.6, complete, color=white)
        text(c, (cut + right) / 2, y + 5.6, f"{total - complete:,}")
    text(c, (left + right) / 2, 6.4, "1,591 declared routes in the same 48 snapshots")
    finish(c)


def adaptation(output):
    records = json.loads((ARTIFACT / "adaptation_study/casebook.json").read_text(
        encoding="utf-8"
    ))["cases"]
    axes = ("identity origin", "post-authorization effects", "identity/state handoff",
            "runtime resolution", "environment and time")
    handling = (
        ("automatic supported source analysis", "Source", NAVY, white),
        ("explicit configuration/input", "Input", TEAL, white),
        ("source-bound primitive adapter", "Primitive", PALE, INK),
        ("non-admission", "Unadmitted", RUST, white),
    )
    counts = [Counter(r["axis_classification"][axis]["handling"] for r in records)
              for axis in axes]
    matrix = [tuple(row[key] for key, *_ in handling) for row in counts]
    if len(records) != 8 or matrix != [(0, 5, 3, 0), (0, 0, 5, 3), (1, 0, 7, 0),
                                       (2, 1, 4, 1), (0, 2, 3, 3)]:
        raise ValueError("Adaptation handling no longer matches the manuscript")
    c = chart(output, "adaptation-handling", 137)
    cols = (161, 224, 287, 350)
    for (_, label, _, _), x in zip(handling, cols):
        text(c, x, 119.5, label, font="Bold")
    for y, axis, row in zip((94, 74, 54, 34, 14), axes, matrix):
        text(c, 122, y + 4, axis[0].upper() + axis[1:], "right")
        for x, count in zip(cols, row):
            tone = HexColor(("#f2f4f5", "#e1eeed", "#ccdfdc", "#accac5",
                             "#8bb6ad", "#6ca198", "#396b63", "#2d5a53")[count])
            rect(c, x - 27, y, 54, 16, tone)
            text(c, x, y + 4, count, color=white if count >= 6 else INK,
                 font="Bold")
    finish(c)


def costs(output):
    data = load_study("credential-cost.json.gz")
    total = data["totals"]
    observed, native = data["measurements"], data["native_common_pipeline"]
    names = (("target_distance", "Target distance"), ("complete_product", "Complete product"),
             ("decision_diagram", "Decision diagram"), ("ordinary_BFS", "Ordinary BFS"))
    if (len(observed), len(native), total["fixed_binding_rows"], total["model_profiles"]) != (5, 3, 112, 8):
        raise ValueError("Unexpected cost denominators")
    if not all(r["complete_outputs_equal"] for r in observed) or not all(r["returncode"] == 0 for r in native):
        raise ValueError("Cost comparison is not equal-output and successful")
    values = {k: median(r["seconds"][k] for r in observed) for k, _ in names}
    if (values != total["algorithm_median_seconds"] or
            median(r["seconds"] for r in native) != total["common_native_pipeline_median_seconds"]):
        raise ValueError("Timing summary differs from raw measurements")
    ms = [v * 1000 for v in values.values()]
    if ([round(x, 2) for x in ms] != [10.84, 36.06, 14.67, 43.93]
            or round(total["common_native_pipeline_median_seconds"], 3) != 15.403
            or round(total["common_table_build_seconds"], 5) != 0.00877):
        raise ValueError("Cost data differs from the numbers in the manuscript")
    c = chart(output, "credential-algorithm-cost", 128)
    left, plotw = 113, 219
    c.setStrokeColor(INK)
    c.setLineWidth(0.55)
    c.line(left, 30, left + plotw, 30)
    for tick in range(0, 51, 10):
        x = left + plotw * tick / 50
        c.line(x, 30, x, 26)
        text(c, x, 17, tick)
    text(c, 365, 116, "Median", size=10.3, font="Bold")
    for y, (_, label), value in zip((101, 81, 61, 41), names, ms):
        length = plotw * value / 50
        rect(c, left, y, length, 9.2, NAVY)
        text(c, left - 10, y + 1.1, label, "right")
        text(c, 365, y + 1.1, f"{value:.2f}")
    text(c, left + plotw / 2, 4.6, "Family-analysis time (ms)")
    finish(c)


def width(output):
    with (ARTIFACT / "results/width.csv").open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    aliases = [int(r["aliases"]) for r in rows]
    if aliases != list(range(1, 17)):
        raise ValueError("Width study must cover aliases 1 through 16")
    local, executed, derived = [], [], []
    for n, row in zip(aliases, rows):
        measured = row["global_oracle_executed"] == "True"
        bound = int(row["global_complete_work_bound"])
        count = int(row["local_binding_evaluations"])
        if (measured != (n <= 8) or bool(row["global_evaluations"]) != measured
                or bound != n * 2 ** (n + 1) or count != 4 * n
                or int(row["maximum_width"]) != 1):
            raise ValueError("Do not conflate executed and derived work")
        local.append((n, count))
        if measured:
            executed.append((n, int(row["global_evaluations"])))
            if executed[-1][1] != bound:
                raise ValueError("Executed complete work and bound disagree")
        if n >= 8:
            derived.append((n, bound))
    c = chart(output, "width", 151)
    left, right, bottom, top = 62, 382, 29, 117

    def loc(x, y):
        return (left + 5 + (x - 1) / 15 * (right - left - 5),
                bottom + (math.log10(y) - math.log10(2)) /
                (math.log10(4_000_000) - math.log10(2)) * (top - bottom))

    c.setLineWidth(0.35)
    c.setStrokeColor(GRID)
    for tick, label in ((10, "10"), (100, "100"), (1000, "1,000"),
                        (10_000, "10,000"), (100_000, "100,000"), (1_000_000, "1,000,000")):
        _, y = loc(1, tick)
        c.line(left, y, right, y)
        text(c, left - 6, y - 2.8, label, "right", 10.1)
    for tick in (1, 4, 8, 12, 16):
        x, _ = loc(tick, 2)
        text(c, x, 16.4, tick, size=10.2)
    c.setStrokeColor(INK)
    c.line(left, bottom, right, bottom)
    c.line(left, bottom, left, top)
    text(c, (left + right) / 2, 4.7, "Declared aliases")
    text(c, left, 121, "Binding evaluations (log scale)", "left", 10.3)

    def series(points, color, marker):
        c.setStrokeColor(color)
        c.setFillColor(color)
        c.setLineWidth(1.05)
        c.setDash(4, 2) if marker == "dash" else c.setDash()
        xy = [loc(*pt) for pt in points]
        for a, b in zip(xy, xy[1:]):
            c.line(*a, *b)
        for x, y in xy[1:]:
            if marker == "circle":
                c.circle(x, y, 1.65, fill=1, stroke=0)
            elif marker == "square":
                c.rect(x - 1.65, y - 1.65, 3.3, 3.3, fill=1, stroke=0)
        c.setDash()

    series(derived, RUST, "dash")
    series(executed, RUST, "square")
    series(local, NAVY, "circle")
    x, y = loc(1, 4)
    c.setFillColor(INK)
    c.circle(x, y, 1.85, fill=1, stroke=0)
    for x, color, symbol, label in (
        (48, NAVY, "circle", "Local: executed"),
        (161, RUST, "square", "Global: executed"),
        (280, RUST, "dash", "Global: derived"),
    ):
        c.setStrokeColor(color)
        c.setFillColor(color)
        c.setLineWidth(1.05)
        c.setDash(3, 2) if symbol == "dash" else c.setDash()
        c.line(x, 137, x + 14, 137)
        if symbol == "circle":
            c.circle(x + 7, 137, 1.65, fill=1, stroke=0)
        elif symbol == "square":
            c.rect(x + 5.35, 135.35, 3.3, 3.3, fill=1, stroke=0)
        c.setDash()
        text(c, x + 18, 135.5, label, "left", 10.1)
    finish(c)


def screening(output):
    with gzip.open(ARTIFACT / "adaptation_study/survey.json.gz", "rt", encoding="utf-8") as stream:
        survey = json.load(stream)
    keys = (("identity_input", "Identity input"),
            ("credential_processing", "Credential processing"),
            ("identity_handoff", "Identity handoff"),
            ("mutation_call", "Named mutation call"),
            ("dynamic_lookup", "Dynamic lookup"),
            ("asynchronous_flow", "Asynchronous flow"))
    total = survey["denominator"]
    counts = [survey["counts"][key] for key, _ in keys]
    if total != 48 or len(survey["rows"]) != total or counts != [17, 25, 10, 42, 24, 22]:
        raise ValueError("The screening snapshot counts differ from the manuscript")
    for (key, _), count in zip(keys, counts):
        if sum(row["features"][key] == "observed" for row in survey["rows"]) != count:
            raise ValueError(f"Screening summary does not match snapshot rows: {key}")
    c = chart(output, "source-screening", 153)
    left, span = 132, 190
    for y, (_, label), count in zip((134, 115, 96, 77, 58, 39), keys, counts):
        rect(c, left, y, span, 10, PALE)
        rect(c, left, y, count * span / total, 10, NAVY)
        text(c, left - 10, y + 1.9, label, "right")
        text(c, 354, y + 1.9, f"{count}/48", font="Bold")
    text(c, 227, 13, "Snapshots with the construct in selected functions")
    finish(c)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    args.output_directory.mkdir(parents=True, exist_ok=True)
    register_fonts()
    for render in (coverage, adaptation, costs, width, screening):
        render(args.output_directory)


if __name__ == "__main__":
    main()
