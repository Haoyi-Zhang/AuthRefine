"""Render four vector evaluation figures from retained AuthRefine results."""

import argparse
from collections import Counter
import csv
import gzip
import json
import math
from pathlib import Path
from statistics import median

from reportlab.lib.colors import HexColor, white
from reportlab.pdfgen.canvas import Canvas

from figure_typography import register_fonts

ARTIFACT = Path(__file__).resolve().parents[1]
WIDTH = 396
INK = HexColor("#1b2f3d")
NAVY = HexColor("#28465c")
TEAL = HexColor("#437f76")
RUST = HexColor("#a6553c")
PALE = HexColor("#e1e8ec")
GRID = HexColor("#c7d2da")


def chart(output, name, height):
    c = Canvas(str(output / f"{name}.pdf"), pagesize=(WIDTH, height),
               invariant=True, initialFontName="Body")
    c.setTitle(name.replace("-", " ").capitalize())
    c.setCreator("")
    return c


def text(c, x, y, value, align="center", size=9.8, color=INK, font="Body"):
    c.setFont(font, size)
    c.setFillColor(color)
    {"center": c.drawCentredString, "left": c.drawString,
     "right": c.drawRightString}[align](x, y, str(value))


def rect(c, x, y, w, h, color):
    c.setFillColor(color)
    c.rect(x, y, w, h, fill=1, stroke=0)


def legend(c, x, y, color, label):
    rect(c, x, y - 0.1, 8, 7, color)
    text(c, x + 12, y, label, "left", 9.5)


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
    c = chart(output, "source-interface-coverage", 92)
    legend(c, 62, 77, NAVY, "All direct dependencies linked")
    legend(c, 229, 77, PALE, "Not completely linked")
    left, right = 78, 384
    for y, label, (total, complete) in zip((52, 24), ("Baseline", "Guarded"), counts):
        cut = left + (right - left) * complete / total
        rect(c, left, y, cut - left, 16, NAVY)
        rect(c, cut, y, right - cut, 16, PALE)
        text(c, left - 8, y + 4.9, label, "right")
        text(c, (left + cut) / 2, y + 4.9, complete, color=white)
        text(c, (cut + right) / 2, y + 4.9, f"{total - complete:,}")
    text(c, (left + right) / 2, 6, "1,591 declared routes in each analysis (same 48 snapshots)")
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
    c = chart(output, "adaptation-handling", 133)
    for (key, label, fill, foreground), x in zip(handling, (134, 192, 241, 306)):
        legend(c, x, 119, fill, label)
    for y, axis, row in zip((94, 75, 56, 37, 18), axes, matrix):
        text(c, 122, y + 3.4, axis[0].upper() + axis[1:], "right")
        x = 134
        for count, (_, _, fill, foreground) in zip(row, handling):
            if count:
                w = count * 31
                rect(c, x, y, w, 13, fill)
                text(c, x + w / 2, y + 3.4, count, size=9.4, color=foreground)
                x += w
    text(c, 258, 4, "8 selected cases per axis")
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
    c = chart(output, "credential-algorithm-cost", 116)
    left, plotw = 105, 268
    c.setStrokeColor(GRID)
    c.setLineWidth(0.35)
    for tick in range(0, 51, 10):
        x = left + plotw * tick / 50
        c.line(x, 24, x, 109)
        text(c, x, 13.5, tick, size=9.2)
    for y, (_, label), value in zip((95, 74, 53, 32), names, ms):
        length = plotw * value / 50
        rect(c, left, y, length, 10.5, NAVY)
        text(c, left - 8, y + 2.3, label, "right")
        text(c, left + length + 5, y + 2.3, f"{value:.2f}", "left", 9.5)
    text(c, left + plotw / 2, 2, "Median family-analysis time (ms)")
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
    c = chart(output, "width", 147)
    left, right, bottom, top = 52, 382, 27, 116

    def loc(x, y):
        return (left + (x - 1) / 15 * (right - left),
                bottom + (math.log10(y) - math.log10(2)) /
                (math.log10(4_000_000) - math.log10(2)) * (top - bottom))

    c.setLineWidth(0.35)
    c.setStrokeColor(GRID)
    for tick, label in ((10, "10"), (100, "100"), (1000, "1,000"),
                        (10_000, "10,000"), (100_000, "100,000"), (1_000_000, "1,000,000")):
        _, y = loc(1, tick)
        c.line(left, y, right, y)
        text(c, left - 5, y - 2.5, label, "right", 8.6)
    for tick in (1, 4, 8, 12, 16):
        x, _ = loc(tick, 2)
        text(c, x, 15, tick, size=9.4)
    c.setStrokeColor(INK)
    c.line(left, bottom, right, bottom)
    c.line(left, bottom, left, top)
    text(c, (left + right) / 2, 3, "Declared aliases")
    text(c, left, 121, "Binding evaluations (log scale)", "left", 9.1)

    def series(points, color, marker):
        c.setStrokeColor(color)
        c.setFillColor(color)
        c.setLineWidth(1.05)
        c.setDash(4, 2) if marker == "dash" else c.setDash()
        xy = [loc(*pt) for pt in points]
        for a, b in zip(xy, xy[1:]):
            c.line(*a, *b)
        for x, y in xy:
            if marker == "circle":
                c.circle(x, y, 1.65, fill=1, stroke=0)
            elif marker == "square":
                c.rect(x - 1.65, y - 1.65, 3.3, 3.3, fill=1, stroke=0)
        c.setDash()

    series(derived, RUST, "dash")
    series(executed, RUST, "square")
    series(local, NAVY, "circle")
    for x, color, symbol, label in (
        (52, NAVY, "circle", "Local: executed"),
        (153, RUST, "square", "Global: executed"),
        (258, RUST, "dash", "Global: derived"),
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
        text(c, x + 18, 134, label, "left", 9.3)
    finish(c)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    args.output_directory.mkdir(parents=True, exist_ok=True)
    register_fonts()
    for render in (coverage, adaptation, costs, width):
        render(args.output_directory)


if __name__ == "__main__":
    main()
