"""Render the evaluation figures as pure vector PDFs from retained results."""

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
INK = HexColor("#18242a")
NAVY = HexColor("#24596c")
GRID = HexColor("#d1d7da")


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


def line(c, x0, y0, x1, y1, color=GRID, width=.55):
    c.setStrokeColor(color)
    c.setLineWidth(width)
    c.line(x0, y0, x1, y1)


def dot(c, x, y, radius=2.5, open_marker=False, color=NAVY):
    c.setFillColor(white if open_marker else color)
    c.setStrokeColor(color)
    c.setLineWidth(.8)
    c.circle(x, y, radius, fill=1, stroke=int(open_marker))


def axis(c, left, right, y, low, high, ticks):
    def loc(value):
        return left + (right - left) * (value - low) / (high - low)
    line(c, left, y, right, y, INK)
    for v, label in ticks:
        x = loc(v)
        line(c, x, y, x, y - 3, INK)
        text(c, x, y - 13, label, size=10.1)
    return loc


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
    c = chart(output, "source-interface-coverage", 100)
    left, right = 86, 280
    x = axis(c, left, right, 32, 0, 1591,
             ((0, "0"), (400, "400"), (800, "800"), (1200, "1,200"), (1591, "1,591")))
    text(c, 341, 85, "Linked / declared", size=10.1, font="Bold")
    for y, label, (total, complete) in zip((69, 49), ("Baseline", "Guarded"), counts):
        line(c, left, y, right, y)
        dot(c, x(complete), y, 2.75, open_marker=(label == "Baseline"))
        text(c, left - 9, y - 3.4, label, "right")
        text(c, 341, y - 3.4, f"{complete:,} / {total:,}", font="Bold")
    text(c, (left + right) / 2, 6.5, "Complete direct links")
    finish(c)


def adaptation(output):
    records = json.loads((ARTIFACT / "adaptation_study/casebook.json").read_text(
        encoding="utf-8"
    ))["cases"]
    axes = ("identity origin", "post-authorization effects", "identity/state handoff",
            "runtime resolution", "environment and time")
    handling = (
        ("automatic supported source analysis", "Source"),
        ("explicit configuration/input", "Input"),
        ("source-bound primitive adapter", "Primitive"),
        ("non-admission", "Unadmitted"),
    )
    counts = [Counter(r["axis_classification"][axis]["handling"] for r in records)
              for axis in axes]
    matrix = [tuple(row[key] for key, *_ in handling) for row in counts]
    if len(records) != 8 or matrix != [(0, 5, 3, 0), (0, 0, 5, 3), (1, 0, 7, 0),
                                       (2, 1, 4, 1), (0, 2, 3, 3)]:
        raise ValueError("Adaptation handling no longer matches the manuscript")
    c = chart(output, "adaptation-handling", 131)
    cols = (174, 234, 295, 353)
    text(c, 8, 116, "Adaptation axis", "left", font="Bold")
    for (_, label), x in zip(handling, cols):
        text(c, x, 116, label, font="Bold")
    line(c, 8, 108, 388, 108, INK)
    for i, (y, name, row) in enumerate(zip((92, 73, 54, 35, 16), axes, matrix)):
        text(c, 8, y, name[0].upper() + name[1:], "left")
        for x, count in zip(cols, row):
            text(c, x, y, count, color=NAVY if count == max(row) else INK,
                 font="Bold" if count == max(row) else "Body")
        line(c, 8, y - 7, 388, y - 7, INK if i == 4 else GRID, .45)
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
    c = chart(output, "credential-algorithm-cost", 148)
    left, right = 120, 328
    x = axis(c, left, right, 31, 0, 50, tuple((v, str(v)) for v in range(0, 51, 10)))
    dot(c, 131, 135, 1.8)
    text(c, 139, 132, "Individual runs", "left", size=10.2)
    text(c, 364, 132, "Median", size=10.3, font="Bold")
    for y, (key, label), value in zip((111, 89, 67, 45), names, ms):
        line(c, left, y, right, y, GRID, .38)
        for i, row in enumerate(observed):
            dot(c, x(1000 * row["seconds"][key]), y + (i - 2) * 3.3, radius=1.45)
        text(c, left - 11, y - 3.5, label, "right")
        text(c, 364, y - 3.5, f"{value:.2f}", font="Bold")
    text(c, (left + right) / 2, 5.5, "Family-analysis time (ms)")
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

    series(derived, INK, "dash")
    series(executed, INK, "square")
    series(local, NAVY, "circle")
    x, y = loc(1, 4)
    c.setFillColor(INK)
    c.circle(x, y, 1.85, fill=1, stroke=0)
    for x, color, symbol, label in (
        (48, NAVY, "circle", "Local: executed"),
        (161, INK, "square", "Global: executed"),
        (280, INK, "dash", "Global: derived"),
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
    c = chart(output, "source-screening", 156)
    left, right = 133, 327
    x = axis(c, left, right, 30, 0, 48, tuple((v, str(v)) for v in range(0, 49, 12)))
    text(c, 361, 145, "Count", size=10.2, font="Bold")
    for y, (_, label), count in zip((133, 116, 99, 82, 65, 48), keys, counts):
        line(c, left, y, right, y, GRID, .4)
        line(c, left, y, x(count), y, NAVY, .8)
        dot(c, x(count), y, 2.4)
        text(c, left - 10, y - 3.4, label, "right")
        text(c, 361, y - 3.4, f"{count}/48")
    text(c, 230, 5, "Snapshots with the construct in selected functions")
    finish(c)


def frontend(output):
    data = load_study("frontend-cost.json.gz")
    rows = data["rows"]
    modes = ("baseline", "guarded")
    if (len(rows), data["measured_fresh_processes"]) != (144, 288) or not data[
            "all_original_source_outputs_unchanged"]:
        raise ValueError("Unexpected matched machine-cost study")
    if {r["repeat"] for r in rows} != {0, 1, 2}:
        raise ValueError("Expected three recorded batches")
    cohorts = [{r["repository_id"] for r in rows if r["repeat"] == i} for i in range(3)]
    if len(cohorts[0]) != 48 or any(c != cohorts[0] for c in cohorts):
        raise ValueError("Batch sources are not the same 48 snapshots")
    totals = {m: [sum(r["methods"][m]["outer_startup_through_exit_wall_ns"]
                      for r in rows if r["repeat"] == i) for i in range(3)] for m in modes}
    if any(totals[m] != data["summaries"][m]["whole48_batch_wall_ns"]
           or median(totals[m]) != data["summaries"][m]["median_whole48_batch_wall_ns"]
           for m in modes):
        raise ValueError("Recorded batch summary disagrees with the process rows")
    c = chart(output, "frontend-batch-cost", 113)
    left, right = 81, 292
    x = axis(c, left, right, 30, 20, 40, tuple((v, str(v)) for v in range(20, 41, 5)))
    for p, m, open_marker in ((106, "Baseline", True), (195, "Guarded", False)):
        dot(c, p, 101, 2.55, open_marker)
        text(c, p + 8, 98, m, "left", 10.3)
    text(c, 348, 98, "Extra time", font="Bold")
    for i, (a, b) in enumerate(zip(*(totals[m] for m in modes)), 1):
        y = 95 - 16 * i
        start, end = a / 1e9, b / 1e9
        line(c, x(start), y, x(end), y, INK, .55)
        dot(c, x(start), y, 2.8, True)
        dot(c, x(end), y, 2.8)
        text(c, left - 12, y - 3.3, f"Batch {i}", "right")
        text(c, 348, y - 3.3, f"+{end - start:.2f} s")
    text(c, (left + right) / 2, 5, "Summed process wall time over 48 snapshots (s)")
    finish(c)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    args.output_directory.mkdir(parents=True, exist_ok=True)
    register_fonts()
    for render in (coverage, adaptation, costs, width, screening, frontend):
        render(args.output_directory)


if __name__ == "__main__":
    main()
