"""Typeset AuthRefine's source and proof diagrams as pure vector PDF."""

import argparse
from dataclasses import dataclass
from pathlib import Path

from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas

from figure_typography import register_fonts

WIDTH = 396
INK = HexColor("#18242a")
SECONDARY = HexColor("#465158")
ACCENT = HexColor("#24596c")
HAIRLINE = HexColor("#a2acb1")


@dataclass(frozen=True)
class Rect:
    x: float
    y: float
    w: float
    h: float

    def intersects(self, other, gap=0):
        return (self.x < other.x + other.w + gap and other.x < self.x + self.w + gap
                and self.y < other.y + other.h + gap and other.y < self.y + self.h + gap)


class Diagram:
    """Fixed baseline layout; reject clearance and clipping errors before export."""

    def __init__(self, output, name, height):
        self.h, self.name = height, name
        self.c = Canvas(str(output / f"{name}.pdf"), pagesize=(WIDTH, height),
                        invariant=True, initialFontName="Body")
        self.c.setTitle(name.replace("-", " ").capitalize())
        self.c.setCreator("")
        self.marks = []

    def reserve(self, box, description):
        if not (4 <= box.x and 3 <= box.y and box.x + box.w <= WIDTH - 4
                and box.y + box.h <= self.h - 3):
            raise ValueError(f"{self.name}: outside safe area: {description} {box}")
        for other, label in self.marks:
            if box.intersects(other, 2):
                raise ValueError(f"{self.name}: insufficient clearance between {description} and {label}")
        self.marks.append((box, description))

    def text(self, x, y, s, size=10.7, font="Body", color=INK, align="center"):
        self.runs(x, y, [(s, font, size, 0)], color, align)

    def runs(self, x, y, runs, color=INK, align="center"):
        widths = [pdfmetrics.stringWidth(s, f, size) for s, f, size, _ in runs]
        pos = x - sum(widths) * {"left": 0, "center": .5, "right": 1}[align]
        upper = min(y - shift - size * .77 for _, _, size, shift in runs)
        lower = max(y - shift + size * .25 for _, _, size, shift in runs)
        self.reserve(Rect(pos, upper, sum(widths), lower - upper),
                     "".join(r[0] for r in runs))
        self.c.setFillColor(color)
        for (s, font, size, shift), width in zip(runs, widths):
            self.c.setFont(font, size)
            self.c.drawString(pos, self.h - y + shift, s)
            pos += width

    def rule(self, x1, x2, y, color=HAIRLINE, stroke=0.5):
        self.reserve(Rect(x1, y - stroke / 2, x2 - x1, stroke), "rule")
        self.c.setStrokeColor(color)
        self.c.setLineWidth(stroke)
        self.c.line(x1, self.h - y, x2, self.h - y)

    def arrow(self, x1, y1, x2, y2, color=INK):
        if (x1 == x2) == (y1 == y2):
            raise ValueError("Use nonzero orthogonal connectors")
        d = abs(x2 - x1) + abs(y2 - y1)
        if d < 8:
            raise ValueError("Insufficient connector length")
        dx, dy = (x2 - x1) / d, (y2 - y1) / d
        px, py = (0.5, 2.35) if dx else (2.35, 0.5)
        self.reserve(Rect(min(x1, x2) - px, min(y1, y2) - py,
                          abs(x2 - x1) + 2 * px, abs(y2 - y1) + 2 * py), "connector")
        bx, by = x2 - 4.6 * dx, y2 - 4.6 * dy
        self.c.setStrokeColor(color)
        self.c.setFillColor(color)
        self.c.setLineWidth(.8)
        self.c.line(x1, self.h - y1, bx, self.h - by)
        head = self.c.beginPath()
        head.moveTo(x2, self.h - y2)
        head.lineTo(bx - dy * 2.25, self.h - (by + dx * 2.25))
        head.lineTo(bx + dy * 2.25, self.h - (by - dx * 2.25))
        head.close()
        self.c.drawPath(head, fill=1, stroke=0)

    def save(self):
        self.c.showPage()
        self.c.save()


def math(s, size=12.1, shift=0):
    return (s, "Math", size, shift)


def workflow(output):
    d = Diagram(output, "analysis-workflow", 75)
    stages = (
        (47, "Admit source", "Entry rules", "Source bodies"),
        (148, "Observe state", "Decisions", "Identity and state"),
        (249, "Diagnose", "Binding family", "Shortest witness"),
        (350, "Check repair", "Replay under", "the same contract"),
    )
    for i, (x, title, top, bottom) in enumerate(stages):
        d.text(x, 19, title, 11.3, "Bold")
        d.rule(x - 37, x + 37, 29, ACCENT if i == 2 else HAIRLINE)
        d.text(x, 47, top, 10.7)
        d.text(x, 62, bottom, 10.7)
        if i:
            d.arrow(x - 59, 29, x - 41, 29, ACCENT)
    d.save()


def handoff(output):
    d = Diagram(output, "credential-handoff", 91)
    stages = ((65, "Key manager", "Resolve the key", "Project record"),
              (198, "Request wrapper", "Attach to request", "Same record + access mode"),
              (331, "Object endpoint", "Check object owner", "Pass mode to serializer"))
    for i, (x, title, action, result) in enumerate(stages):
        d.text(x, 18, title, 11.3, "Bold")
        d.rule(x - 50, x + 50, 29)
        d.text(x, 49, action)
        d.text(x, 72, result, 10.7, "Bold" if i < 2 else "Body",
               ACCENT if i < 2 else INK)
        if i:
            d.arrow(x - 79, 49, x - 53, 49)
    d.save()


def mapping(output):
    d = Diagram(output, "ownership-witness", 108)
    d.text(9, 14, "Fixed request", 10.6, "Bold", align="left")
    d.text(86, 14, "Read-only key for Project 1; GET Object 2", 10.9, align="left")
    for x, label in ((9, "Comparison"), (166, "Required owner"), (323, "Decision")):
        d.text(x, 39, label, 10.6, "Bold", align="left")
    d.rule(9, 387, 47, stroke=.65)
    for y, title, owner, decision in (
        (66, "Observed source", "Project 2", "Deny"),
        (91, "Alternative binding", "Project 1", "Allow"),
    ):
        d.text(9, y, title, 11.0, align="left")
        d.text(166, y, owner, 11.0, align="left")
        d.arrow(254, y - 3, 302, y - 3)
        d.text(323, y, decision, 11.0, "Bold", ACCENT if decision == "Deny" else INK, "left")
    d.save()


def square(output):
    d = Diagram(output, "semantic-square", 112)
    prime = math("'", 9.8, 1.5)
    d.text(10, 37, "Source", 10.5, "Bold", align="left")
    d.text(10, 92, "Target", 10.5, "Bold", align="left")
    d.runs(107, 37, [math("s = ν(q)")])
    d.runs(298, 37, [math("s"), prime, math(" = ν(q"), prime, math(")")])
    d.runs(107, 92, [math("q")])
    d.runs(298, 92, [math("q"), prime])
    d.arrow(151, 33, 249, 33)
    d.arrow(151, 88, 249, 88)
    d.runs(200, 22, [math("P"), math("β", 8.5, -1.6), math(" : x / d")])
    d.runs(200, 77, [math("M : x / d")])
    for x in (107, 298):
        d.arrow(x, 77, x, 48, ACCENT)
        d.text(x + 16, 66, "ν", 12, "Math", ACCENT)
    d.save()


def trace(output):
    d = Diagram(output, "diagnostic-trace", 122)
    for x, title in ((124, "Initial"), (238, "After a"), (356, "After b")):
        d.text(x, 15, title, 10.5, "Bold")
    d.rule(10, 386, 24, stroke=.65)
    d.rule(10, 386, 70)
    for y, title, binding, states, final_decision in (
        (50, "Target", "Binding (r, r)", (0, 1, 0), "b / allow"),
        (96, "Reference", "Fixed (r, t)", (0, 1, 1), "b / deny"),
    ):
        d.text(10, y, title, 11, "Bold", align="left")
        d.text(10, y + 14, binding, 10.4, color=SECONDARY, align="left")
        for i, (x, value) in enumerate(zip((124, 238, 356), states)):
            color = ACCENT if i == 2 and title == "Reference" else INK
            d.text(x, y + 2, f"p = {value}", 12.3, "Math", color)
            if i:
                prior = (124, 238)[i - 1]
                d.arrow(prior + 21, y - 2, x - 22, y - 2, color)
                d.text((prior + x) / 2, y - 12, "a / allow" if i == 1 else final_decision,
                       10.3, color=color)
    d.save()


def transfer(output):
    d = Diagram(output, "evaluation-design", 111)
    d.text(198, 15, "Shared input: nine source boundaries and 78 contexts", 10.9, "Bold")
    d.rule(8, 388, 26, stroke=.65)
    d.rule(8, 388, 65)
    for y, label, method, observation in (
        (49, "Frozen transfer", ("Run the frozen", "pipeline"),
         ("Record completion", "and unknowns")),
        (88, "Source adaptation", ("Add source", "adapters"),
         ("Check the same", "contexts again")),
    ):
        d.text(8, y, label, 10.9, "Bold", align="left")
        for x, values in ((198, method), (340, observation)):
            d.text(x, y - 6, values[0])
            d.text(x, y + 8, values[1])
        d.arrow(109, y - 3, 146, y - 3)
        d.arrow(249, y - 3, 285, y - 3, ACCENT if y == 88 else INK)
    d.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--math-font", type=Path, required=True, help="STIXGeneralItalic.ttf")
    args = parser.parse_args()
    args.output_directory.mkdir(parents=True, exist_ok=True)
    register_fonts()
    font = TTFont("Math", str(args.math_font.resolve(strict=True)))
    if any(ord(c) not in font.face.charToGlyph for c in "νβ'pqrts"):
        raise ValueError("Diagram math font lacks required glyphs")
    pdfmetrics.registerFont(font)
    for compose in (workflow, handoff, mapping, square, trace, transfer):
        compose(args.output_directory)


if __name__ == "__main__":
    main()
