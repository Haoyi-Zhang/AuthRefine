"""Compose vector-only source, trace, and evaluation diagrams."""

import argparse
from dataclasses import dataclass
from pathlib import Path

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas

from figure_typography import (
    ACCENT, COMPACT_WIDTH, GUIDE, INK, MATH, SECONDARY, TEXT, WIDTH,
    label_size, register_fonts,
)


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

    def __init__(self, output, name, height, width=WIDTH):
        self.w, self.h, self.name = width, height, name
        self.c = Canvas(str(output / f"{name}.pdf"), pagesize=(width, height),
                        invariant=True, initialFontName="Body")
        self.c.setTitle(name.replace("-", " ").capitalize())
        self.c.setCreator("")
        self.marks = []

    def reserve(self, box, description):
        if not (4 <= box.x and 3 <= box.y and box.x + box.w <= self.w - 4
                and box.y + box.h <= self.h - 3):
            raise ValueError(f"{self.name}: outside safe area: {description} {box}")
        for other, label in self.marks:
            if box.intersects(other, 2):
                raise ValueError(f"{self.name}: insufficient clearance between {description} and {label}")
        self.marks.append((box, description))

    def text(self, x, y, s, size=TEXT, font="Body", color=INK, align="center"):
        self.runs(x, y, [(s, font, size, 0)], color, align)

    def runs(self, x, y, runs, color=INK, align="center"):
        runs = [(s, f, label_size(f, size), shift) for s, f, size, shift in runs]
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

    def lifeline(self, x, start, end):
        # Horizontal handoff edges meet these lifelines intentionally.
        self.c.setStrokeColor(GUIDE)
        self.c.setLineWidth(.55)
        self.c.setDash(1.5, 2.5)
        self.c.line(x, self.h - start, x, self.h - end)
        self.c.setDash()

    def mark(self, x, y, kind, color=ACCENT, radius=2.8):
        self.reserve(Rect(x-radius, y-radius, 2*radius, 2*radius), f"{kind} mark")
        self.c.setStrokeColor(color)
        self.c.setFillColor(color)
        self.c.setLineWidth(.8)
        yy = self.h - y
        if kind == "record":
            self.c.rect(x-radius, yy-radius, 2*radius, 2*radius, stroke=0, fill=1)
        elif kind in ("open", "solid"):
            self.c.circle(x, yy, radius, stroke=1, fill=int(kind == "solid"))
        else:
            raise ValueError(f"Unknown mark {kind}")

    def connectors(self, routes, color=INK, dashed=False):
        """Clearance-check routed segments; joins within this group are intentional."""
        segments = []
        for points, arrowhead, *stroke in routes:
            last = len(points) - 2
            for i, ((x1, y1), (x2, y2)) in enumerate(zip(points, points[1:])):
                if (x1 == x2) == (y1 == y2):
                    raise ValueError("Use nonzero orthogonal connectors")
                dx, dy = x2 - x1, y2 - y1
                tip = arrowhead and i == last
                px = 2.2 if tip and not dx else .55
                py = 2.2 if tip and not dy else .55
                box = Rect(min(x1, x2) - px, min(y1, y2) - py,
                           abs(dx) + 2 * px, abs(dy) + 2 * py)
                distance = abs(dx) + abs(dy)
                if tip and distance < 8:
                    raise ValueError("Insufficient arrowhead clearance")
                segments.append((box, (x1, y1, x2, y2, dx / distance, dy / distance), tip,
                                 stroke[0] if stroke else color))
        for box, *_ in segments:
            self.reserve(box, "connector")
            self.marks.pop()
        for box, (x1, y1, x2, y2, dx, dy), tip, tone in segments:
            self.marks.append((box, "connector"))
            self.segment(x1, y1, x2, y2, dx, dy, tip, tone, dashed)

    def arrow(self, x1, y1, x2, y2, color=INK, dashed=False):
        self.connectors([([(x1, y1), (x2, y2)], True)], color, dashed)

    def segment(self, x1, y1, x2, y2, dx, dy, tip, color, dashed):
        inset = 4.8 if tip else 0
        bx, by = x2 - inset * dx, y2 - inset * dy
        self.c.setStrokeColor(color)
        self.c.setFillColor(color)
        self.c.setLineWidth(.9)
        if dashed:
            self.c.setDash(3.0, 2.2)
        self.c.line(x1, self.h - y1, bx, self.h - by)
        self.c.setDash()
        if not tip:
            return
        head = self.c.beginPath()
        head.moveTo(x2, self.h - y2)
        head.lineTo(bx - dy * 2.25, self.h - (by + dx * 2.25))
        head.lineTo(bx + dy * 2.25, self.h - (by - dx * 2.25))
        head.close()
        self.c.drawPath(head, fill=1, stroke=0)

    def save(self):
        self.c.showPage()
        self.c.save()


def math(s, size=MATH, shift=0):
    return (s, "Math", size, shift)


def workflow(output):
    d = Diagram(output, "analysis-workflow", 89)
    d.text(9, 20, "Source snapshot", 10.8, align="left")
    d.text(9, 48, "Entry conditions", 10.8, align="left")
    d.text(153, 34, "Observe", 11.2, "Bold")
    d.text(330, 34, "Compare", 11.2, "Bold")
    d.text(330, 78, "Replay repair", 11.2, "Bold")
    d.connectors([
        ([(86, 17), (106, 17), (106, 45), (86, 45)], False),
        ([(106, 30), (125, 30)], True),
    ], INK)
    d.arrow(180, 30, 298, 30, INK)
    d.text(238, 21, "Decisions, identities, states", 10.1)
    d.arrow(330, 43, 330, 65, INK)
    d.text(342, 56, "Witnesses", 9.9, align="left")
    d.text(121, 78, "Reference contract", 10.8, "Bold", align="left")
    d.connectors([
        ([(219, 74), (289, 74)], True),
        ([(267, 74), (267, 53), (309, 53), (309, 43)], True),
    ], SECONDARY, dashed=True)
    d.save()


def handoff(output):
    d = Diagram(output, "credential-handoff", 79, COMPACT_WIDTH)
    for x, title in ((52, "Key manager"), (176, "Request wrapper"),
                     (300, "Object endpoint")):
        d.text(x, 16, title, 11.0, "Bold")
        d.lifeline(x, 24, 73)
    for x0, x1, y, label, tag_x in (
        (52, 176, 41, "Project record", 82),
        (176, 300, 65, "Same record + access mode", 181),
    ):
        d.mark(tag_x, y - 12, "record", radius=2.3)
        d.text(tag_x + 7, y - 9, label, 10.1, color=ACCENT, align="left")
        d.arrow(x0, y, x1, y, ACCENT)
    d.save()


def mapping(output):
    d = Diagram(output, "ownership-witness", 97)
    d.text(14, 25, "Read-only key", 10.7, "Bold", align="left")
    d.text(14, 39, "Project 1", 10.5, align="left")
    d.text(14, 74, "GET Object 2", 10.7, "Bold", align="left")
    d.connectors([
        ([(91, 31), (128, 31), (128, 71), (91, 71)], False),
        ([(128, 51), (155, 51)], False),
        ([(155, 51), (155, 25), (186, 25)], True),
        ([(155, 51), (155, 71), (186, 71)], True),
    ], ACCENT)
    for y, title, owner, decision, tone, mark in (
        (25, "Observed", "Owner: Project 2", "Deny", SECONDARY, "open"),
        (71, "Alternative", "Owner: Project 1", "Allow", ACCENT, "solid"),
    ):
        d.text(197, y - 2, title, 10.9, "Bold", align="left")
        d.text(197, y + 13, owner, 10.5, align="left")
        d.arrow(284, y, 317, y, tone)
        d.mark(329, y, mark, tone)
        d.text(339, y + 3.5, decision, 11.4, "Bold", tone, "left")
    d.save()


def square(output):
    d = Diagram(output, "semantic-square", 98, COMPACT_WIDTH)
    prime = math("'", 9.8, 1.5)
    d.text(18, 31, "Source", 11.0, "Bold", align="left")
    d.text(18, 79, "Target", 11.0, "Bold", align="left")
    d.runs(105, 31, [math("s = ν(q)")])
    d.runs(291, 31, [math("s"), prime, math(" = ν(q"), prime, math(")")])
    d.runs(105, 79, [math("q")])
    d.runs(291, 79, [math("q"), prime])
    d.arrow(144, 27, 252, 27)
    d.arrow(126, 75, 270, 75)
    d.runs(198, 16, [math("P"), math("β", 8.5, -1.6), math(" : x / d")])
    d.runs(198, 64, [math("M : x / d")])
    for x in (105, 291):
        d.arrow(x, 65, x, 43, ACCENT, dashed=True)
        d.text(x + 14, 57, "ν", MATH, "Math", ACCENT)
    d.save()


def trace(output):
    d = Diagram(output, "diagnostic-trace", 122)
    for x, value in ((37, 0), (135, 1)):
        d.text(x, 64, f"p = {value}", 13.0, "Math")
    d.arrow(59, 60, 114, 60, ACCENT)
    d.text(86.5, 49, "a / allow", 10.3)
    d.connectors([
        ([(156, 60), (187, 60)], False),
        ([(187, 29), (187, 90)], False),
        ([(187, 29), (311, 29)], True, ACCENT),
        ([(187, 90), (311, 90)], True, SECONDARY),
    ], ACCENT)
    for y, title, value, action, tone, mark in (
        (29, "Target (r, r)", 0, "b / allow", ACCENT, "solid"),
        (90, "Reference (r, t)", 1, "b / deny", SECONDARY, "open"),
    ):
        d.mark(229, y - 14, mark, tone, 2.5)
        d.text(237, y - 10, action, 10.7, "Bold", tone, "left")
        d.text(337, y + 4, f"p = {value}", 13.0, "Math", tone)
        d.text(337, y + 21, title, 10.7, color=SECONDARY)
    d.save()


def transfer(output):
    d = Diagram(output, "evaluation-design", 79, COMPACT_WIDTH)
    d.text(43, 36, "9 boundaries", 10.7, "Bold")
    d.text(43, 52, "78 contexts", 10.5)
    d.connectors([
        ([(76, 39), (99, 39)], False),
        ([(99, 39), (99, 19), (129, 19)], True),
        ([(99, 39), (99, 60), (129, 60)], True),
    ], ACCENT)
    for y, method, result, tone in (
        (19, "Frozen transfer", "5/9 complete", SECONDARY),
        (60, "Source adaptation", "9/9 complete", ACCENT),
    ):
        d.text(142, y + 3.6, method, 10.8, "Bold", align="left")
        d.arrow(234, y, 263, y, tone)
        d.text(276, y + 3.6, result, 10.8, "Bold", tone, "left")
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
