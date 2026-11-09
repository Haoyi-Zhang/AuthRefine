"""Compose source, trace and evaluation diagrams from glyphs and vector routes."""

import argparse
from dataclasses import dataclass
from pathlib import Path

from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas

from figure_typography import (
    ACCENT, COMPACT_WIDTH, GUIDE, INK, MATH, SECONDARY, TEXT, WIDTH,
    label_size, register_fonts,
)

PICTOGRAMS = Path(__file__).resolve().parent / "pictograms"


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

    def icon(self, x, y, name, size):
        asset = ImageReader(str(PICTOGRAMS / f"{name}.png"))
        pixels_x, pixels_y = asset.getSize()
        scale = size / max(pixels_x, pixels_y)
        w, h = pixels_x * scale, pixels_y * scale
        if 72 / scale < 450:
            raise ValueError(f"{name}: less than 450 dpi at manuscript size")
        box = Rect(x-w/2, y-h/2, w, h)
        self.reserve(box, name)
        self.c.drawImage(asset, box.x, self.h-box.y-h, w, h, mask="auto")

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
    d = Diagram(output, "analysis-workflow", 143)
    d.icon(20, 31, "workflow-source", 20)
    d.icon(20, 76, "workflow-conditions", 20)
    d.text(35, 34.5, "Source snapshot", align="left")
    d.text(35, 79.5, "Entry conditions", align="left")
    d.icon(165, 53, "workflow-observe", 23)
    d.text(165, 30, "Observe", 10, "Bold")
    d.icon(285, 53, "workflow-compare", 23)
    d.text(285, 30, "Compare", 10, "Bold")
    d.icon(360, 99, "workflow-replay", 21)
    d.text(360, 135, "Replay repair", 10, "Bold")
    d.connectors([
        ([(110, 31), (125, 31), (125, 76), (110, 76)], False),
        ([(125, 53), (150, 53)], True),
    ], INK)
    d.arrow(180, 53, 270, 53, INK)
    d.text(224, 42, "Decision, identity, state", 9.4)
    d.connectors([([(300, 53), (360, 53), (360, 85)], True)], INK)
    d.text(332, 44, "Witnesses", 9.4)
    d.icon(158, 105, "workflow-contract", 18)
    d.text(172, 108.5, "Reference contract", 10, "Bold", align="left")
    d.connectors([
        ([(270, 105), (335, 105), (335, 99), (346, 99)], True),
        ([(285, 105), (285, 67)], True),
    ], SECONDARY, dashed=True)
    d.text(278, 125, "Edited boundary", 9.4)
    d.connectors([([(317, 122), (360, 122), (360, 113)], True)], INK)
    d.save()


def handoff(output):
    d = Diagram(output, "credential-handoff", 104, COMPACT_WIDTH)
    for x, title, icon in ((52, "Key manager", "handoff-key"),
                           (176, "Request wrapper", "handoff-wrapper"),
                           (300, "Object endpoint", "handoff-endpoint")):
        d.icon(x, 19, icon, 23)
        d.text(x, 42, title, 10, "Bold")
        d.lifeline(x, 49, 98)
    for x0, x1, y, label, tag_x in (
        (52, 176, 68, "Project record", 85),
        (176, 300, 91, "Same record + access mode", 183),
    ):
        d.icon(tag_x, y - 12, "handoff-record", 9)
        d.text(tag_x + 8, y - 9, label, 9.3, color=ACCENT, align="left")
        d.arrow(x0, y, x1, y, ACCENT)
    d.save()


def mapping(output):
    d = Diagram(output, "ownership-witness", 101)
    d.icon(22, 34, "ownership-key", 20)
    d.icon(22, 78, "ownership-object", 20)
    d.text(37, 31, "Read-only key", 10, "Bold", align="left")
    d.text(37, 45, "Project 1", align="left")
    d.text(37, 81, "GET Object 2", 10, "Bold", align="left")
    d.connectors([
        ([(112, 34), (126, 34), (126, 78), (112, 78)], False),
        ([(126, 55), (146, 55)], False),
        ([(146, 55), (146, 29), (165, 29)], True),
        ([(146, 55), (146, 79), (165, 79)], True),
    ], ACCENT)
    for y, title, owner, decision, tone, sign in (
        (29, "Observed binding", "Owner: Project 2", "Deny", SECONDARY, "deny"),
        (79, "Alternative binding", "Owner: Project 1", "Allow", ACCENT, "allow"),
    ):
        d.icon(178, y, "ownership-project", 16)
        d.text(191, y - 1, title, 9.6, "Bold", align="left")
        d.text(191, y + 13, owner, align="left")
        d.arrow(287, y, 316, y, tone)
        d.icon(330, y, f"ownership-{sign}", 14)
        d.text(342, y + 3.5, decision, 10, "Bold", tone, "left")
    d.save()


def square(output):
    d = Diagram(output, "semantic-square", 98, COMPACT_WIDTH)
    prime = math("'", 9.8, 1.5)
    d.icon(17, 27, "commutation-valuation", 16)
    d.icon(17, 75, "commutation-state", 16)
    d.text(30, 31, "Source", 10, "Bold", align="left")
    d.text(30, 79, "Target", 10, "Bold", align="left")
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
    d = Diagram(output, "diagnostic-trace", 118)
    for x, value in ((37, 0), (135, 1)):
        d.icon(x, 56, f"diagnosis-register-{value}", 19)
        d.text(x, 80, f"p = {value}", MATH, "Math")
    d.arrow(51, 56, 121, 56, ACCENT)
    d.text(86, 45, "a / allow", 9.5)
    d.text(86, 101, "Shared prefix", 9.3, color=SECONDARY)
    d.connectors([
        ([(149, 56), (187, 56)], False),
        ([(187, 29), (187, 90)], False),
        ([(187, 29), (305, 29)], True, ACCENT),
        ([(187, 90), (305, 90)], True, SECONDARY),
    ], ACCENT)
    for y, title, value, action, tone, sign in (
        (29, "Target (r, r)", 0, "b / allow", ACCENT, "allow"),
        (90, "Reference (r, t)", 1, "b / deny", SECONDARY, "deny"),
    ):
        d.icon(228, y - 14, f"diagnosis-{sign}", 11)
        d.text(238, y - 10, action, 10, "Bold", tone, "left")
        d.icon(319, y, f"diagnosis-register-{value}", 18)
        d.text(348, y + 4, f"p = {value}", MATH, "Math", tone)
        d.text(348, y + 21, title, 9.5, color=SECONDARY)
    d.save()


def transfer(output):
    d = Diagram(output, "evaluation-design", 85, COMPACT_WIDTH)
    d.icon(43, 29, "transfer-cohort", 20)
    d.text(43, 53, "9 boundaries", 10, "Bold")
    d.text(43, 67, "78 contexts")
    d.text(304, 13, "Boundaries complete", 9.3, color=SECONDARY)
    d.connectors([
        ([(76, 51), (99, 51)], False),
        ([(99, 51), (99, 24), (119, 24)], True),
        ([(99, 51), (99, 72), (119, 72)], True),
    ], ACCENT)
    for y, method, result, tone, icon in (
        (24, "Frozen transfer", "5/9", SECONDARY, "frozen"),
        (72, "Then adapt source", "9/9", ACCENT, "adapt"),
    ):
        d.icon(133, y, f"transfer-{icon}", 16)
        d.text(145, y + 3.6, method, 10, "Bold", align="left")
        d.arrow(234, y, 263, y, tone)
        d.text(304, y + 3.6, result, 10, "Bold", tone)
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
