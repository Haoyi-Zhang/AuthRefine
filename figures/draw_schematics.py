"""Place the supplied schematic artwork and exact, selectable PDF labels.

The artwork is not redrawn or raster-edited. The crop is a PDF placement clip.
No external service is used by this script.
"""

import argparse
from pathlib import Path

from reportlab.lib.colors import HexColor
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas

from figure_typography import register_fonts

HERE = Path(__file__).resolve().parent
WIDTH = 396
INK = HexColor("#182c3b")
SECONDARY = HexColor("#34495a")


class Schematic:
    def __init__(self, output, name, crop, bottom=5, top=5):
        self.name = name
        self.left, self.top, right, lower = crop
        self.scale = WIDTH / (right - self.left)
        self.height = (lower - self.top) * self.scale
        self.bottom = bottom
        self.total = self.height + bottom + top
        self.pdf = Canvas(
            str(output / f"{name}.pdf"), pagesize=(WIDTH, self.total),
            invariant=True, initialFontName="Body",
        )
        self.pdf.setTitle(name.replace("-", " ").capitalize())
        self.pdf.setCreator("")
        art = ImageReader(str(HERE / "artwork" / f"{name}.png"))
        if art.getSize() != (2172, 724):
            raise ValueError(f"{name}: artwork dimensions changed")
        self.pdf.saveState()
        clip = self.pdf.beginPath()
        clip.rect(0, bottom, WIDTH, self.height)
        self.pdf.clipPath(clip, stroke=0, fill=0)
        self.pdf.drawImage(
            art, -self.left * self.scale,
            bottom + self.height - (2048 / 3 - self.top) * self.scale,
            width=2048 * self.scale, height=2048 / 3 * self.scale,
        )
        self.pdf.restoreState()

    def at(self, x, y):
        """Map coordinates from the artwork's nominal 2048 by 683 viewport."""
        return ((x - self.left) * self.scale,
                self.bottom + self.height - (y - self.top) * self.scale)

    def text(self, x, y, value, size=9.6, font="Body", color=INK):
        width = pdfmetrics.stringWidth(value, font, size)
        if x - width / 2 < 0 or x + width / 2 > WIDTH or not 2 <= y <= self.total - size:
            raise ValueError(f"{self.name}: label outside canvas: {value!r}")
        self.pdf.setFont(font, size)
        self.pdf.setFillColor(color)
        self.pdf.drawCentredString(x, y, value)

    def label(self, px, py, value, size=9.6, font="Body", color=INK):
        x, y = self.at(px, py)
        self.text(x, y - size * 0.31, value, size, font, color)

    def formula(self, px, py, parts, size=10.8):
        x, y = self.at(px, py)
        widths = [pdfmetrics.stringWidth(value, "Math", size * scale)
                  for value, scale, _ in parts]
        x -= sum(widths) / 2
        self.pdf.setFillColor(INK)
        for (value, scale, shift), width in zip(parts, widths):
            self.pdf.setFont("Math", size * scale)
            self.pdf.drawString(x, y - size * 0.31 + shift, value)
            x += width

    def save(self):
        self.pdf.showPage()
        self.pdf.save()


def workflow(output):
    image = Schematic(output, "analysis-workflow", (24, 167, 2024, 515), bottom=27)
    for x, title, detail in (
        (255, "Source admission", "Bodies and entry rules"),
        (769, "State observations", "Decisions and state"),
        (1280, "Contract diagnosis", "Bindings and witnesses"),
        (1796, "Repair validation", "Replay and compare"),
    ):
        xpos, _ = image.at(x, 0)
        image.text(xpos, 15.2, title, 10, "Bold")
        image.text(xpos, 3.4, detail, 9, color=SECONDARY)
    image.save()


def handoff(output):
    image = Schematic(output, "credential-handoff", (44, 194, 2004, 520), bottom=28)
    for x, title, detail in (
        (349, "Key manager", "Resolve project"),
        (1078, "Request wrapper", "Store project and mode"),
        (1757, "Object endpoint", "Check owner; serialize"),
    ):
        xpos, _ = image.at(x, 0)
        image.text(xpos, 16, title, 10, "Bold")
        image.text(xpos, 4.4, detail, 9, color=SECONDARY)
    image.label(787, 309, "Exact project", 9)
    image.label(1368, 309, "Same identity", 9)
    image.save()


def square(output):
    image = Schematic(output, "semantic-square", (95, 72, 1955, 607))
    prime = ("'", 0.86, 1.25)
    for x, title, target_title, state, target in (
        (450, "Source valuation", "Target state", [("s = ν(q)", 1, 0)], [("q", 1, 0)]),
        (1599, "Next source valuation", "Next target state",
         [("s", 1, 0), prime, (" = ν(q", 1, 0), prime, (")", 1, 0)],
         [("q", 1, 0), prime]),
    ):
        image.label(x, 151, title, 9.4, "Bold")
        image.formula(x, 207, state)
        image.label(x, 481, target_title, 9.4, "Bold")
        image.formula(x, 537, target)
        image.label(x + 55, 348, "ν", 10.8, "Math")
    image.formula(1017, 138, [("P", 1, 0), ("β", 0.75, -1.55), (": x / d", 1, 0)], 9.5)
    image.label(1017, 466, "M: x / d", 9.5, "Math")
    image.save()


def trace(output):
    image = Schematic(output, "diagnostic-trace", (64, 174, 1978, 542))
    for y, title, detail, final, decision in (
        (267, "Target", "implements (r, r)", "p = 0", "b / allow"),
        (464, "Reference", "fixed to (r, t)", "p = 1", "b / deny"),
    ):
        image.label(265, y - 25, title, 10, "Bold")
        image.label(265, y + 33, detail, 9, color=SECONDARY)
        for x, state in zip((645, 1220, 1796), ("p = 0", "p = 1", final)):
            image.label(x, y, state, 11, "Math")
        image.label(923, y - 42, "a / allow", 9.5)
        image.label(1498, y - 42, decision, 9.5)
    image.save()


def transfer(output):
    image = Schematic(output, "evaluation-design", (5, 77, 1850, 673), bottom=3, top=16)
    for x, label in ((400, "Selected entries"), (1024, "Method"), (1646, "Observation")):
        xpos, _ = image.at(x, 0)
        image.text(xpos, image.total - 12, label, 10, "Bold")
    for y, first, second in ((206, "Frozen", "transfer"), (497, "Source", "adaptation")):
        image.label(120, y - 20, first, 9.6, "Bold")
        image.label(120, y + 31, second, 9.6, "Bold")
    for y, labels in (
        (352, ("9 entries", "Frozen pipeline", "Complete or unknown")),
        (648, ("Same 9 entries", "Source adapters", "Same contexts")),
    ):
        for x, label in zip((400, 1024, 1646), labels):
            image.label(x, y, label, 9.2, color=SECONDARY)
    image.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--math-font", type=Path, required=True,
                        help="Path to STIXGeneralItalic.ttf")
    args = parser.parse_args()
    args.output_directory.mkdir(parents=True, exist_ok=True)
    register_fonts()
    pdfmetrics.registerFont(TTFont("Math", str(args.math_font.resolve(strict=True))))
    for compose in (workflow, handoff, square, trace, transfer):
        compose(args.output_directory)


if __name__ == "__main__":
    main()
