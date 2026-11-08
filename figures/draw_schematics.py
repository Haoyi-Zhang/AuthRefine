"""Compose checked scientific diagrams with vector paths and embedded fonts."""

import argparse
from dataclasses import dataclass
from pathlib import Path

from PIL import Image
from reportlab.lib.colors import HexColor
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas

from figure_typography import register_fonts

HERE = Path(__file__).resolve().parent
W = 396
INK = HexColor("#142b3b")
SOFT = HexColor("#405465")
BORDER = HexColor("#546c7b")
PANEL = HexColor("#f4f7f9")
TEAL = HexColor("#e6f1ed")
RUST = HexColor("#964d36")
WARM = HexColor("#f9eee8")


@dataclass(frozen=True)
class Rect:
    x: float
    y: float
    w: float
    h: float

    def intersects(self, other, gap=0):
        return (self.x < other.x + other.w + gap and other.x < self.x + self.w + gap
                and self.y < other.y + other.h + gap and other.y < self.y + self.h + gap)

    def contains(self, other, pad=0):
        return (self.x + pad <= other.x and self.y + pad <= other.y
                and other.x + other.w <= self.x + self.w - pad
                and other.y + other.h <= self.y + self.h - pad)


class Diagram:
    def __init__(self, output, name, height):
        self.h, self.name = height, name
        self.c = Canvas(str(output / f"{name}.pdf"), pagesize=(W, height),
                        invariant=True, initialFontName="Body")
        self.c.setTitle(name.replace("-", " ").capitalize())
        self.c.setCreator("")
        self.canvas = Rect(0, 0, W, height)
        self.modules = []
        self.marks = []

    def reserve(self, bounds, description, parent=None):
        if not self.canvas.contains(bounds, 3) or (parent and not parent.contains(bounds, 4)):
            raise ValueError(f"{self.name}: {description} is too close to its boundary: {bounds}")
        for box in self.modules:
            if box != parent and box.intersects(bounds, 2):
                raise ValueError(f"{self.name}: {description} intersects unrelated module {box}")
        for other, desc in self.marks:
            if other.intersects(bounds, 1.5):
                raise ValueError(f"{self.name}: {description} collides with {desc}")
        self.marks.append((bounds, description))

    def box(self, x, y, w, h, fill=PANEL, border=BORDER, dashed=False):
        r = Rect(x, y, w, h)
        if (not self.canvas.contains(r, 5) or any(r.intersects(m, 4) for m in self.modules)
                or any(r.intersects(mark, 2) for mark, _ in self.marks)):
            raise ValueError(f"{self.name}: module collision: {r}")
        self.modules.append(r)
        self.c.setFillColor(fill)
        self.c.setStrokeColor(border)
        self.c.setLineWidth(0.8)
        if dashed:
            self.c.setDash(3, 1.8)
        self.c.roundRect(x, self.h - y - h, w, h, 3, fill=1, stroke=1)
        self.c.setDash()
        return r

    def text(self, x, y, s, size=10.8, font="Body", color=INK, parent=None):
        self.runs(x, y, [(s, font, size, 0)], color, parent)

    def runs(self, x, y, runs, color=INK, parent=None):
        widths = [pdfmetrics.stringWidth(s, f, size) for s, f, size, _ in runs]
        pos = x - sum(widths) / 2
        upper = min(y - shift - size * .76 for _, _, size, shift in runs)
        lower = max(y - shift + size * .23 for _, _, size, shift in runs)
        self.reserve(Rect(pos, upper, sum(widths), lower - upper),
                     "".join(r[0] for r in runs), parent)
        self.c.setFillColor(color)
        for (s, font, size, shift), width in zip(runs, widths):
            self.c.setFont(font, size)
            self.c.drawString(pos, self.h - y + shift, s)
            pos += width

    def arrow(self, x1, y1, x2, y2):
        if (x1 == x2) == (y1 == y2):
            raise ValueError("Arrow must be a nonzero orthogonal segment")
        d = abs(x2 - x1) + abs(y2 - y1)
        if d < 8:
            raise ValueError("Insufficient arrow channel")
        dx, dy = (x2 - x1) / d, (y2 - y1) / d
        self.reserve(Rect(min(x1, x2) - (0.4 if dx else 3.0),
                          min(y1, y2) - (0.4 if dy else 3.0),
                          abs(x2 - x1) + (0.8 if dx else 6),
                          abs(y2 - y1) + (0.8 if dy else 6)), "arrow")
        bx, by = x2 - 5.5 * dx, y2 - 5.5 * dy
        self.c.setStrokeColor(BORDER)
        self.c.setFillColor(BORDER)
        self.c.setLineWidth(0.95)
        self.c.line(x1, self.h - y1, bx, self.h - by)
        head = self.c.beginPath()
        head.moveTo(x2, self.h - y2)
        head.lineTo(bx - dy * 2.6, self.h - (by + dx * 2.6))
        head.lineTo(bx + dy * 2.6, self.h - (by - dx * 2.6))
        head.close()
        self.c.drawPath(head, fill=1, stroke=0)

    def save(self):
        self.c.showPage()
        self.c.save()


class Artwork:
    """Clip the unchanged atlas at placement; no raster text or resizing."""

    def __init__(self):
        path = HERE / "artwork" / "interface-icons.png"
        self.image = ImageReader(str(path))
        self.w, self.h = self.image.getSize()
        self.crops = []
        with Image.open(path) as raw:
            if raw.mode != "RGBA":
                raise ValueError("Transparent atlas required")
            alpha = raw.getchannel("A")
            for col, row in ((0, 0), (1, 0), (0, 1), (1, 1)):
                x, y = col * self.w // 2, row * self.h // 2
                qw, qh = self.w // 2, self.h // 2
                # Locate visible ink, then keep its original antialiasing halo.
                # This threshold is for placement measurement, not a raster edit.
                bounds = alpha.crop((x, y, x + qw, y + qh)).point(
                    lambda value: 255 if value >= 8 else 0
                ).getbbox()
                if not bounds or not Rect(0, 0, qw, qh).contains(
                    Rect(bounds[0], bounds[1], bounds[2] - bounds[0], bounds[3] - bounds[1]), 6
                ):
                    raise ValueError(f"Atlas quadrant {(col, row)} is empty or crosses the gutter")
                self.crops.append((x + bounds[0] - 5, y + bounds[1] - 5,
                                   bounds[2] - bounds[0] + 10, bounds[3] - bounds[1] + 10))

    def place(self, d, n, x, y, size, parent=None):
        left, top, w, h = self.crops[n]
        scale = size / max(w, h)
        dest = Rect(x - w * scale / 2, y - h * scale / 2, w * scale, h * scale)
        if 72 / scale < 450:
            raise ValueError("Illustration placement below 450 effective dpi")
        d.reserve(dest, f"pictogram {n}", parent)
        clip = d.c.beginPath()
        clip.rect(dest.x, d.h - dest.y - dest.h, dest.w, dest.h)
        d.c.saveState()
        d.c.clipPath(clip, fill=0, stroke=0)
        d.c.drawImage(self.image, dest.x - left * scale, d.h - dest.y - (self.h - top) * scale,
                      self.w * scale, self.h * scale, mask="auto")
        d.c.restoreState()


def workflow(output, art):
    d = Diagram(output, "analysis-workflow", 96)
    rows = ((0, "Admit source", "Entry rules", "Source bodies"),
            (2, "Observe state", "Decisions", "Identity, state"),
            (1, "Diagnose", "Binding family", "Shortest witness"),
            (3, "Check repair", "Replay under", "same contract"))
    for i, (icon, title, a, b) in enumerate(rows):
        x = 6 + 101 * i
        box = d.box(x, 8, 81, 80, TEAL if i == 3 else PANEL)
        xc = x + 40.5
        art.place(d, icon, xc, 25, 18, box)
        d.text(xc, 48, title, 11.1, "Bold", parent=box)
        d.text(xc, 64, a, 10.4, parent=box)
        d.text(xc, 77, b, 10.4, parent=box)
        if i:
            d.arrow(x - 16, 47, x - 4, 47)
    d.save()


def handoff(output, art):
    d = Diagram(output, "credential-handoff", 104)
    d.text(198, 15, "The same project record is carried through both handoffs", 11.1, "Bold")
    for i, (icon, title, detail, extra) in enumerate((
        (1, "Key manager", "Resolve key to", "a project record"),
        (0, "Request wrapper", "Attach record", "and access mode"),
        (3, "Object endpoint", "Compare owner", "and serialize"),
    )):
        x = 8 + i * 137
        box = d.box(x, 25, 106, 72, TEAL if i == 2 else PANEL)
        art.place(d, icon, x + 53, 40, 16, box)
        d.text(x + 53, 61, title, 11.3, "Bold", parent=box)
        d.text(x + 53, 76, detail, 10.5, parent=box)
        d.text(x + 53, 89, extra, 10.5, parent=box)
        if i:
            d.arrow(x - 27, 61, x - 4, 61)
    d.save()


def square(output, art):
    d = Diagram(output, "semantic-square", 141)
    prime = ("'", "Math", 9.8, 1.5)
    def m(s):
        return (s, "Math", 12, 0)
    for i, (x, title, state, target) in enumerate((
        (12, "Source valuation", [m("s = ν(q)")], [m("q")]),
        (247, "Next source valuation", [m("s"), prime, m(" = ν(q"), prime, m(")")],
         [m("q"), prime]),
    )):
        top = d.box(x, 9, 137, 40, TEAL)
        bot = d.box(x, 90, 137, 40)
        xc = x + 68.5
        d.text(xc, 25, title, 11.2, "Bold", parent=top)
        d.runs(xc, 40, state, parent=top)
        d.text(xc, 106, "Next target state" if i else "Target state", 11.2, "Bold", parent=bot)
        d.runs(xc, 121, target, parent=bot)
        d.arrow(xc, 86, xc, 53)
        d.text(xc + 15, 72, "ν", 12, "Math")
    d.arrow(154, 32, 242, 32)
    d.arrow(154, 113, 242, 113)
    d.runs(198, 23, [m("P"), ("β", "Math", 8.5, -1.6), m(" : x / d")])
    d.runs(198, 104, [m("M : x / d")])
    d.save()


def trace(output, art):
    d = Diagram(output, "diagnostic-trace", 129)
    for x, title in ((126, "Start"), (241, "After a"), (356, "After b")):
        d.text(x, 16, title, 11, "Bold")
    for y, title, binding, values, decision in (
        (38, "Target", "implements (r, r)", (0, 1, 0), "b / allow"),
        (84, "Reference", "fixed to (r, t)", (0, 1, 1), "b / deny"),
    ):
        d.text(47, y + 8, title, 11.2, "Bold")
        d.text(47, y + 23, binding, 10.4)
        for i, (x, value) in enumerate(zip((99, 214, 329), values)):
            different = i == 2 and title == "Reference"
            box = d.box(x, y, 54, 30, WARM if different else (TEAL if i == 2 else PANEL),
                        RUST if different else BORDER, different)
            d.text(x + 27, y + 19, f"p = {value}", 12.2, "Math", parent=box)
            if i:
                d.arrow(x - 56, y + 15, x - 5, y + 15)
                d.text(x - 30.5, y + 4, "a / allow" if i == 1 else decision, 10.4)
    d.save()


def transfer(output, art):
    d = Diagram(output, "evaluation-design", 129)
    d.text(198, 16, "Shared inputs: 9 source boundaries, 78 normal contexts", 11.2, "Bold")
    for y, label, how, outcome in (
        (30, "Frozen transfer", ("Run the frozen", "pipeline"), ("Record completion", "and unknowns")),
        (78, "Source adaptation", ("Add source", "adapters"), ("Recheck the", "same contexts")),
    ):
        for i, (x, lines) in enumerate(zip((8, 144, 280), ((label,), how, outcome))):
            box = d.box(x, y, 108, 39, TEAL if y == 78 else PANEL)
            for offset, line in enumerate(lines):
                d.text(x + 54, y + (23 if len(lines) == 1 else 16 + 14 * offset), line,
                       11.0, "Bold" if i == 0 else "Body", parent=box)
            if i:
                d.arrow(x - 24, y + 20, x - 4, y + 20)
    d.save()


def mapping(output, art):
    d = Diagram(output, "ownership-witness", 142)
    d.text(198, 16, "One fixed request, two ownership decisions", 11.4, "Bold")
    box = d.box(8, 54, 110, 69, PANEL)
    d.text(63, 70, "Same request", 11.1, "Bold", parent=box)
    for y, s in ((85, "Read-only key"), (99, "Project 1 record"), (113, "GET Object 2")):
        d.text(63, y, s, 10.5, parent=box)
    # Both comparisons receive the same fixed request.
    d.arrow(123, 63, 171, 63)
    d.arrow(123, 108, 171, 108)
    for y, title, detail, result in (
        (30, "Observed source", "Object 2 belongs to Project 2", "Deny"),
        (86, "Alternative binding", "Object 2 is mapped to Project 1", "Allow"),
    ):
        box = d.box(176, y, 212, 44, TEAL if result == "Deny" else WARM)
        d.text(282, y + 16, title + ": " + result, 11.2, "Bold", parent=box)
        d.text(282, y + 32, detail, 10.7, parent=box)
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
    art = Artwork()
    for compose in (workflow, handoff, square, trace, transfer, mapping):
        compose(args.output_directory, art)


if __name__ == "__main__":
    main()
