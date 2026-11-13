"""Compose source, trace and evaluation diagrams from glyphs and vector routes."""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from reportlab.lib.colors import white
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from PIL import Image

from figure_typography import (
    ACCENT, COMPACT_WIDTH, GUIDE, INK, LIGHT, MATH, SECONDARY, TEXT, WIDTH,
    label_size, register_fonts,
)
from binding_overview import draw as worked_overview, run as checked_example
from credential_pair import draw as observed_pair

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

    @contextmanager
    def outline(self, x, y, w, h, name, tone=SECONDARY, tinted=False):
        """Keep the contents inside the outline and the routes outside it."""
        box = Rect(x-w/2, y-h/2, w, h)
        self.reserve(box, name)
        self.marks.pop()
        start = len(self.marks)
        self.c.setLineWidth(.72)
        self.c.setStrokeColor(tone)
        self.c.setFillColor(LIGHT if tinted else white)
        self.c.roundRect(box.x, self.h-box.y-h, w, h, 4, stroke=1, fill=1)
        yield
        for inner, label in self.marks[start:]:
            if not (box.x + 2 <= inner.x and inner.x + inner.w <= box.x + w - 2
                    and box.y + 2 <= inner.y and inner.y + inner.h <= box.y + h - 2):
                raise ValueError(f"{self.name}: {label} does not fit inside {name}")
        del self.marks[start:]
        self.marks.append((box, name))

    def node(self, x, y, w, h, runs, *, tone=SECONDARY, color=INK, tinted=False):
        name = "".join(run[0] for run in runs)
        with self.outline(x, y, w, h, name, tone, tinted):
            self.runs(x, y+3.4, runs, color=color)

    def icon(self, x, y, name, size, cell=None):
        path = PICTOGRAMS / f"{name}.png"
        if cell is None:
            asset = ImageReader(str(path))
        else:
            with Image.open(path) as plate:
                plate = plate.convert("RGBA")
                w, h = plate.size
                image = plate.crop((w * cell // 3, 0, w * (cell + 1) // 3, h))
                bounds = image.getchannel("A").point(lambda n: 255 if n > 32 else 0).getbbox()
                if not bounds:
                    raise ValueError(f"Empty pictogram at {cell}")
                asset = ImageReader(image.crop(bounds))
        pixels_x, pixels_y = asset.getSize()
        scale = size / max(pixels_x, pixels_y)
        w, h = pixels_x * scale, pixels_y * scale
        if 72 / scale < 450:
            raise ValueError(f"{name}: less than 450 dpi at manuscript size")
        box = Rect(x-w/2, y-h/2, w, h)
        self.reserve(box, name)
        self.c.drawImage(asset, box.x, self.h-box.y-h, w, h, mask="auto")

    def rule(self, x1, y1, x2, y2):
        self.connectors([([(x1, y1), (x2, y2)], False)], GUIDE)

    def mark(self, x, y, filled, name, radius=2.9, joined=False):
        box = Rect(x-radius, y-radius, 2*radius, 2*radius)
        # A joint intentionally touches the connectors of the same branch.
        if joined:
            if any(box.intersects(other, 2) for other, label in self.marks
                   if label != "connector"):
                raise ValueError(f"{name}: junction overlaps another mark")
        else:
            self.reserve(box, name)
        self.c.setLineWidth(.6)
        self.c.setStrokeColor(ACCENT if filled else SECONDARY)
        self.c.setFillColor(ACCENT)
        self.c.circle(x, self.h-y, radius, fill=int(filled), stroke=1)

    def connectors(self, routes, color=INK, dashed=False):
        """Clearance-check routed segments; joins within this group are intentional."""
        segments = []
        for points, arrowhead, *stroke in routes:
            last = len(points) - 2
            for i, ((x1, y1), (x2, y2)) in enumerate(zip(points, points[1:])):
                dx, dy = x2 - x1, y2 - y1
                distance = (dx * dx + dy * dy) ** .5
                if not distance:
                    raise ValueError("A connector segment must have nonzero length")
                tip = arrowhead and i == last
                px = max(.55, 2.25 * abs(dy) / distance) if tip else .55
                py = max(.55, 2.25 * abs(dx) / distance) if tip else .55
                box = Rect(min(x1, x2) - px, min(y1, y2) - py,
                           abs(dx) + 2 * px, abs(dy) + 2 * py)
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


def square(output):
    # Two routes around the same commuting square: decode then step,
    # or step then decode. The decision d is emitted by both transitions.
    d = Diagram(output, "semantic-square", 101, COMPACT_WIDTH)
    prime = math("'", 9.8, 1.5)
    d.text(26, 36, "Source", font="Bold", align="left")
    d.text(26, 88, "Target", font="Bold", align="left")
    d.node(117, 32, 78, 22, [math("s = ν(q)")], tone=ACCENT, tinted=True)
    d.node(284, 32, 78, 22, [math("s"), prime, math(" = ν(q"), prime, math(")")],
           tone=ACCENT, tinted=True)
    d.node(117, 84, 42, 22, [math("q")])
    d.node(284, 84, 42, 22, [math("q"), prime])
    d.runs(190, 21, [math("P"), math("β", 8.5, -1.6), math(" : x / d")])
    d.runs(190, 73, [math("M : x / d")])
    d.arrow(160, 32, 241, 32, INK)
    d.arrow(142, 84, 259, 84, INK)
    for x in (117, 284):
        d.arrow(x, 69, x, 47, ACCENT, dashed=True)
        d.runs(x+12, 65, [math("ν")], color=ACCENT, align="left")
    d.save()


def trace(output):
    example = checked_example()
    row = next(r for r in example["profiles"] if r["binding"] == {"z_a": "r", "z_b": "t"})
    first, second = row["trace"]
    if ([s["request"][-1] for s in (first, second)] != ["a", "b"]
            or first["target"] != ["allow", 1] or first["source"] != ["allow", 1]
            or second["target"] != ["allow", 0] or second["source"] != ["deny", 1]
            or not (first["decision_equal"] and first["state_equal"])
            or second["decision_equal"] or second["state_equal"]):
        raise ValueError("Illustrated trace differs from the checked example")

    d = Diagram(output, "diagnostic-trace", 97)
    # Draw the agreed starting observation and the agreed successor only
    # once. Each branch then shows its own decision and successor state.
    d.node(32, 44, 38, 22, [math("p=0")])
    d.node(136, 44, 38, 22, [math(f"p={first['target'][1]}")])
    d.text(84, 36, "a / allow", color=SECONDARY)
    d.arrow(55, 44, 113, 44, ACCENT)
    d.connectors([
        ([(159, 44), (181, 44)], False),
        ([(181, 23), (181, 73)], False),
        ([(181, 23), (273, 23)], True, ACCENT),
        ([(181, 73), (273, 73)], True, INK),
    ], SECONDARY)
    d.mark(181, 44, True, "shared successor", radius=1.4, joined=True)
    for y, title, key, color in ((23, "Target", "target", ACCENT),
                                 (73, "Reference", "source", INK)):
        decision, state = second[key]
        d.text(227, y-8, f"b / {decision}", font="Bold", color=color)
        d.node(296, y, 38, 22, [math(f"p={state}")], tone=color,
               color=color, tinted=key == "target")
        d.text(322, y+4, title, color=SECONDARY, align="left")
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
    for compose in (worked_overview, observed_pair, square, trace):
        compose(args.output_directory)


if __name__ == "__main__":
    main()
