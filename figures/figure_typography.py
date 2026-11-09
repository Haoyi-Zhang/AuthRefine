"""Embedded manuscript fonts shared by the Python figure renderers."""

from pathlib import Path
import os
import re
import struct
import subprocess

from reportlab.lib.colors import HexColor, linearlyInterpolatedColor
from reportlab.pdfbase import pdfmetrics


# PDF points at native size. Match the approximately 10 pt acmsmall body.
WIDTH = 396
COMPACT_WIDTH = 352
TEXT = 9.8
EMPHASIS = 10.0
MATH = 10.9
INK = HexColor("#24282b")
SECONDARY = HexColor("#50595d")
ACCENT = HexColor("#1d5965")
GUIDE = HexColor("#9ca7a9")
GRID = HexColor("#dbe1e2")
LIGHT = HexColor("#edf1f1")


def label_size(font, requested):
    return min(requested, {"Body": TEXT, "Bold": EMPHASIS, "Math": MATH}[font])


def count_tint(value, maximum):
    # Keep adjacent integer levels on opposite sides of the text-contrast break.
    t = value / maximum
    if 0.6 < t < 0.7:
        t = 0.6
    elif 0.7 <= t < 0.775:
        t = 0.775
    return linearlyInterpolatedColor(LIGHT, ACCENT, 0, 1, t)


def tex_file(name):
    if tree := os.environ.get("AUTHREFINE_TEXMF"):
        paths = tuple(Path(tree).rglob(name))
        if len(paths) != 1:
            raise FileNotFoundError(f"Expected exactly one {name} in the supplied font tree")
        return str(paths[0])
    path = subprocess.check_output(["kpsewhich", name], text=True).strip()
    if not path or not Path(path).is_file():
        raise FileNotFoundError(f"Missing manuscript font resource: {name}")
    return path


class LibertineFace(pdfmetrics.EmbeddedType1Face):
    """Read the Type 1 face widths from the exact T1 manuscript metrics."""

    def _loadMetrics(self, tfm_path):
        data = Path(tfm_path).read_bytes()
        lf, lh, bc, ec, nw, nh, nd, ni, nl, nk, ne, np = struct.unpack(
            ">12H", data[:24]
        )
        if len(data) != 4 * lf or not (bc <= 32 and ec >= 126 and np >= 2):
            raise ValueError("Unexpected Libertine metric layout")
        start = 24 + 4 * lh
        width_start = start + 4 * (ec - bc + 1)
        widths = struct.unpack_from(">" + "i" * nw, data, width_start)
        parameters = width_start + 4 * (nw + nh + nd + ni + nl + nk + ne)
        space = struct.unpack_from(">i", data, parameters + 4)[0]
        encoding = pdfmetrics.getEncoding("WinAnsiEncoding")
        self.glyphWidths = {
            encoding[code]: 1000 * (
                space if code == 32 else widths[data[start + 4 * (code - bc)]]
            ) / 2**20
            for code in range(32, 127)
        }
        self.glyphNames = sorted(self.glyphWidths)
        header = self._binaryData[:self._length1].decode("ascii")
        self.name = re.search(r"/FontName\s+/(\S+)", header)[1]
        self.familyName = "Linux Libertine"
        bounds = re.search(r"/FontBBox\s*[{\[]\s*([^}\]]+)", header)[1]
        self.bbox = [int(float(v)) for v in bounds.split()]
        self.ascent, self.descent = self.bbox[3], self.bbox[1]
        self.capHeight, self.xHeight, self.stemV = 643, 429, 79
        self.italicAngle = float(re.search(r"/ItalicAngle\s+([-\d.]+)", header)[1])


def register_fonts():
    for alias, stem in (("Body", "LinLibertineT"), ("Bold", "LinLibertineTB")):
        face = LibertineFace(tex_file(stem + "-lf-t1.tfm"), tex_file(stem + ".pfb"))
        pdfmetrics.registerTypeFace(face)
        pdfmetrics.registerFont(pdfmetrics.Font(alias, face.name, "WinAnsiEncoding"))
