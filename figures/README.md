# AuthRefine manuscript figures

The manuscript uses six illustrated schematics and six vector quantitative
figures. Text, mathematical notation and connectors are typeset separately
from the high-resolution transparent pictograms in `pictograms/`.
Each pictogram denotes a specific input, component, state or outcome.
The diagram source checks margins, label and connector clearance, and a
minimum embedded image resolution of 450 dpi at the manuscript size.

| Vector plot | Retained input |
| --- | --- |
| `source-interface-coverage.pdf` | `source_study/data/source-transfer.json.gz` |
| `adaptation-handling.pdf` | `adaptation_study/casebook.json` |
| `credential-algorithm-cost.pdf` | `source_study/data/credential-cost.json.gz` |
| `width.pdf` | `results/width.csv` |
| `source-screening.pdf` | `adaptation_study/survey.json.gz` |
| `frontend-batch-cost.pdf` | `source_study/data/frontend-cost.json.gz` |

To redraw the figures, use Python with ReportLab. Put the
manuscript's Linux Libertine TeX fonts on the `kpsewhich` search path
(or set `AUTHREFINE_TEXMF` to their TeX font tree). The schematic renderer
also requires `STIXGeneralItalic.ttf` for the math labels.
From the artifact directory, pass a fresh output directory to both commands:

    python -B figures/draw_evaluation.py --output-directory /path/to/output
    python -B figures/draw_schematics.py --math-font /path/to/STIXGeneralItalic.ttf --output-directory /path/to/output

No source application or model is executed during drawing. Move the checked
PDFs to the manuscript's `paper/figures` directory to use them in a build.
