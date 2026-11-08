# AuthRefine manuscript figures

The manuscript uses six schematics and six quantitative figures, all with
embedded type and vector paths. Text is selectable. The schematic renderer
checks margins, label separation and clearance from connectors before export.
The diagrams define the actual transitions and comparisons, without raster
artwork or external rendering services.

| Vector plot | Retained input |
| --- | --- |
| `source-interface-coverage.pdf` | `source_study/data/source-transfer.json.gz` |
| `adaptation-handling.pdf` | `adaptation_study/casebook.json` |
| `credential-algorithm-cost.pdf` | `source_study/data/credential-cost.json.gz` |
| `width.pdf` | `results/width.csv` |
| `source-screening.pdf` | `adaptation_study/survey.json.gz` |
| `frontend-batch-cost.pdf` | `source_study/data/frontend-cost.json.gz` |

To redraw the figures, use Python with ReportLab. Put the
manuscript's Linux Libertine TeX fonts on the `kpsewhich` search path; the
schematic renderer also requires `STIXGeneralItalic.ttf` for the math labels.
From the artifact directory, pass a fresh output directory to both commands:

    python -B figures/draw_evaluation.py --output-directory /path/to/output
    python -B figures/draw_schematics.py --math-font /path/to/STIXGeneralItalic.ttf --output-directory /path/to/output

No source application or model is executed during drawing. Move the checked
PDFs to the manuscript's `paper/figures` directory to use them in a build.
