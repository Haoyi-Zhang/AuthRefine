# AuthRefine manuscript figures

The manuscript uses five schematic PDFs and four vector plots. The schematic
artwork in [artwork](artwork/) was generated using OpenAI image generation
([prompts](diagram-prompts.md)). The artwork is kept as supplied; the crop and
scientific labels are set independently in the PDF. The diagrams describe the
workflow, an identity handoff, a commuting square, a two-request witness and a
transfer protocol. They do not depict measured results.

| Vector plot | Retained input |
| --- | --- |
| `source-interface-coverage.pdf` | `source_study/data/source-transfer.json.gz` |
| `adaptation-handling.pdf` | `adaptation_study/casebook.json` |
| `credential-algorithm-cost.pdf` | `source_study/data/credential-cost.json.gz` |
| `width.pdf` | `results/width.csv` |

To redraw the figures, use Python with ReportLab and Pillow. Put the
manuscript's Linux Libertine TeX fonts on the `kpsewhich` search path; the
schematic renderer also requires `STIXGeneralItalic.ttf` for the math labels.
From the artifact directory, pass a fresh output directory to both commands:

    python -B figures/draw_evaluation.py --output-directory /path/to/output
    python -B figures/draw_schematics.py --math-font /path/to/STIXGeneralItalic.ttf --output-directory /path/to/output

No source application or model is executed during drawing. Move the checked
PDFs to the manuscript's `paper/figures` directory to use them in a build.
