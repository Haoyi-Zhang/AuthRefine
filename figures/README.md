# AuthRefine manuscript figures

The manuscript uses six schematics and five vector plots. The workflow and
credential handoff use text-free pictograms from an [illustration atlas](artwork/interface-icons.png)
generated using OpenAI image generation ([prompt](diagram-prompts.md)).
The atlas pixels are unchanged. Its pictograms are clipped at placement and
kept in their own slots; all boxes, arrows, labels and formulas are vector PDF
elements. The other four schematics are entirely vector. The diagram renderer
checks margins, label spacing, icon placement and arrow clearance before saving.

| Vector plot | Retained input |
| --- | --- |
| `source-interface-coverage.pdf` | `source_study/data/source-transfer.json.gz` |
| `adaptation-handling.pdf` | `adaptation_study/casebook.json` |
| `credential-algorithm-cost.pdf` | `source_study/data/credential-cost.json.gz` |
| `width.pdf` | `results/width.csv` |
| `source-screening.pdf` | `adaptation_study/survey.json.gz` |

To redraw the figures, use Python with ReportLab and Pillow. Put the
manuscript's Linux Libertine TeX fonts on the `kpsewhich` search path; the
schematic renderer also requires `STIXGeneralItalic.ttf` for the math labels.
From the artifact directory, pass a fresh output directory to both commands:

    python -B figures/draw_evaluation.py --output-directory /path/to/output
    python -B figures/draw_schematics.py --math-font /path/to/STIXGeneralItalic.ttf --output-directory /path/to/output

No source application or model is executed during drawing. Move the checked
PDFs to the manuscript's `paper/figures` directory to use them in a build.
