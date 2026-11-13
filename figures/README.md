# AuthRefine manuscript figures

The manuscript uses four diagrams and seven vector quantitative figures.
The binding profile and the split trace read the executable two-stage example
in `src/diagnostic_example.py`. They check the transition table, complete
profile and shared prefix before drawing. The credential pair
reads the retained input, observation and ownership records in
`source_study/data/credential-{input,observations,family}.json.gz`. It checks
the shared read context, identical resolved-to-forwarded record, and the
distinct observed results before drawing the two paths from the shared record.
The observed denial is the common input to both comparisons. Only the
disagreeing row shows a witness: the recorded read of the second object.
The matching and disagreeing bindings differ only in the reference's owner
for that object. The prospective transfer figure reads the retained
frozen and adapted observations and checks that both stages use the same
nine boundaries and 78 contexts. The plot counts context agreements separately
from complete boundaries. The linkage figure shows both matched aggregate
counts and the signed per-snapshot changes.

The overview uses high-resolution, image-generated pictograms to identify
the forwarded record, requested objects and reference contract. The two-stage diagnostic
figure pairs a transition graph with a per-binding prefix comparison.
All labels, mathematical notation, observations and connectors are drawn
separately from those pictograms.
The included transparent strip was generated with OpenAI's built-in image
generation tool from the three abstract shapes described in
`pictograms/README.md`; no application records were supplied to that tool.
The source checks margins, label and connector clearance, and a minimum
embedded resolution of 450 dpi. Exact transitions and study observations
use vector marks, not generated pixels.

Use the journal column as the design surface: keep the main observation and
its consequence on the same reading path. Reserve dividers for real changes
of evidence, use type and sparse marks rather than cards, and distinguish
observations from derivations by shape or line style as well as color.
Review the rebuilt figures in the compiled paper before shipping them.

| Vector plot | Retained input |
| --- | --- |
| `source-interface-coverage.pdf` | `source_study/data/source-transfer.json.gz` |
| `evaluation-design.pdf` | `prospective_study/{primary,secondary}.json.gz` |
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

Drawing the overview evaluates the small synthetic diagnostic example. No
source application or external service is executed. Move the checked
PDFs to the manuscript's `paper/figures` directory to use them in a build.
