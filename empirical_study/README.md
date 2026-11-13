# Fixed-source empirical study

This is the forty-project source-bound replication described in the manuscript.
The population was already source-exposed. Repository/family identities and a
fixed selection order are retained; these are not fresh blind holdout projects.

Run the offline evidence and original-source checks:

```sh
python -B empirical_study/verify.py
python -B empirical_study/review.py
python -B -m unittest discover -s tests -p test_fixed_source_empirical.py -v
python -B -m unittest discover -s tests -p test_review_completion.py -v
```

The primary selection has 76 source functions and 328 finite contexts. Ten
post-exposure path extensions have forty-one original functions and 83 contexts.
They strengthen existing projects rather than add independent samples. Native
and model arms are checked for typed returns, exceptions, provider arguments and
order, and state. Exact source-function entry is observed separately. Prior
administrative defaults and placeholder controls are not application-wide
authorization results. SQLite schema projections and supplied service facts
retain their declared boundaries; framework providers are shared between arms.

`data/inputs.json.gz` contains the frozen population and complete selected
function bodies/normal inputs. `data/sources.json.gz` preserves corresponding
original source modules and source attribution/license material.
`data/observations.json.gz` retains the measured paired observations and costs,
the application-path static counts and the seven-context policy-copy repair
case. These implementation-exposed functional expectations are not independent
expert answers. Timing phases with different envelopes must not be pooled.

Static application-path counts are 2,212 routes in twenty projects, with
800 versus 1,022 fully linked direct dependencies. Four example routes are
separate. Reproducing the archive-wide static scans requires the original full
snapshots at the recorded upstream revisions; selected modules do not stand in
for those archives. The retained observations and the existing source front end
remain available for inspecting that comparison.

## Optional native replay

Use non-root Linux, `/usr/bin/python3` and bubblewrap. Prepare dependencies in
separate directories, without importing or starting an application: Casbin
1.43.0, simpleeval 1.0.8, SQLAlchemy 2.0.55 and typing_extensions 4.16.0 in an
engine site; Django 5.2.17, DRF 3.18.1, asgiref 3.12.1 and sqlparse 0.6.0 in a
framework site; and the Django 6.1.2 package directory for Healthchecks.
The existing `requirements-test.txt` supplies the engine versions. Pure-wheel
dependency preparation is separate from replay; replay has no network access.
Only the Django module is overlaid for Healthchecks; the other framework
packages remain from the framework site. This is not a conflict between the
separate Django paths.

```sh
python -B empirical_study/replay.py \
  --engine-site /absolute/engine/site-packages \
  --framework-site /absolute/framework/site-packages \
  --healthchecks-django /absolute/credential/site-packages/django \
  --output /absolute/new-empty-output
```

This reruns the sixteen pure-boundary projects, the 24 delegated projects and
ten strengthened paths over three repetitions. Each pure-predicate batch runs
native then model within each context. Delegated and extension repetitions
alternate native/model process order. It stops on any scientific-field
difference; it does not compare machine-dependent timing values for equality.
It never imports full source applications, runs their startup hooks or accesses
live systems. Use `--suite primary`, `--suite delegated` or `--suite extensions`
to replay one declared stratum. Pure-predicate repetitions remain separate from
the fresh native/model processes of the delegated and extension strata.

## Interpreting the forty project outcomes

`data/evidence-classification.csv` maps each frozen project to its evidence
category. The project keys resolve to the exact repository and snapshot in
`data/inputs.json.gz`. Ten source-boundary extensions deepen the verification
of the same projects, not the number of findings. R01 is a difference between
documentation and the selected entry contract. R22 records two mismatches in
seven Agentic UX policy/test contexts; both are resolved on a local model copy
without changing the upstream source or the expected outcomes. The remaining
38 records are scoped verification. None of these records establishes an
upstream defect. The verifier checks row identities, extension membership
and the retained local policy comparison before reporting these counts.
`data/evidence-trace.json` links the two exceptions to their retained records
and the upstream material checked. These links provide context; the offline
verifier checks the frozen source identity, record links and mismatch counts
without contacting the upstream projects.

## Contract review

The archived assessments are tool-assisted, not independent human judgments.
Six initial
response files contain 230 answers and three final files resolve all 115 items.
Source-contract review covers 99 items; method and design review each have eight
separate topics. Final source labels are 52 concrete behavior contracts,
45 conditional contracts and two interface obligations. The initial source
category agreement is 83/99 (kappa 0.692); the original sixteen differing labels
are retained rather than replaced by final consensus. These are adjudicated
source-behavior classifications, not a business-intent oracle or confirmed defects.
Raw submitted opinions and identifying coordination records remain outside the
public artifact. `methods.json` includes all 99 label-to-source bindings: 59
redistributable selected entries and forty selected project boundaries. Each
binding records its exact source revision, function anchors, original context
denominators, initial category pair and final resolution. All sixteen method
and design dispositions are also linked. `review.py` checks completeness,
source identity, category totals and their consistency with the executed study.
It resolves every function name and line interval against the original source
syntax, and recomputes agreement counts, disagreement identifiers and kappa for
all three initial pairs. It does not rerun the review or infer reviewer identities. Functional
expectations and source-scope adjudications remain distinct evidence layers.
Original source comments and upstream tests remain primary evidence. Upstream
licenses and attribution apply to those original materials; the project license
does not replace them.

## Costs and support denominators

Static baseline/guarded scans and dynamic native/model replay are different
experiments. Static wall time includes worker startup and output transport;
its process-CPU window starts after imports and ends before serialization.
Primary dynamic repetitions contain both sequential arms in each of three
batches. Delegated repetitions have six arm batches, whose wall values must be
counted once rather than 24 times. The extensions have sixty project/arm
processes. Per-context execution and extension elapsed windows differ. No
unmeasured engineering, preparation or review effort is replaced by zero.

The forty-project table in `methods.json` separates static support, selected
dynamic boundaries and controls. It does not describe every entry of each
application. Nineteen snapshots have unsupported static route forms; R01 has
example routes only. Whole-application prevalence, exhaustive authentication/
write-path coverage and statistical independence are not inferred from these
selected entries. See `SEMANTICS.md` for the observation relation and repairs.
