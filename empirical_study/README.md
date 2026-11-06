# Fixed-source empirical study

This is the forty-project source-bound replication described in the manuscript.
The population was already source-exposed. Repository/family identities and a
fixed selection order are retained; these are not fresh blind holdout projects.

Run the offline evidence and original-source checks:

```sh
python -B empirical_study/verify.py
python -B -m unittest discover -s tests -p test_fixed_source_empirical.py -v
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

## Contract review

Submitted source-contract review covers 99 items: two initial assessments and
a separate final adjudication. Final labels are 52 concrete behavior contracts,
45 conditional contracts and two interface obligations. Method and design
review each have eight separate topics. These are source-scope classifications,
not an independent business-intent oracle or confirmed application defects.
Raw submitted opinions and identifying coordination records remain outside the
public artifact. Aggregate outcomes and their limitations are recorded in
`methods.json`; implementation-derived functional expectations remain separate.
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
