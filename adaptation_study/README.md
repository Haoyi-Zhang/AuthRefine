# Source adaptation study

This study separates application characteristics, analysis admission failures
and validation boundaries. It reuses the original 48 exposed source snapshots
and the original eight deeper cases; the latter are a subset, not eight added
independent applications. No application service, upstream test, exploit or
live endpoint executes.

## Source scope and classification

`sources.json.gz` contains the 236 previously selected Python modules, their
3,909 selected function anchors, exact source identities, original project
metadata and complete selected license texts for all 48 snapshots. These are
the original source files, not implementations by this artifact's authors.
Each keeps its included upstream license; this repository's MIT license does
not relicense third-party material. `pretix-token-source.txt` is the original
selected token authenticator under Pretix's included AGPL/additional terms in
the source collection and `../source_study/source/pretix/LICENSE`.

The survey uses overlapping source-construct labels. Observed identity inputs,
credential-processing code, named mutation calls, identity handoffs, dynamic
lookup, asynchronous flow, query-like calls and exceptions guide adaptation
review. Route decorators are not counted as body mutation calls. A dictionary
update, a serializer save and a database commit are distinct behaviors even
when they share a lexical feature. The survey does not equate a construct with
a permission decision, durable write or requirement for a particular adapter.

Recompute with the same Python 3.14 parser as the source inventory:

```
python -B adaptation_study/study.py --check
```

`survey.json.gz` records one row per original snapshot and each selected
function/line witness. Percentages use 48 snapshots, not endpoints, contexts
or repeated runs. Non-observation means only not observed within the selected
function scope. Parse failures remain unassessed, not negative labels. This
fixed exposed sample is not an estimate of prevalence across GitHub.

`casebook.json` complements the mechanical screen with eight source-anchored
case syntheses. For every case it identifies entry premises, checked consumers,
required configuration/adaptation and non-admitted alternatives. Its five
axes are identity origin, effects after authorization, identity/state handoff,
runtime resolution, and environmental/temporal assumptions. Resolution can
be automatic source analysis, explicit configuration, a source-bound primitive
adapter, or non-admission. These axes overlap. Historical manual effort was
not timed and is not assigned zero or invented retrospectively. The records
are not an independent semantic gold set.

Every case now has one source-witnessed assignment on each of the five axes,
with a concrete handling mode and exact function anchors. This is a descriptive
classification of the checked interface, not automatically inferred policy
intent. Recompute the 40 assignments and their eight-case denominators with:

```
python -B adaptation_study/study.py --check-casebook
```

In this selected eight-case population, six profiles start from supplied
identity facts and two now resolve identity through a selected source body and
native primitives. Seven stop at a guard or query before business writes;
Healthchecks also checks the selected write and readback. These describe our
checked boundaries, not how often the applications themselves omit writes or
authentication. The casebook gives the exact source functions for each row.

## Executed boundary extensions

Use Linux, install `../requirements-test.txt`, and prepare the existing frozen
framework as described in `../source_study/README.md`. Put that framework
directory on PYTHONPATH. Then run:

```
python -B adaptation_study/profiles.py --check
python -B adaptation_study/profiles.py --control drop_save
python -B adaptation_study/profiles.py --control skip_active
```

Healthchecks now follows the original write-authorize wrapper into the complete
selected resume body. The owned native projection observes the flip insertion,
specified field update, unchanged other objects and SQL readback. Across 112
normal contexts, six perform the expected update and 106 reject or conflict
without writes. Both plain and stored-authenticator profiles, read-only keys,
wrong owners, absent objects and already-active objects are represented.
Dropping the save is detected by readback, not hidden behind an allow result.
The primitive save/flip/serialization contracts are explicit; this does not
execute the original ORM methods, outer middleware, transactions or background
notifications, nor certify other write endpoints.

Pretix interprets the complete selected token-authentication body rather than
assuming its active-token result. Active, inactive, deleted and missing token
stores cross the existing 288 token/event contexts: 288 proceed to permission
checking and 864 stop at authentication. Returned token/team facts cross an
explicit representation map into the existing permission profile; physical
object identity across two interpreters is not claimed. Dropping the activity
check is detected. DRF header parsing, alternative session/device/OAuth entry,
plugin grant expansion and concurrent revocation remain outside this profile.
The complete team grant set and resolved view inputs remain supplied.

The recorded expected/observed fields enter the existing finite reset-context
diagnostic, product and ordinary-BFS consumers: 336 write properties and 2,304
entry/permission properties. These are observed projection properties, not
2,640 independent applications or a proof of arbitrary persistent histories.
`profiles.json.gz` retains raw contexts, database observations and consumers;
all fields are recomputed by `--check` before comparison.

## Connected requests and persistent state

The reset-context observations above remain separate. `chained_profiles.py`
adds two connected consumers using the same original applications.

For Healthchecks, an actual reachable request prefix is replayed before the
next request, without resetting the database between those requests. Each
credential-store form reaches eight states over 28 request symbols. All 448
edges across the two forms check the response, persisted records, event
multiplicity, field clearing and preservation of other objects. A repeated
successful resume becomes a conflict without another event.

Three resumed bits represent the store only after checking the complete
owned-store invariant: fixed owners, exactly one event and cleared fields for
each resumed object, and unchanged remaining records. This conditional
projection is closed under the selected sequential operation. The measured
graph feeds the existing target-distance, product and symbolic diagnosis:
one of 27 explicitly supplied owner mappings matches, and the other 26 have
one-request explanations. All 52 excluded-mapping witnesses across the two
store forms replay against actual stores. These explain reference mappings,
not 52 application defects. Original ORM internals, other operations,
concurrency, event ordering across objects and notification delivery are
outside this projection.

```
# Use the original frozen Healthchecks framework on PYTHONPATH.
python -B adaptation_study/chained_profiles.py health --check
python -B adaptation_study/chained_profiles.py health --control lost_save
python -B adaptation_study/chained_profiles.py health --control repeat_write
```

For Pretix, native Django request-header normalization and DRF token header
parsing precede the original selected authenticator body and existing event
permission consumer. The separate frozen native runtime satisfies the selected
source's Django range and DRF minimum; it is not a full Pretix installation.
Fourteen header profiles, four token-store states and 288 existing event
contexts produce 16,128 connected observations: 3,456 are not attempted by the
Token authenticator, 10,944 reject, and 1,728 continue to permission checking.
An absent or other-scheme header is not silently treated as authenticated or
as a token rejection. Source import, inheritance and model bindings are checked
before the selected body is admitted. Missing activity checks and header
delegation are detected by owned deliberate controls.

```
python -B adaptation_study/chained_profiles.py prepare --framework /owned/header-framework
python -B adaptation_study/chained_profiles.py header --framework /owned/header-framework --check
python -B adaptation_study/chained_profiles.py header --framework /owned/header-framework --control header_bypass
python -B adaptation_study/chained_profiles.py header --framework /owned/header-framework --control skip_active
```

`native-header-runtime.json.gz` fixes pure primary-host wheels and every
unpacked file. Preparation does not execute package build hooks. The original
dependency declaration is retained in `pretix-pyproject.toml` under Pretix's
included license. Use separate processes for the two native framework
environments. Current connected observations are in `chained-health.json.gz`
and `chained-header.json.gz`; they do not replace or inflate the earlier
reset-profile results. Resolved view slots and complete grants remain explicit
inputs; session/device/OAuth fallback, plugins, live servers and deployment
are not certified by header parsing.
