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

In this selected eight-case population, five profiles (62.5%) start from supplied
identity facts and three (37.5%) now resolve identity through selected source
bodies and explicit primitives. Six stop before business writes; Healthchecks
and Wger check selected write/readback boundaries. EteSync's credential deletion
and renewal are separate state effects, not business writes. These describe our
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

The connected consumer also resolves the original item-view permission defaults
from source instead of merely accepting hand-entered view slots. It checks the
passive source mixin and the actual frozen native base's eleven-class MRO and
five defining module files before matching the existing finite consumer. Nine
original view declarations share these defaults; this does not multiply the
288 event contexts or the application denominator. Direct scalar declarations
are accepted; rebinding, dynamic permission hooks, reflective slot mutation and
instance/action overrides are not silently treated as absent. Original module
initialization, router dispatch and runtime monkey-patching are not executed.
The original source mixin in `pretix-view-base.txt` retains Pretix's included
AGPL/additional terms. The exact declaration lines and native source bindings
are included in `chained-header.json.gz`.

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
reset-profile results. Class defaults are now source-checked under an explicit
no-instance-override contract; complete grants remain supplied. Session/device/
OAuth fallback, plugins, live servers and deployment are not certified by header
parsing or declaration resolution.

Only a typed observed contract mismatch counts as a detected deliberate fault.
Missing dependencies, ordinary setup errors and unsupported source admission
propagate as errors, not successful negative controls.

## Source-derived default-core grants

`grant_binding.py` removes the supplied complete-grant-output premise for a
separate fixed default-core profile. It extracts the original receiver's nine
literal groups and twelve modern permission names, interprets the original
team grant builder, and resolves its one local registry import to those fixed
source declarations. The original compatibility table supplies seven legacy
checks and the source adds the settings alias. No application module imports
or signal dispatch executes. Additional/replacing plugin receivers are not
inferred from the default receiver.

An important distinction is that the core declares `event.items:write`, not
`event.items:read`. Raw unknown names and legacy names can be stored in a
true-only team configuration, but do not thereby become modern core grants.
Configuration migration is distinct from the compatibility expansion used by
the selected builder. The earlier 288 given-grant contexts and all earlier
authentication/header observations remain unchanged conditional results, not
claims that every supplied name is generated by this default registry.

The complete twelve-bit modern-configuration space, all-permissions flag and
legacy-output flag give 16,384 grant-function comparisons with a separate
direct equation. Eight raw configuration profiles then cross 72 existing
event/method contexts and four credential conditions: 2,304 native-header,
source-authenticator, grant-builder and item-consumer observations. Exactly
576 authenticate; the 192 with event access invoke the grant builder once.
Rejected authentication and absent event access do not evaluate it. Full
source-produced grants are retained; only membership of the declared item
write permission is projected into the existing item-view consumer. This is
not equivalence for arbitrary views, plugin registries or deployed systems.
The raw flags/JSON come from owned SQLite rows and all expected/observed fields
are recomputed. The result contributes no new application or independent gold
sample. Dropping the all-permissions flag, promoting raw unknown keys and
dropping legacy expansion are detected by dedicated owned negative controls.

```
python -B adaptation_study/grant_binding.py --framework /owned/header-framework --check
python -B adaptation_study/grant_binding.py --framework /owned/header-framework --control drop_all
python -B adaptation_study/grant_binding.py --framework /owned/header-framework --control raw_keys
python -B adaptation_study/grant_binding.py --framework /owned/header-framework --control drop_legacy
```

`source-grants.json.gz` records the complete raw configuration profiles,
source lines, produced sets, boundary observations and finite/BFS diagnostic
consumer. `pretix-core-registry.txt` and `pretix-legacy-permissions.txt` are
byte-exact original Pretix sources under the included AGPL/additional terms,
not relicensed by this artifact's MIT license. The original full team source
and Pretix license remain under `../source_study/source/pretix/`.

## Lifecycle and creation boundaries

`token_lifecycle.py` connects the complete original EteSync token lookup,
activity, expiry and renewal bodies to its source-lowered collection/item
queries. Standard UTC datetime arithmetic and owned SQLite token, membership
and revision rows implement the explicit primitive contracts. Source defaults
enable renewal, use a strict sixty-second throttle and set a thirty-day
expiry. The 72 entry observations distinguish 24 authenticated, 30 rejected
and 18 malformed-source-error outcomes. Successful identities feed 288 query
observations. Eight expiry saves and four expired-token deletions are read
back, with unrelated tokens preserved. Fourteen sequential steps check renewal
followed by throttling, deletion followed by absence, and tokens without expiry.

At expiry equal to the current instant, the selected source accepts and renews;
it deletes only when expiry is strictly earlier. An inactive user is rejected
before expiry deletion. A missing second header field produces the source's
IndexError, not an invented ordinary denial. The selected body also does not
validate the first header field; this is recorded as a body boundary, not an
end-to-end HTTP or vulnerability claim. Full APIKeyHeader/DI dispatch, original
ORM managers, arbitrary clock schedules and concurrency remain unassessed.

`owner_insert.py` interprets Wger's selected permission guard and complete
creation body. Sixteen normal contexts vary given authentication facts and
client owner inputs: eight insert the exact request principal through an owned
serializer primitive and SQLite readback; eight stop before insertion. An
unrelated routine stays unchanged. This closes the selected creation boundary,
not full serializer validation, all permission classes or request dispatch.

```
python -B adaptation_study/token_lifecycle.py --check
python -B adaptation_study/owner_insert.py --check
python -B adaptation_study/study.py --check-casebook
```

Saved rows are in `token-lifecycle.json.gz` and `owner-insert.json.gz`. The
original source texts and licenses remain in `sources.json.gz`, not rewritten
as application implementations. Five lifecycle controls exercise omitted save,
omitted deletion, wrong user transfer, disabled renewal and an eager throttle;
three creation controls exercise omitted insertion, client-owner substitution
and a mismatched request. Only actual observation differences count as detection.

## Selected user, trainer and public query scope

`queryset_scope.py` additionally interprets Wger's complete selected
`get_queryset` and its original `request_user_or_trainer_q` helper. A typed Q
predicate contract becomes parameterized selection on an owned SQLite routine
table. Thirty-six contexts vary two supplied users, six session-identity states
and absent/false/true schema-view flags. Twelve schema views return no rows
without invoking the helper or filter. The other 24 preserve the union of own,
truthy trainer-selected and public rows, with no store changes. Missing, null
and zero session entries do not add a trainer owner; a foreign trainer ID with
no row adds no result. Session identity and trainer authority are inputs, not
authenticated or inferred by this selected query.

Four owned fault controls omit trainer scope, omit public rows, substitute the
owner or ignore the schema-view short circuit. Only observed row/call-order
differences count as detection; setup and admission errors propagate.

```
python -B adaptation_study/queryset_scope.py --check
python -B adaptation_study/queryset_scope.py --control omit_trainer
python -B adaptation_study/queryset_scope.py --control omit_public
python -B adaptation_study/queryset_scope.py --control wrong_owner
python -B adaptation_study/queryset_scope.py --control ignore_fake_view
```

`queryset-scope.json.gz` retains the original function identities, all contexts
and exact expected/observed rows. No original ORM, session producer, permission
dispatcher or deployed service executes. This closes the selected helper/query
boundary, not every custom queryset or a trainer-session security guarantee.

The current casebook has 36 exact source-function anchors. It recomputes both
scope counts and handling modes, rather than trusting a manually entered total:

| Handling mode | Axis assignments | Share of 40 assignments |
| --- | ---: | ---: |
| Supported source analysis | 3 | 7.5% |
| Explicit input/configuration | 8 | 20% |
| Source-bound primitive adapter | 22 | 55% |
| Non-admission | 7 | 17.5% |

These are forty case/axis annotations on eight purposive cases, not forty
independent applications or a semantic-accuracy statistic. Identity and business
write proportions use eight cases; the source-construct survey uses 48 selected
snapshots. Only one case now has the complete selected expiry/refresh profile;
the other seven are not labelled as lacking such application behavior.
