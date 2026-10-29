# Source-bound authorization study

The source front end and selected closed-body interpreters connect declared
producers, stores and consumers. Unknown calls remain unknown. The eight case
records cover four centralized and four cross-component source contracts;
seven have conditional normal-context comparisons, and Pretix remains unknown.
The original 12 development, 48 exposed transfer and two auxiliary reservations
retain their roles. Source annotations identify structural clauses and source
locations; they are not an allow/deny outcome gold set.

From the artifact root:

```sh
python -B source_study/verify.py
python -B source_study/replay.py check
```

The portable verifier recomputes complete interpretation families and finite
reset-context tables. It does not rerun all original applications or promote
the source transfer counts to semantic accuracy. The data retain the original
experimental scope and the 20 historical dispositions, including non-admissions.

The credential chain can also be replayed using actual selected Django/SQLite
primitives. On non-root Linux with Python 3.12 or newer, bubblewrap and prlimit,
prepare the frozen pure wheels once in a directory outside the repository:

```sh
python -B source_study/replay.py prepare --framework /tmp/authrefine-framework
python -B source_study/replay.py replay --framework /tmp/authrefine-framework
```

Preparation downloads only the three frozen primary-host wheels, checks their
identities and unpacks them without build hooks. Replay itself has no network,
host home or inherited environment. It interprets ten selected source bodies
as closed data and executes trusted framework primitives on owned normal rows.
The exact returned project identity and read-only/version consumer arguments
are checked. Original application services, serializer content and write
actions do not execute. The selected Healthchecks source and its BSD license
are included under `source/healthchecks`; they retain their own license.

On Ubuntu 24.04, an administrator may need to install `apparmor-profiles` and
load the distro-supplied `/usr/share/apparmor/extra-profiles/bwrap-userns-restrict`
profile with `apparmor_parser -r`. The CI does this on its disposable runner.
This permits namespace setup for the packaged Bubblewrap executable while
retaining broader AppArmor restrictions; it does not disable the host policy
or remove the replay's no-network, no-home, no-capability checks. A failed
namespace preflight stops the replay and retains its actual error.

Algorithm timing and the common native pipeline are separate in the cost data.
The recorded environment is not a required throughput target on another machine.
Data files use lossless `.json.gz` storage; the verifier reads and parses every
compressed dataset and checks the original case-byte identities after decoding.
There is one current copy, not parallel compressed/uncompressed deliveries.
Counts of contexts, table batches or mapping hypotheses are not independent
applications, vulnerabilities or evidence of deployment correctness.

Two further fixed profiles have a complete source/observation consumer:

```sh
python -B source_study/complete_profiles.py
```

For Pretix, three complete original function bodies check 288 owned token/event
contexts with 288 actual SQLite queries and exact event/organizer/grant handoffs.
The entry contract supplies an already validated active team token, resolved
scalar event.items view slots and the complete team grant set. Authentication,
plugin/legacy grant expansion and alternative session/device/OAuth profiles are
not inferred. Unhandled profiles stop as unknown; the earlier broader negative
admission is retained, not changed into a whole-application success.

For H19, the pinned minimum Piccolo source profile is replayed for 18 contexts.
The selected field contract has 26 nonagreeing before-properties and 18 after-
properties out of 180 each. Complete-product/diagnostic consumers retain the
shortest field witnesses. This is a reproducible negative source result, not
an inferred historical package installation or a certified complete repair.

Original Pretix files are passive data under their included AGPL/additional
terms in source/pretix/LICENSE. The selected Piccolo API/ORM source keeps its
original licenses in source/h19. Neither application's modules, services,
upstream tests nor published exploit examples execute.

Conditional model laws are supplied in `proofs/`, with their retained check
results in `data/formal-results.json.gz`. Each is standalone with Lean 4.8.0:

```sh
lean source_study/proofs/ClosureGuardComposition.lean
lean source_study/proofs/DRFGuardComposition.lean
lean source_study/proofs/DRFDynamicFactory.lean
```

The organization/header laws can be checked in the same way. These results
apply to the stated complete predicates and handoffs, not to arbitrary source
extraction, authentication, ORM, concurrency or deployment.

The paper's structural coverage figure is reproducible from the retained
source-transfer records. With Matplotlib installed (the paper build used
3.11.2), run from the artifact root:

```sh
python -B source_study/draw_coverage.py --output ../paper/figures/source-interface-coverage.pdf
```

These are route-linkage counts, not measured semantic accuracy. Plotting is
optional and does not add a dependency to the finite checker or native replay.
