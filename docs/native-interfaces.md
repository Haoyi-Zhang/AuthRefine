# Native authorization interfaces

The native entry point checks explicitly admitted source/configuration
interfaces. Source files are parsed, not imported or executed. An accepted
component comparison is not a certification of the whole application.

Run `python src/native_pipeline.py --help` to list modes. Install only one of
`requirements-native.txt` or `requirements-native-pycasbin.txt` in an isolated
environment, and select its matching `AUTHREFINE_RUNTIME` profile. Query modes
also require `requirements-query.txt`. Import/distribution identities are checked;
the two distributions must not share the same `casbin` import location.

`requirements-native-casbin141.txt` is a third isolated profile, selected as
`AUTHREFINE_RUNTIME=casbin-1.41.0`, for a source that pins that exact distribution.
Application cases are not replayed under an incompatible dependency and called
equivalent. A new profile requires its native parser, role depth and own tests
to be checked; installed metadata alone is not semantic evidence.

`requirements-native-casbin137.txt` selects the exact `casbin-1.37.0`
distribution for the YAML gateway source. That release has no StringAdapter;
the bounded generic-test line transport calls its actual native line loader,
whereas the selected gateway study uses its native FileAdapter on owned files.
Other profiles retain their own StringAdapter. YAML regression tests additionally
need `requirements-policy-yaml.txt`; installing that file does not replace the
native engine. Do not overlay different engines in one import location.

The optional source-bound normal DTO/wire comparison additionally uses
`requirements-wire.txt` in an isolated dependency directory. This is the actual
source-declared protobuf6.32.1 library on owned records, not execution of a gRPC
service or generated application module. Pure-Python and upb replays use the
same input set and are not independent application samples.

## Original fixed-interpretation family and source handoffs

`family-diagnosis --reference-json POLICY --machine-json MACHINE` runs the full
fixed-binding profile through target-distance, complete product and decision-
diagram analyses. All supplied hypotheses remain in the family. Each failure
has a replay under one fixed binding; the three same-information profiles must
agree. A candidate matching the native output does not establish intended policy
or whole-application correctness. This is a diagnostic result, not a blanket
Boolean acceptance verdict; inspect classification and complete profiles.

`wrapper --policy-line-syntax native-literals ...` explicitly admits source
policy lines whose quote characters are literal identifier characters. It is
not RFC4180 quote decoding. The original text is loaded by the native engine
and its ordered rows must match the admitted rows before any agreement. The
default strict syntax is unchanged, and nesting is still unsupported.

`call-handoff --source SOURCE --function CALLER --callee CONSUMER --parameters
FORMAL... --inputs JSON` extracts a unique selected call's string arguments,
including a single string template and positional/keyword correspondence. It
projects supplied typed strings only; earlier authentication, guards, runtime
receiver binding and endpoint effects are not executed or certified.

`return-contract --producer-source PRODUCER --producer-function METHOD --source
CALLER --callee CONSUMER` checks a fixed nonempty-tuple return shape, reports
Boolean consumers separately from explicit tuple unpacking, and compares
admitted Boolean tests on owned typed return records with the declared first-
field decision interface. Shadowed receivers and opaque uses remain unadmitted.
Import/constructor bindings and current router registration require separate
source evidence: unmounted legacy code is not an active endpoint finding.

These diagnostic/projection commands return no whole-application acceptance.
Their explicit null acceptance and exit 2 are not policy denial. No supplied
source module or service is imported, started, or exploited.

## Tenant configuration and query ownership

`tenant-configuration --model MODEL --policy POLICY` accepts a specific
five-field role/path/method/tenant-equality schema. Exact/trailing-prefix paths
are partitioned by matching signature. Method patterns must be anchored literal
alternations. Tenant identifiers are abstracted by their equality relation for
each request; this is not a global two-tenant database abstraction.

`query-filter --source SOURCE` interprets a bounded `tenant_filtered` expression
using actual SQLAlchemy SELECTs on owned in-memory records. The expected result
comes from a separate record-filter specification. An identity filter or a
tautology is checkable and can fail; correctness is not assumed from a function
name. This mode does not load an application's database.

`tenant-lookup --model MODEL --policy POLICY --source ENDPOINT --function NAME
--dependency-source DEPENDENCY --query-source FILTER` connects an admitted
permission dependency to a selected UUID lookup. Native authorization and SQL
decisions are measured on owned inputs. The selected source imports, role/tenant
arguments, model, query key, and principal handoff are checked within this
interface. Authentication issuers, dependency overrides, ORM relationship
loading, response serialization and PostgreSQL/async integration are not
certified. The fixture's read-only object-ownership contract is separate from
the source decision under test.

## Source discovery is not a semantic verdict

`source-paths --source SOURCE` records direct enforce-containing functions and
same-file syntactic caller candidates, including permission methods that call a
wrapper. Ambiguous and dynamic bindings are not claimed as verified runtime
edges. `request-scan` separately tries admitted direct request decoders and keeps
unsupported functions in its denominator. Neither mode can certify omitted
imports, arbitrary dynamic dispatch, or a whole repository by itself.
Direct `enforce` sinks also record whether the call is immediately awaited.
An `async def` is not itself evidence that `enforce` returns an awaitable.
Discovery does not guess that return type; bind the actual native provider and
measure its return protocol separately. A Boolean/awaitable mismatch is not
automatically an authorization bypass or a completed application verdict.

## Relational producers and REST source-chain assembly

`relational-seed --adapter-source ADAPTER --model-source MODELS
--user-source USERS --seed SQL` parses a bounded Django Role/Rule/UserProfile
projection and selected literal INSERT records. It never imports those modules
or executes the supplied SQL. Only identity/policy fields are projected; password
and other unselected columns are not persisted. A separate owned in-memory
SQLite join is the relational reference. Source dictionary order is observed:
swapping subject/role can produce a mismatch rather than being normalized away.
This is not execution of Django ORM, its managers/orderings, or a live database.

`rest-configuration --model MODEL --policy POLICY --domain JSON` compares one
admitted role/keyMatch2/literal-method-prefix/explicit-override schema on the
declared finite inputs. Arbitrary path regexes and URL normalization are outside
this mode. The override comes from the actual model literal, not a fixed user.

`rest-application --archive SOURCE_ZIP --settings SETTINGS_MEMBER --seed
SEED_MEMBER --domain JSON` follows the source-declared default permission,
absolute adapter import, relative Role/Rule imports, installed user application,
and literal native-model location. The caller supplies these four inputs, not a
hand-transcribed field map or model path. Renamed package/class/model locations
are covered by owned controls. The selected engine distribution must satisfy
the source's admitted Poetry caret declaration. Duplicate/escaping/linked source
members, missing models, altered request argument order, dynamic settings and
ambiguous imports do not yield a pass. No archive member is extracted or run.

This source-chain mode has a bounded AST shape, not a general Python or Django
semantics. It compares a source-declared default boundary under supplied request
records and a selected seed: module initializers, deployment overrides,
authentication, per-endpoint overrides, ORM behavior and business effects are
not certified. A missing-input or unsupported result is not policy denial.

`proofs/RelationalProjection.lean` proves typed field-order correspondence for
all field values admitted by its projection contract. The development runner
separately checks that the actual source descriptor has those canonical terms
before invoking Lean. This is not a proof of AST extraction, SQL parsing/joins,
CSV serialization, native engine correctness, or a whole application.

## Decoded identity claims and role handoff

`claim-boundary --source USER --enum-source ENUM --model MODEL --policy POLICY
--claims JSON --admin-role ROLE [--no-admin-bypass]` admits one explicit
decoded-claim projection/role-edge/consumer AST shape. Claims are typed owned
records: no JWT, issuer, identity provider, gateway, foreign module or service is
run. The reference combines realm roles with client-qualified roles and the
independently converted static policy. The native side inserts roles produced
by the extracted source slice and checks the actual native engine.

The source's direct-role admin bypass is separate from the model's deny-overrides
effect. A changed client separator is an admitted owned fault control with a
composed mismatch even though the configuration-only baseline is unchanged.
Source role-name/subject equality is not silently assumed impossible. This
does not establish that the policy or issuer's grants are externally correct.

The admitted property aliases an existing realm-role list; repeated reads append
duplicate client roles. A missing realm-role list instead uses a fresh default.
`proofs/ClaimRoleObservation.lean` proves membership-observation stability after
positive repeated reads with fixed client roles while exhibiting changing raw
lists. The runner binds the selected source descriptor separately. Raw payload
identity, serialization, changing/revoked claims and whole Python/application
semantics are explicitly outside that quotient. The owned observation is not a
new upstream security finding.

## YAML producer, persisted store and precedence

`yaml-application --archive SOURCE_ZIP --contexts JSON --domain JSON` discovers
one source class with the admitted YAML producer/consumer methods. It follows
the constructor's settings import and literal defaults to the model, initial
policy and YAML files. No per-project source path, class name, settings field
map or model path is supplied. Renamed packages/classes/fields/parameters are
covered by owned regressions. Zero candidates is missing input; multiple
candidates are ambiguous rather than selected by their comparison outcome.

Admission checks the complete constructor order, exact safe-loader shape,
direct imports and default-path declarations. The two file-creation guards
must be unentered under the explicit existing-file snapshot contract. Native
engine and YAML dependencies must match exact reviewed declarations. Source
modules, settings initializers and file-creation helpers are never executed.
Dynamic paths, extra constructor operations, binding mutations, missing files,
dependency conflicts and incomplete scans do not yield a successful comparison.

This is automation of a declared default-source chain, not arbitrary Python or
startup discovery. Its caller still supplies owned user/group contexts and a
finite resource/action domain. Environment and constructor overrides, Pydantic
initialization, working directory, filesystem/locale behavior, authentication,
route reachability and deployment require separate evidence. Automatically
recovering an already studied source chain is not a new application sample.

`yaml-policy --source SOURCE --model MODEL --policy INITIAL_POLICY --yaml-policy
YAML --contexts JSON --domain JSON` parses bounded plain YAML with the pinned
safe decoder and interprets four selected synchronous methods without importing
the application. Actual native clear/add/save/enforce operations run on owned
temporary files; interpreted rows, independent YAML row comprehension and the
persisted file must agree. The given user/group contexts and finite request
domain include stable custom-rule precedence, group fallback and default policy.

Only the declared source condition vocabulary is compared. Unknown condition
keys and metadata remain present in the input and are reported as not certified
enforced; rate limits and approval requirements are not inferred. The source's
`regexMatch(p.obj,r.obj)` reverses the usual-looking request/policy argument
order and is not silently converted to a glob. Bounded literal resources and a
small custom-rule regex vocabulary are required. JWT/groups, deployment,
arbitrary regexes and full reload histories are outside this interface.

## Database-row loader and ready async consumers

`snapshot-policy --source SOURCE --model MODEL --rows JSON --owners JSON
--requests JSON [--consumer check_permission|enforce]` interprets selected async
method ASTs over owned immutable policy/owner snapshots. Awaited results have
explicit typed tokens: an omitted await cannot become a truthy coroutine.
Database query providers are ours, not Tortoise ORM or an application module.
Only declared scalar fields, bounded list/filter/exists operations and reviewed
native policy operations exist in this interpreter.

The actual row loader's field order and NULL compaction, global administrator,
domain hierarchy and resource-owner keys are observed. An independent relational
and graph contract generates expected decisions; it is not read back from the
native engine. Nullable holes, extra fields, long/cyclic role graphs, primitive
shadowing and altered model/accessor/initialization guards are not certified.

The caller must establish an already-initialized consistent snapshot. Startup
locks, User-role synchronization, ORM semantics, writes, cache freshness,
transactions, issuers and endpoints are not proved by this comparison. The two
consumers have different contracts: `enforce` has no owner bypass. The original
checker's 32-resource limit is unchanged: all finite, stateless observation
chunks must pass, and a later chunk's mismatch is retained. This is not a proof
of arbitrary async extraction or stateful histories.

## Selected historical source outcomes

`historical-boundary --source SOURCE --interface session-filter|sync-permissions|post-transform-guard`
compares three admitted source fragments on fixed, disclosed owned input domains.
It never imports the affected application or runs an advisory example. Session
filtering observes output membership on supplied access bits/block counts. The
synchronous-permission interface retains callback denial, next-resolver calls,
awaitable-context errors and coroutine-close effects as distinct observations.
A custom falsy awaitable is not assumed truthy. Counts of different observations
are not counts of vulnerabilities or unauthorized requests.

The post-transform interface admits only the non-injected, explicitly versioned
`get_tool` prefix. It observes the selected original and transformed component,
visibility and supplied authorization bits. Implicit version fallback, resources,
templates, prompts, tool execution and the provider's actual authorization
predicate are outside it. Original guards are interpreted from the selected AST,
not replaced by the expected condition. A 32-context comparison is not 32
applications or execution of a component service.

`observation_protocol.py` encodes domain results and explicit effect flags in a
bounded observation-capture event. Its core acknowledgement is not a permission
grant. An exception is not silently erased into ordinary denial. The one-call
protocol does not certify arbitrary application histories. Every finite chunk
must agree; a later mismatch cannot be hidden by an earlier successful chunk.
`proofs/OutcomeObservation.lean` proves fixed-length Boolean packing injective;
the actual Python one-through-seven-bit envelope is bound separately on all
254 vectors. This elementary representation lemma is not extractor soundness
or a new security theorem.

## Current-instance and persistent exact-row stores

`persistent-store --source SOURCE --model MODEL --rows JSON --initial-store N`
binds one complete admitted constructor and add/remove/async-authorize fragment.
It constructs the actual native engine with two owned file paths, matching the
source constructor protocol. The default independent contract requires successful
updates to change both in-memory and stored policy; restart reloads that file.
The complete universe has at most three rows/six state bits. Cell initialization
is owned measurement setup, not a claim that every cell is production-reachable.
The original checker then searches from the declared initial state.

`--memory-only` checks current-instance set behavior without claiming persistence.
`--owned-explicit-save` is a separately labelled repair control; it does not modify
upstream source or prove that the original application already saves. Enabling
auto-save alone is not assumed to make FileAdapter mutations durable. Boolean
API results are not permissions to administer a policy. Error paths, no-file
construction, JWT, administrative RBAC, concurrency, crash recovery and full
application operation remain outside this fragment.

## Serial domain-role update closures

`domain-role-updates --source SOURCE --model MODEL` parses three complete source
closures behind the admitted getter/lock/awaited-threadpool bridge. No actual
application module, database, threadpool or lock is run. On the explicitly owned
two-role/two-tenant domain, the source-derived operation sequence calls the
reviewed native role API, followed by a direct native permission check.

Independent set contracts distinguish adding one role, replacing all current
roles, and removing the target user's tenant membership. Other-user and other-
tenant sentinel rows, unexpected produced groupings and native errors remain
observable. This is a 40-context selected serial comparison, not SCD2 history,
database transaction/adapter verification or certification of the full ordered
permission-check/bypass chain. The native distribution must be recorded: a
source-pinned pycasbin API is not interchangeable with another package simply
because both expose an import called `casbin`.

## Versioned source cache and permission snapshots

`version-cache --source SOURCE --model MODEL --epochs JSON --requests JSON`
interprets the selected complete version-cache, tuple-subject, authorization,
required-permission and snapshot methods. Owned repository capabilities provide
typed active rows and one stable epoch during each call. Actual native engines
are constructed from the source-produced rows; the custom subject matcher is
interpreted from its source AST. The independent oracle uses user/role-prefixed
subjects, explicit deny-overrides and four resource-prefix snapshot sets.

Requests and snapshots retain cold hits, warm hits and epoch changes. Provider
failures are explicit unavailable-source errors, not ordinary denials. The
serial reload-region contract is not a proof of the real lock, concurrent
transaction isolation, MySQL, query execution, identity issuer or deployment.
The caller's epoch mapping must be immutable: reusing a version for different
rows invalidates this particular contract.

`proofs/EpochCache.lean` proves that refresh preserves cache validity and consumer
observations over arbitrary finite epoch histories, under an initially valid
cache, immutable epoch payload and corresponding consumer premises. The runner
separately binds the actual source body and owned native histories. This is a
conditional memoization obligation, not a novel authorization theorem or proof
of arbitrary extraction, ORM isolation or concurrency.

## Cache-first decisions, failures and audit coverage

`cache-first --source SOURCE --model MODEL --policy POLICY` compares the selected
complete check method with its declared fixed owned role matrix. A different
policy is rejected rather than checked against the same hardcoded oracle.
Cache Success/Failure, miss, allow, deny and unrecognized payloads are separate
owned values. Native call attempts and actual native calls are counted apart:
an injected owned failure is not an actual call or another application.

Cache-hit returns, source TTL/namespace, fail-closed native errors, writes, audit
and logging are observed. Cache-provider and audit-provider errors retain their
own effects and ordering. In the selected source, cache hits precede the audit
callback; the stronger all-checks-audited contract is therefore compared
separately and does not pass. This documentation/effect-coverage difference is
not automatically a new vulnerability. Real cache expiration/invalidation,
PostgreSQL, Redis, audit persistence and concurrent role changes are not tested.

## Complete selected request guard and nonawaitable results

`request-outcomes --source SOURCE --model MODEL` interprets two complete selected
module functions: authenticated-record retrieval and the request guard. The
fixed owned matrix and 1,176 identity/resource/action/provider contexts retain
unauthenticated and missing-context errors, the explicitly supplied bypass
contract, provider unavailability, native calls, allowed results, denials and
audit presence. It does not compare audit payload correctness. It requires
the admitted domain-role/wildcard model; its oracle is not applied to arbitrary
policies or externally issued role entitlements.

An actual synchronous native Boolean consumed by a source `await` yields an
explicit TypeError observation. It is not a normal deny, a truthy coroutine, a
new security finding or an execution of the source application. A separately
labelled owned direct-Boolean control tests this protocol repair; it is not an
upstream patch. Source getter/construction binding is checked separately;
database/startup, JWT, all endpoint bindings and deployment overrides remain
unverified. Module/class rebindings and primitive shadowing are rejected.

The shared `effect_slice.py` interpreter exposes only typed data and explicitly
supplied owned capabilities. Async work is deferred until await; lexical
closures share enclosing bindings, exception handlers resolve their bound types,
and exception targets are cleared on exit. Budget and admission failures cannot
be caught by a source Exception handler. This bounded fragment is not a general
Python semantics or a mechanized sound extractor.

## Local record-construction block

`python -B src/record_projection.py --source SOURCE --function NAME --record NAME
--barrier STATEMENT --cases JSON --receipt NEW_PATH` also accepts `--archive ZIP
--member RELATIVE` in place of `--source`. The barrier is parsed, never executed.
The selected unique dictionary assignment and immediately adjacent loops are
transported without changing executable AST. They must end at that exact
reviewed barrier; an unknown statement is not skipped. The source module is
not imported. No manually transcribed output-field function is supplied.

Cases supply every required bounded plain input binding and a separate expected
mapping. The interpreter supports bounded enumerate/local tuple unpacking and
string-keyed plain dictionary writes. Nested capabilities, deferred operations,
host objects, cycles, primitive shadowing and exhausted budgets cannot become
successful plain data. Exact comparisons distinguish Boolean and integer values.
All planned cases remain in the denominator; a later mismatch remains a mismatch
even if an earlier case was unsupported. Existing receipts are not overwritten.

This contract starts at the local record assignment. Earlier guards/providers,
full-function reachability, runtime transport and unselected consumers require
separate evidence. The D06 deployment uses this actual AST projection with
independently supplied value-preservation expectations and pinned protobuf;
its source-bound sender/receiver constructor templates are not a general RPC
extractor. Native protobuf execution is not application or device execution.

## Source-rooted native file and pure-method discovery

`python -B src/native_pipeline.py file-wrapper-application --archive SOURCE.zip
--ordered-method-contract principal-resource-action --receipt NEW_PATH`
discovers direct Casbin file constructors and selected pure decision methods.
No project member path, class name, configuration path or parameter-name map
is supplied. The positional role contract is explicit input, not inferred
authentication semantics. Renaming those source identifiers does not change
the admitted interface.

Only literal source-rooted Path expressions, a direct two-file constructor,
static import/re-export chains, a source-compatible exact engine dependency,
and the previously supported pure three-argument return fragment are admitted.
Alternative import-root interpretations must all select the exact same source
class; unresolved/ambiguous constructions remain in the result. Configuration
paths based on an unknown working directory, dynamic path values, extra
initializer effects, receiver descriptors, trusted-primitive rebindings and
aggregate work exhaustion do not produce agreement. All source is parsed,
never imported or executed.

The result concerns the selected constructor/method under fixed file and
ordered-input contracts. It does not certify startup's import environment,
credentials, all callers, policy mutation or other methods. The original D06
archive replays the same 1,080 native wrapper decisions; this removes manual
source wiring without adding an application or independent semantic sample.

## Source-rooted ready-snapshot discovery

`python -B src/native_pipeline.py snapshot-application --archive SOURCE.zip
--rows ROWS.json --owners OWNERS.json --requests REQUESTS.json --ready-interface
--receipt NEW_PATH` discovers the supported async row-loader/owner/global-role
consumer interface, its source-rooted native model file, imported schema and
nearest package declaration. No per-project file paths, service class, schema
import module or model map is supplied. Class and package identifiers can change;
the supported six-method semantic interface and typed input roles are explicit.

The archive's projected Tortoise columns are checked for scalar type, nullability
and literal text capacity. Supplied rows must fit those bounds. The native
distribution must satisfy the source's admitted lower-bound declaration. A source
Python minimum is reported separately from the host AST interpreter; agreement
does not establish a complete runnable application environment. Competing import
roots, dynamic/CWD-based paths, primitive rebindings, unsupported schema and work
exhaustion do not become successful comparisons. All discovered candidates remain
in the outcome, including a failed candidate beside an admitted one.

`--ready-interface` asserts a caller-given initialized, immutable snapshot state;
it is not inferred initialization or actual ORM execution. Model-file origin is
a syntactic declaration: startup guards, locks, administrator synchronization,
identity issuance, transactions, later mutations and concurrent calls require
their own evidence. The original D07 archive reproduces the same189 request cells
and156 native enforce operations without importing its application or ORM.

## Source-rooted version-cache discovery

`python -B src/native_pipeline.py version-cache-application --archive SOURCE.zip
--epochs EPOCHS.json --requests REQUESTS.json --default-model --stable-epochs
--receipt NEW_PATH` discovers the supported five-method cache/snapshot service,
its default source-rooted model and nearest exact native dependency. The caller
does not supply service paths, class names, model-file maps or record-field maps.
The imported protocol names and supported method grammar are still explicit;
this is not arbitrary Python or authentication-intent inference.

The actual local cache and imported permission-snapshot frozen dataclass
declarations are checked for constructor field order, annotations, default and
method absence. Source exception-class contracts and default-model parameter
binding are checked separately. These extra checks prevent a hand-written
record constructor from silently replacing a different declared constructor.
The older `version-cache` slice command supplies record constructors as explicit
given contracts; it does not by itself establish these imported source shapes.

Both flags are substantive premises: no caller model override and a stable
immutable repository epoch during each invocation, starting with a supplied
empty coordinator cache and serial lock. That initial state is not inferred
from executing the constructor. Initialization, actual SQL,
issuer validity, runtime import hooks and concurrent snapshots are not certified.
The original D08 source replays the same320 authorization and32 snapshot contexts;
the twelve-archive audit records one comparison and eleven missing-input cases,
not twelve general automatic applications or extra independent samples.

## Result interpretation

- Exit 0: the stated admitted comparison agrees.
- Exit 1: an admitted comparison has a mismatch, with scoped evidence.
- Exit 2: no complete semantic verdict: discovery only, unsupported input,
  partial coverage, missing dependency/input, native error, or exhausted budget.

`--receipt NEW_PATH` writes a new receipt without replacing an existing one.
Use the full receipt's scope and unresolved boundaries, not exit status alone.
Owned mutation controls are not new security findings or additional applications.

## Cache component and formal scope

`cached_factory.py` recognizes a strict acquire/authorize/clear native file
factory pattern. Its comparison distinguishes stored permission, loaded
permission and cache readiness. Caller-protocol-disabled edges are excluded
explicitly; a missing reachable enabled edge is inconclusive, not a denial.
`proofs/CachedFactory.lean` checks the bound finite measured table and arbitrary
length traces admitted by the declared caller protocol. The research verification
runner checks table/interface identity before invoking Lean. This does not prove
arbitrary Python extraction, configuration resolution, concurrency or deployment
correctness.
