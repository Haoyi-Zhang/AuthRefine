# node-casbin batch-policy maintenance input

Original upstream identity: `casbin/node-casbin`, now redirected by GitHub to
`apache/casbin-node-casbin`. Copyright 2018/2019 The Casbin Authors in the retained
source files. Apache License 2.0, included unchanged as `LICENSE`.

The files under `src/`, `test/`, `examples/`, plus `package.json` and `LICENSE`,
are unmodified source bytes fetched from
https://raw.githubusercontent.com/casbin/node-casbin/d8a7cbabb4de50f04261c04eb7551c1f25e13fc7/
on 2026-10-24. Their relative paths are the upstream paths, except
`src/internalEnforcer-parent.ts`: this is `src/internalEnforcer.ts` from parent
`c4b289fd81773c36f4656d442d371b1ed43a12b8`, retained for the API-change boundary.
No upstream NOTICE file is present in that commit's recursive Git tree.

Maintenance event: PR #535, commit
https://github.com/apache/casbin-node-casbin/commit/d8a7cbabb4de50f04261c04eb7551c1f25e13fc7
adds four Ex APIs and six tests. Tag `v5.46.0` resolves directly to this commit
(GitHub git/ref/tags API checked on 2026-10-24). The source package.json still says
5.43.0; that literal metadata is preserved, not replaced with the release tag.

Selected source: `addPoliciesInternal`, `addPoliciesInternalEx` in
`src/internalEnforcer.ts`; `hasPolicy` and `addPolicies` in `src/model/model.ts`;
the public API forwarding functions in `src/managementEnforcer.ts`.
Selected tests: `addPoliciesEx` and `addPoliciesEx - all existing rules` in
`test/managementAPI.test.ts`, including the beforeEach initializer and
`examples/rbac_policy.csv`. The other four new tests are retained but not counted
or modeled (they concern named/grouping APIs).

The owned `src/maintenance_case.py` reads these two tests as data. It executes no
TypeScript, auth service, adapter, watcher, install hook or upstream test runner.
It is an adaptation of the reviewed branch semantics, not native-engine evidence.
`true`/`false` API returns are encoded as allow/deny symbols; these are not access
decisions. The consumer is `hasPolicy`, not `Enforce`.

Admission: one existing `p` policy type, exact three-string rows, no priority,
distinct rows per batch, six-row universe, sequential successful in-memory calls,
no adapter/watcher/role-link effects, errors, concurrent mutation or policy order
observations. The frozen `g` row stays outside this p-store API model. A store
with any other p row is rejected by the decoder, never projected away. All six
membership bits are exposed. The initial four rows and the mixed/all-existing
batches are extracted, not invented. Arbitrary six-row subsets extend those
source tests for finite one-step checking; they are owned inputs, not upstream
test observations.

The legacy API still exists after the change. Its difference from Ex is intended,
not a reported defect. There are no reference aliases in this case; it adds no
evidence of discovered human ambiguity, deployment or external adoption.
