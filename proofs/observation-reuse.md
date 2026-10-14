# Invocation-local reuse of complete source cells

## Contract and argument

`verify_reachable(..., reuse_observations=True)` is an opt-in implementation of
the existing complete-state/Cartesian predicate. The default remains unchanged.
Inputs are fixed during an invocation: policy, typed candidate domains, membership,
request alphabet and machine are not concurrently mutated. No entry survives a
call, and no producer supplies the cache or its values.

For a complete source observation s and request x, define
f(s,x,beta) = F(P,beta,s,x). The function depends on P, s, x and the fixed binding,
not the target identifier q. A cell is stored only after every assignment to its
conservative support passes, proving f(s,x,beta) = y for every admitted complete
binding by the existing support lemma. At another target state with observation
s, the checker still compares that state's decision and successor observation to
y. Equality establishes the same universal cell equation without interpreting
the policy again. Inequality is a real bad cell: the first canonical support
assignment extends to a fixed complete binding, and its source output is y.

The implementation retains every target state, edge and predecessor. It does
not merge observation fibers or assume coherence. FIFO order and the first bad
cell therefore remain unchanged. The shortest-prefix argument supplies a
matching prefix under the selected complete binding, which is independently
replayed from the declared initial source state. A different later edge with the
same source observation cannot pass merely because a prior cell passed.

Consequently, at sufficient work limits the acceptance verdict, shortest length,
binding, path, replay and optional ordered cell records equal the non-reusing
algorithm's. Schema validation, initial mismatch, full post-state equality,
logical binding-cap preflight and replay guards remain unchanged. Work exhaustion
can differ because physical work differs, but still returns inconclusive and
withholds incomplete witnesses. This is memoization of an already proved cell
equation, not new semantic information from a region list or a new refinement
relation. It neither hides source-state bits nor establishes native execution.

## Cost model

Let R be reachable target states and V their distinct complete observations.
For successful checks, the non-reusing reference call count is

    sum(q in R, x in X) product(z in D(P,nu(q),x)) |C(z)|.

With reuse the physical count is

    sum(s in V, x in X) product(z in D(P,s,x)) |C(z)|.

Every target edge still incurs validation/traversal/comparison work. The cache
has at most |V||X| entries, each retaining one output and its support list:
O(sum(s in V,x in X)(1+|D(P,s,x)|)) stored scalar/name handles under a unit-cost
hash/field model, additional to inputs, graph bookkeeping and output. It can add
work and memory when all observations are unique. It does not remove the
exponential support factor, schema/table input cost, or target storage.

The legacy-named `binding_evaluations` field in opt-in mode is the original
logical obligation count, including cached obligations; its cap is intentionally
unchanged. `physical_binding_evaluations` counts actual local reference calls
(not witness replay); `reused_cells` counts checked cache hits, including a hit
that exposes a different target output; `reuse_entries` counts stored passed
cells. Declared work additionally precharges lookup, storage and cached witness
binding construction. As before, these units are not processor instructions or
an independent memory cap. Physical replay and all actual CPU samples are retained
in the measurement boundary, not inferred from logical counts.

## Rechecked historical obligations

`results/same-information-recheck-20261014.json` repeats the complete portable
comparison: 9,985 completed main-workflow cases, 9,977 actual complete-binding
products (eight wide products still omitted), 54,398 evaluations per default
method, and 9,012 equivalent candidates. All 49 retained examples agree in
verdict and shortest length. The 9,936 generated policies still yield 2,215
distinct initialized named one-step tables and 9,772 canonical ASTs, with maximum
semantic multiplicity 791 and 139,088 compiler/reference step comparisons.
These tables include unreachable valuations and binding interfaces; they are
not minimized trace functions or a representative policy population.

The six frozen Casbin-derived interpretations still agree on 516 finite requests
and forty assertions. Casbin is unavailable in the bundled Python environment;
no native engine was installed or executed. Historical results, Linux campaigns,
native-boundary statements and licenses remain unchanged.

## Same-information full-cost comparison

`results/observation-reuse-20261014/` retains all literal inputs and outputs for
49 retained examples and fifteen constructed phase lifts. Each lift preserves
every complete policy observation, decision and original successor while a
target-only phase advances modulo 1, 3 or 9. Induction on request length proves
trace equality with the original target. This models redundant target
representation, not a deployed routing engine or hidden-policy-state theorem.
The five policies per phase are three width fixtures (1/4/8 aliases) and one-use
versions of the finite basic/deny-overrides public interpretations.

Both methods load exactly the same frozen/current modules, decode identical
bytes, use the same named-environment backend, and serialize byte-identical
complete replay-bearing semantic reports. Only diagnostic work fields differ.
The default current reports also equal the frozen pre-edit reports exactly.
Seven alternating fresh-process trials per method/group measure complete
validation, traversal, reference calls, replay and semantic serialization. Cold
process wall time additionally includes interpreter/module startup, input/output
pipes, diagnostic serialization and exit. One separately traced process per
method/group measures Python allocations beginning before input decoding.

| Cohort | Cases | Reference calls before/reuse | Median check ms before/reuse | Median cold-process ms before/reuse |
|---|---:|---:|---:|---:|
| Retained examples | 49 | 3,431 / 3,431 | 28.6509 / 30.1028 | 109.0617 / 110.3219 |
| Phase 1 | 5 | 178 / 178 | 1.4277 / 1.5029 | 79.3009 / 79.2359 |
| Phase 3 | 5 | 534 / 178 | 3.6483 / 1.7550 | 80.1157 / 78.9728 |
| Phase 9 | 5 | 1,602 / 178 | 10.2045 / 2.5291 | 87.0526 / 79.2591 |

No retained example has a reuse hit. Its 237,953 input bytes and 29,967 semantic
output bytes are unchanged, while traced pipeline Python peaks rise from
1,911,084 to 2,010,892 bytes. Phase 1 likewise has no hits and raises its Python
peak 98,034 to 103,315 bytes. Phase 3 peaks are 150,157/148,133; phase 9 peaks
294,328/287,534. These traced peaks include decoded inputs, reports and transient
cache allocations, but exclude pre-import allocations and native/kernel memory.

Median OS process peak working sets (bytes) are 26,697,728/26,685,440 for the
retained cohort, 25,698,304/25,698,304 for phase 1, 25,804,800/25,800,704 for phase
3, and 25,518,080/25,800,704 for phase 9. Windows `PeakWorkingSetSize` includes
the process's startup, resident modules and decoded inputs. These are complete
process resident high-water measurements, not total system/commit memory;
small differences do not imply an algorithmic memory reduction. Phase 9's
process peak increases despite fewer semantic calls.

Phase 1/3/9 input encodings are 12,580/16,070/27,204 bytes; semantic outputs are
768/774/783 bytes. Retained-cohort decode/serialization medians are
1.6252/0.3893 ms before and 1.6033/0.3816 ms with reuse. Raw output includes actual
diagnostic-pipe byte counts as well. All checking/pipeline CPU observations are
preserved: Windows samples are quantized in 15.625 ms increments and many are
zero, so sub-quantum CPU gains are not inferred. Input construction and optional
state-list materialization are separately recorded, not added to unrelated
medians to manufacture an end-to-end interval.

Environment: CPython 3.12.14 MSC v.1944 AMD64, Windows-11-10.0.28000-SP0,
Intel i7-12700KF; bytecode disabled. Seven single-host cold trials are not
hardware-normalized throughput. The implemented reuse saves actual verification
work when complete observations recur; this does not establish a new algorithm,
general speedup, memory/privacy advantage, or native benefit.
