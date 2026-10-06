# Trace-refinement certificates

This artifact implements a finite controlled authorization language, a compiler, semantic reification, a standalone closed-state checker, shortest-trace diagnosis, two algorithmic cross-checks, and executable reference constructions for the paper's derived characterizations. It includes the consumed public example inputs, deterministic generators, all measured case records, an adversarial repair campaign, and proof notes. No network access is needed to reproduce the evidence.

## Meaning of a certificate

A reference binding is chosen once and held fixed for the whole execution. A target transition exposes its decision and the complete named Boolean post-state; the initial state is observed too. Acceptance means equivalence to the target for **every** admitted binding, not merely to the compiler's default binding. Under complete observations, that positive result also implies switching closure; the declared source semantics and counterexample replay still use one fixed binding. The closed-state checker recomputes each obligation from typed data. It imports neither the parser nor the compiler.

This is a finite mathematical interface, not unrestricted prose, a deployed policy engine, or a guarantee that the underlying authorization requirements are desirable. The proofs describe the algorithms; there is no proof-assistant extraction of the executable source. The product oracle shares the checker's reference interpreter, while the symbolic backend supplies separate semantic construction and shares structural validation. This is not three independent implementations of the entire system.

## Mathematical extensions and implementation boundary

The proof notes also give the canonical observed-state quotient, an exact earliest-failure profile for each binding, the sharper coherent-quotient witness bound, dependency-closed state projection, and restriction to a specified nonempty binding family. They also show that accepted full-state uniformity tolerates stepwise binding changes, and classify whether a candidate implements all, a proper nonempty family, or none of the admitted interpretations. `src/extensions.py` supplies bounded reference constructions for these consequences without changing the main Cartesian checker or the declared fixed-binding language. The ordinary diagnostic returns one shortest uniform counterexample, including the empty word when initial observations differ. The companion profile routine enumerates the complete finite family only when both its streaming family cap and shared work budget permit. Family ingestion, graph traversal, certificate closure, projection scans, semantic steps, and witness replay all consume that work budget; exhaustion is inconclusive rather than a semantic rejection. `proofs/semantics.md` states each result with its premises. `reference_audit.csv` maps all 58 cited works to their primary access paths, reading depth, manuscript locations and supported claims. `literature_comparison.csv`, `literature_reference_counts.csv` and `proofs/literature.md` record the separate journal-calibration sample and the direct scholarly comparisons.

`results/extensions.json` records 592 deterministic finite cross-checks: 128 binding-profile instances covering 296 complete bindings, 128 two-state quotient cases, 192 policy/projection pairs covering 10,224 full one-step tuples, all 15 nonempty subfamilies of a four-binding correlated example, and 128 full-state switching cases plus one decision-only separator. These checks connect the written consequences to the reference code; they are not proof-assistant mechanization, performance benchmarks, or evidence about larger policy distributions. The main full-state algorithms and the extension campaign are included in the complete reproduction. The resource exception described below applies to repeated executions as well as the original measurement.

`results/adversarial.json` records a separate 1,024-case deterministic campaign added after code-level audit found and repaired two boundary defects: direct diagnosis omitted the length-zero initial-observation case, and derived family procedures could materialize an unbounded Cartesian family before checking their semantic-step budget. The repaired campaign covers all four alias sorts, five target-mutation modes, 288 empty-word witnesses, 440 positive witnesses, 30,056 compiler/reference one-step comparisons, 1,462 binding-profile/singleton-product comparisons, 28,080 projection tuples, 1,024 quotient classifications, and 1,024 full-state switching comparisons. Four controls exercise wide-family preflight, a nonterminating duplicate iterator, zero-budget preparation, and decision-only trace annotations. It uses 244,830 counted operations and makes no performance or population claim.

`results/exhaustive.json` adds a third, direct source evaluator for a completely enumerated tiny domain. One representative is retained for each of 180 initialized source semantics (90 transition tables with both initial values) and crossed with all 128 total two-state targets in the declared target shape, for 23,040 pairs and 123,492 recorded comparisons. All local, product, symbolic, diagnostic, profile, and switching results agree. This is exhaustive only for the stated tiny family. `src/reference_check.py` separately validates the frozen bibliography inventory; the full project invocation also checks the current BibTeX, TeX citations, audit locations, and identifier distribution without network access.

## Reproduction

The supported execution environment is CPython on Linux with the POSIX `resource` module. The retained earlier release-entry record was produced with CPython 3.13 on Linux; the current repairs have only portable Windows validation until the current Linux suite and campaign run. Native Windows is not a supported runtime because its standard library does not provide `resource`; use a Linux container or a Linux distribution under WSL when starting from Windows. No third-party Python package is required. On Linux, every `peak_rss_kib` field is the `ru_maxrss` high-water value in KiB; CPU and wall-time fields are seconds. These measurements are environmental fields and are excluded from scientific-record comparison.

From this directory, the quick release check and the full deterministic matrix are:

```sh
python verify_release.py
python verify_release.py --campaign
```

The quick check verifies the supported platform, required scientific files, frozen-input paths and byte counts, JSON readability, the exact forty-chunk/10,000-record baseline shape, forty-nine policy/certificate/diagnostic examples by actual semantic replay, and the current 56 unit-test methods in ordinary and optimized modes. The retained Linux entry-check record covers the earlier 47-method suite, not the nine subsequently added regressions. It deliberately does **not** claim a whole-source-tree checksum or snapshot fingerprint.

The campaign command copies the artifact into an isolated temporary directory and runs four fresh, non-resumed reproductions: the Cartesian product of Python hash seeds 1729 and 2718 with `UTC` and `America/Los_Angeles`. Each invocation receives both a new `--output` directory and the copied frozen `results` directory through `--compare`. The verifier accepts a configuration only after the new output contains exactly forty JSONL chunks, forty metric files, 10,000 ordered primary records, and both `summary.json` and `reproduction.json` explicitly report scientific-field agreement with the baseline. A zero process return code without those files is a failure.

`results/reproducibility_entry_check.json` records the compact, path-free outcome of the earlier four-configuration entry-point validation. The verifier does not trust that record as a substitute for executing a new campaign.

For one direct reconstruction instead of the four-configuration matrix, choose an output path that does not already exist:

```sh
python reproduce.py --output ../reproduced --compare results
```

That command repeats the current unit suite, the offline 58-reference inventory check, the 52-case pilot, the 3,330 original auxiliary cases, the 592 extension cross-checks, the 1,024 adversarial cases, the 23,040-pair complete tiny-domain audit, and all 10,000 primary cases in forty chunks of 250. Up to ten sequential chunks share one worker process; each worker still has a 120-second timeout. It regenerates the summary and compares every primary, pilot, auxiliary, extension, adversarial, exhaustive-audit, and reference-integrity record against the delivered evidence after removing only timing and Linux RSS fields. The same invocation reruns the seven documented inspection/example commands in temporary destinations and records their exit status. Every child command also retains complete stdout, stderr, timeout and exit information in the output's `raw-logs/`, including on failure. `fresh_reproduction` describes a new non-resumed output; the entry point does not extract an archive and records `fresh_archive_extraction` as false.

The supplied Linux workflow runs the quick checks and one complete fresh reproduction for each of the four documented hash-seed/time-zone configurations, sequentially. It bounds the quick check at 180 seconds and each full reproduction at 300 seconds, while keeping the 120-second child-command limits. It checks the materialized output contract and uploads complete or partial raw data and logs with `if: always()`. Workflow configuration is not an executed scientific result; completion must be established by its uploaded output and successful checks.

A deliberately interrupted campaign can be continued with the same output path and `--resume`. Incomplete chunk pairs are not silently replaced. A resumed invocation's elapsed and child-CPU measurements describe that invocation, not earlier processes. `results/clean_reproduction.json` is retained as an earlier code-frozen reconstruction record; it is not used as a substitute for the materialized-output checks performed by the current release entry point. The primary measurement tables come from `results/summary.json` and its raw chunks.

To regenerate only the tables from already complete records:

```sh
python src/summarize.py results
```

This recomputes the summaries from the raw records and overwrites only the derived summary/CSV files. It does not rerun or add observations.

## Inspect a single certificate

```sh
python src/checker.py results/examples/case-00000/policy.json results/examples/case-00000/automaton.json results/examples/case-00000/certificate.json
```

This example must be accepted. The checker accepts canonical typed JSON, not the surface sentence; inspection of the sentence-to-AST translation remains a separate obligation. It reports a positive result only after all cells and closure conditions complete. Exit 1 denotes invalid evidence or a completed semantic mismatch; exit 2 denotes an incomplete resource-bounded check. A failure on an unreachable state in an unnecessarily large certificate is not, by itself, a reachable counterexample.

The command-line interface also supports normalization, compilation, diagnosis, and reification. The following paths must not already exist:

```sh
python src/policy.py normalize results/examples/case-00000/policy.cnl ../normalized.cnl
python src/policy.py compile ../normalized.cnl ../compiled-policy
python src/policy.py diagnose ../compiled-policy/policy.json ../compiled-policy/automaton.json ../diagnosis.json
python src/policy.py reify ../compiled-policy/policy.json ../compiled-policy/automaton.json ../reified.cnl
```

Compilation uses the first canonical candidate for each reference; it does not assert uniformity. Diagnosis compares every binding by local support and emits a complete fixed binding with a minimum-length distinguishing word when one exists; an initial-observation disagreement is reported as the empty word before transition scanning. Reification is behavioral, not recovery of the original sentence. Its finite literal construction can exceed the AST envelope even when the mathematical reification criterion holds.

The sentence envelope is four MiB and the JSON envelope is 32 MiB. Writers do not replace existing destinations and make each individual file visible only after its bounded encoding is complete. A multi-file compile command is not a transaction across the directory: earlier complete files can remain if a later file cannot be written. These limits are operational outcomes, not altered policy semantics.

## Evidence map

`src/language.py` defines the grammar, typing checks and canonical representation. `src/compiler.py` uses bit-oriented execution and deliberately different numeric target-state identifiers. `src/checker.py` uses a named Boolean environment and reconstructs the source valuation from the target observation. `src/oracle.py` performs fixed-binding product and bounded word enumeration without the local support reduction. `src/symbolic.py` uses reduced ordered finite-domain decision diagrams without the support calculation. `src/public_inputs.py` contains the six explicit public-model projections and a separate model-level interpreter. `src/extensions.py` implements the derived finite constructions, and `src/extension_checks.py` cross-checks them against singleton products, direct fiber tests, exhaustive subfamilies, and one-step projection. `src/adversarial_checks.py` performs the all-sort mutation, shortest-diagnostic, quotient, projection, switching, and resource-boundary campaign. `src/exhaustive_audit.py` supplies the direct tiny-domain semantics and complete cross-product audit. `src/reference_check.py` validates the frozen reference inventory and, in the complete package, the current BibTeX and TeX sources. `proofs/semantics.md` gives standalone mathematical arguments and states the implementation boundary separately.

`results/chunks/` contains exactly 10,000 ordered primary records and forty timing/count records. `results/examples/` contains 49 complete readable public, width and chain instances. Generated instances are reconstructed from the deterministic case index; their full verdicts, witnesses, counts and symbolic comparisons are retained in the raw case records. `results/theory.json` contains all 3,330 original auxiliary records. `results/extensions.json` contains all 592 derived-construction records. `results/adversarial.json` contains all 1,024 adversarial records and boundary controls. `results/exhaustive.json` contains the complete 23,040-pair tiny-domain audit. `results/reference_verification.json` records the standalone inventory check, while `results/reference_verification_project.json` records the final BibTeX--TeX--audit check. `results/pilot/` contains the measured pilot and its public inputs/renderings. `claim_evidence_ledger.csv` maps the claims to arguments, source and raw evidence.

The primary campaign comprises 18 public-derived cases, 9,936 generated cases, 16 width cases, 15 delayed-divergence cases and 15 validation controls. The generated set has 9,772 different canonical ASTs, with 164 duplicate occurrences; it is not a random or human policy sample. There are 9,012 accepted primary cases. The 9,985 structurally valid cases all agree with the symbolic backend; the full fixed-binding product is executed on 9,977 primary cases. Its absence in eight wide cases is explicit, not a passing result. All 889 attempted reachable decision mutations are detected.

The six public model/policy pairs yield 516 finite projected requests and 40 frozen initial-state assertions. The one-use and parity extensions are constructed stateful variants, not properties of the upstream examples. The upstream engine itself is not executed. Large-width global work in `width.csv` is a derived count beyond eight aliases, not a measured run. Decision-diagram conditional visits and source-binding evaluations are different units; they do not establish a universal speed ranking.

The augmented delivered campaign counts 1,340,425 specified operations, including the adversarial and complete tiny-domain work, and stays below its two-million per-campaign ceiling. This is not a lifetime total. Known retained executions total 13,885,593 counted operations and at least 328.397886908 CPU seconds; both are lower bounds because some startup, precursor-audit, unit-test, command, bibliography, and document work was not measured by one lifecycle counter. `results/resource_accounting.json` preserves the individual measurements and must not be read as a full-lifecycle resource certification.

## Input attribution

The Casbin inputs are normalized text transcriptions of public source rendering. The model expressions, policy rows and ordering are retained, but upstream byte identity is not claimed. The exact consumed representation, selection and conversions are distributed in `external_inputs/casbin/`, together with the Apache license and notice. Reproduction consumes these frozen files, not the mutable upstream branch. `external_resources.csv` records the public access paths, dates, licenses, integration boundaries and scholarly sources. Scholarly full texts are not redistributed.

## Limits

The experiment envelope contains at most 16 principals, 16 roles, 32 resources, 32 actions, seven Boolean variables, sixteen aliases, 256 rule/atom/effect nodes and 512 target states. Most generated cases are much smaller. The coNP and NP results concern the uncapped parameterized grammar, not asymptotics of these constant finite caps. State revelation is a premise of the local certificate and short-witness theorem. Decision-only behavior can need arbitrarily longer witnesses relative to target-state count alone.

No external policy service is contacted. The mathematical proofs and internal cross-checks do not establish deployment security, general natural-language understanding, representative workloads, human usability or independent review.

## License

Original code, proof notes and generated data are provided under the MIT license in `LICENSE`. The consumed Casbin content remains under its Apache license and notice. Scholarly citations retain their respective rights; no scholarly paper is included in this repository.


## Release verification

`python verify_release.py` checks required scientific assets, frozen result structure, JSON readability, example-level semantic replay, archive hygiene, and tests in ordinary and optimized modes. `python verify_release.py --campaign` adds the four-configuration fresh reconstruction matrix described above. The verifier has no dependency on `SOURCE-MANIFEST.sha256`, does not claim a fingerprint of the complete source snapshot, and never treats a timeout or exhausted work budget as semantic rejection.
