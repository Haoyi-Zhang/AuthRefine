# Reproducibility Contract

The artifact distinguishes four outcomes: verified equivalent, verified non-equivalent with a replayable witness, invalid input, and inconclusive because a declared work limit was exhausted. Inconclusive is never converted to semantic rejection.

## Quick integrity check

```bash
python verify_release.py
```

This parses all JSON evidence, checks immutable-source hashes and archive hygiene, and runs the tests in ordinary and optimized modes.

## Full deterministic campaign

```bash
python verify_release.py --campaign
```

The campaign runs in a temporary copy. It does not require network access and does not rely on resolver results in `reference_resolution_audit.json`.

## Determinism envelope

The release audit repeats the campaign under two Python hash seeds and two time zones. Scientific JSON is compared after removing explicitly environmental timing, memory, host, and timestamp fields. This is a reproducibility check, not a claim of bit-for-bit performance identity.

## Trusted computing base

The mathematical statements rely on the definitions and proofs in the paper. Executable evidence relies on CPython, the operating system, the JSON/Unicode behavior of the standard library, and the delivered checker and semantic implementations. Product search shares the reference interpreter and is therefore an algorithmic cross-check rather than a fully independent formalization.
