# Source-capsule execution and observation

The comparison is between a compiled capsule and an operational interpretation
of that same capsule, under declared providers. It is not a proof of arbitrary
Python, of the complete original module, or of an application's policy intent.

## Construction and state relation

A capsule retains the selected source span and body identity. Construction
removes annotations and decorators, including those on nested definitions, and
replaces nonliteral entry defaults with `None`. Entry arguments or a separate
dependency graph supply those values. The source-module globals, class context
needed by zero-argument `super`, and explicitly linked methods form part of the
construction. Preservation of the full original module is not inferred from
two arms using the same construction.

Inputs and providers define corresponding initial states. Frame-local names
are declared before execution; an uninitialized local raises `UnboundLocalError`
instead of reading a global. A closure retains its lexical frame, and an
uninitialized free cell raises `NameError`. Positional-only, ordinary,
keyword-only and variadic binding are separated. Asynchronous calls bind their
arguments at call time and defer only their bodies.

For expressions, correspondence requires ordinary supported values and the
declared object relation. Short-circuit operators retain their actual operands;
the final rich comparison is not forced to a Boolean. Dictionary keys precede
their values, and expansion requires a mapping. A generator obtains its outer
iterator at creation; later iterables and elements remain lazy. Await requires
an admitted awaitable and a coroutine can be consumed only once. Augmented
assignment evaluates its target once. Exception-target names are cleared when
their handler exits. Global/nonlocal writes, arbitrary runtime introspection,
unadmitted imports and other unsupported operations remain outside this model.

## What the observation establishes

Observations distinguish typed values, target exception classes and declared
status codes, ordered provider arguments, and the tracked state footprint.
Registered objects have stable reference labels. Other containers use a value
projection: this does not certify arbitrary alias graphs or Python object
identity. Django model/primary-key equality represents entity identity, not
Python `is`. Non-string dictionary keys use typed entry pairs, preventing a
collision between `1` and `"1"`; set and frozenset have distinct tags.

Target execution and result projection have separate exception boundaries.
Only an exception raised during target execution is a source exception.
Projection failures are harness errors or unsupported observations. Unresolved
operations are latched even if cleanup returns or a context manager suppresses
their control signal. Unsupported operations, resource bounds and harness
errors are inconclusive, never permissions or successful checks.

The corresponding proof obligation is conditional: supported expressions must
preserve the value/object relation; statements must preserve the relation on
normal completion, return and target exception; and providers and source
construction must preserve their declared relations. This yields equality of
the stated finite observations, not a universal theorem for the entire
syntactically admitted Python domain. The current implementation is supported
by source bindings, explicit domain checks and executable differential controls,
not an end-to-end mechanization of the interpreter or extractor.

## Review-triggered repairs

The owned `test_review_semantics.py` examples cover argument and lexical binding,
awaitability, coroutine reuse, dictionary and generator evaluation order,
exception cleanup, target evaluation frequency, and projection errors. The same
22 examples exposed 16 failures and three errors before repair and pass after
repair. These are defects in the research runtime/observer, not newly discovered
defects in upstream applications. The pre-repair execution and unchanged tests
are retained in private research records; current delivery contains only the
current implementation.

The R24 anonymous active property is now included in the source selection and
actually invoked. The old unobserved `null` record is not rewritten as `false`.
Newly executed observations and exact function-object entry establish the current
result, while the earlier record keeps its original scope.
