# Conversion checks for the retained policy models

The manuscript's validation inputs use six selected public Casbin
model/policy pairs. These notes justify the finite model comparisons, not
arbitrary upstream execution. The artifact retains the selected inputs,
source references, license, and interpreter independently of these proofs.

## Outside-name preservation

For the selected static equality fragment, keep every relevant literal and
role-graph endpoint and one fresh outside name per field. Require role
queries to target retained literals or endpoints, and exclude matchers
that compare two unconstrained fields. An outside name and the representative
both differ from every retained literal; neither starts a path in the fixed
graph or equals a retained target. Retained names stay fixed. This preserves
atom truth, conjunctions, and the chosen aggregation. Arbitrary equality
between outside fields and graph mutation are outside this argument.

## Ordinary conversion

Literal rows become allowing conjunctions. Subject-role membership is
computed by finite reflexive reachability; resource-role expansion replaces
each source row with adjacent alternatives, preserving its priority. Under
all-allow aggregation an original row matches exactly when one alternative
does. For deny override, placing deny rows before allow rows implements
allow-and-not-deny; implicit priority instead retains the original file
order. With the same default, the basic, subject-role, deny-override,
resource-role, and priority conversions equal the stated finite
interpretations. This concerns the stated graph semantics, not undocumented
depth limits or cycle handling.

## Domain embedding

Encode a domain request (user, domain, object, action) as
((user, domain), (object, domain), action) using injective delimited pairs.
When the domains agree, membership and literal tests recover the original
predicates. With different domains, injectivity prevents a rule from
matching both fields in one domain, so the added request is denied by
default. The finite product therefore preserves original decisions but
does not count its added cross-domain combinations as original requests.

The separate source-model interpreter checks the full selected request
product and forty retained assertions. Constructed one-use and parity
variants add a bit, respectively clearing it on an admitted allowance or
toggling it after allowance without changing the original decision.
Neither variant represents recovered stateful behavior from the upstream
examples.
