# Security and Input-Handling Notes

This repository is a research artifact for finite policy equivalence. It is not an authorization enforcement service and should not be placed on a request path without an independent integration and threat-model review.

## Untrusted inputs

The parser and compiler-independent checker validate schemas, finite domains, indices, total tables, optional certificate closure, identifier lengths, and Unicode categories. Identifiers reject `Cc`, `Cf`, and `Cs` characters. The legacy region checker caps binding evaluations only, not closure/support work. The list-free checker additionally charges preparation, traversal, support, conservative semantic-node visits, path reconstruction, replay, and optional reporting. These declared charges exclude JSON decoding/schema validation and are not a wall-time or process-memory guarantee. The derived family procedures have their separately documented streaming and work limits. Exhaustion is inconclusive, never semantic rejection or acceptance.

JSON decoding, filesystem access, and process limits remain part of the host-language trusted computing base. Run the artifact in a resource-limited process when evaluating untrusted files. The code does not require network access for any scientific result. The optional reference-resolution audit is documentary metadata validation and is not used by the checker.

## Non-claims

A passing certificate does not prove that a deployed enforcement point cannot be bypassed, that a state decoder is faithful to live memory, that requests are serialized atomically, that external role data is current, or that unrestricted prose was translated as its author intended. Those are separate integration obligations.

## Reporting defects

For a research handoff, preserve the failing input, command line, Python version, and the complete structured status. Do not reduce `invalid` or `inconclusive` to a Boolean failure when reporting a checker issue.
