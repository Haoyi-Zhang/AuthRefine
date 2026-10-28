"""Explicit native line syntax: quotes are identity characters, not CSV quoting.

Only the already admitted model families are accepted. The original text is
passed intact to the pinned native parser, whose ordered rows are checked by
native_casbin._engine before any comparison. Bracket/parenthesis nesting is not
interpreted in policy rows. Slash comment lines are retained for native loading.
"""
from native_casbin import (AdmissionError, Configuration, MAX_ROWS, MAX_TEXT_BYTES,
                           _check_role_depth, admit_configuration)
from language import named


def admit_native_literals(model_text, policy_text):
    if not isinstance(policy_text, str):
        raise AdmissionError("native policy text must be a string", "invalid")
    if len(policy_text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise AdmissionError("policy text exceeds input envelope", "inconclusive")
    base = admit_configuration(model_text, "# empty policy")
    rows, lines = [], []
    for number, raw in enumerate(policy_text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if any(character in line for character in "[]()"):
            raise AdmissionError(f"policy line {number}: nested native fields need a separate conversion")
        row = [cell.strip() for cell in line.split(",")]
        if not all(named(cell) for cell in row):
            raise AdmissionError(f"policy line {number}: invalid or empty name", "invalid")
        kind = row[0]
        width = 4 if base.family == "rbac_with_domains" else 3
        width += int(base.family in ("priority", "rbac_with_deny"))
        valid = kind == "p" and len(row) == width + 1
        valid |= kind == "g" and base.family != "basic" and len(row) == (4 if base.family == "rbac_with_domains" else 3)
        valid |= kind == "g2" and base.family == "rbac_with_resource_roles" and len(row) == 3
        if not valid:
            raise AdmissionError(f"policy line {number}: undeclared policy type or field count")
        if kind == "p" and base.family in ("priority", "rbac_with_deny") and row[-1] not in ("allow", "deny"):
            raise AdmissionError(f"policy line {number}: unsupported decision")
        if "unlisted" in row:
            raise AdmissionError("a source name collides with the outside-name representative")
        rows.append(row)
        lines.append(number)
        if len(rows) > MAX_ROWS:
            raise AdmissionError("policy row envelope exceeded", "inconclusive")
    _check_role_depth(base.family, rows)
    return Configuration(base.family, model_text, policy_text or "# empty policy", rows, lines)
