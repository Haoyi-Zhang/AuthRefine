"""Convert a precise stateless five-field tenant/route policy schema.

Tenant identifiers are used only by equality. The abstract resource carries the
same/different relation of the supplied pair, NOT a global two-tenant database
abstraction. This does not certify the origin of a caller's resource tenant.
"""
from __future__ import annotations

import configparser
import json
import re

from checker import verify_reachable
from finite_routes import path_matches
from language import PolicyError, named, normalize
from native_casbin import AdmissionError, Configuration, MAX_TEXT_BYTES, _check_role_depth, _compact, _engine
from native_runtime import engine_identity
from public_inputs import closure


MATCHER = 'g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act) && (p.scope == "any" || r.tenant == r.rtenant)'
SCHEMA = {"request_definition": {"r": "sub, tenant, obj, act, rtenant"},
          "policy_definition": {"p": "sub, obj, act, scope"}, "role_definition": {"g": "_, _"},
          "policy_effect": {"e": "some(where (p.eft == allow))"}, "matchers": {"m": MATCHER}}


def action_set(pattern):
    if re.fullmatch(r"\^[A-Z]+\$", pattern):
        return {pattern[1:-1]}
    if re.fullmatch(r"\^\([A-Z]+(?:\|[A-Z]+)*\)\$", pattern):
        values = pattern[2:-2].split("|")
        if len(values) != len(set(values)):
            raise AdmissionError("method alternation repeats a literal")
        return set(values)
    raise AdmissionError("action regex must be an anchored alternation of literal uppercase methods")


def admit_tenant_routes(model_text, policy_text):
    if any(not isinstance(text, str) or len(text.encode("utf-8")) > MAX_TEXT_BYTES for text in (model_text, policy_text)):
        raise AdmissionError("tenant configuration exceeds input envelope", "inconclusive")
    parser = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=True)
    try:
        parser.read_string(model_text)
    except configparser.Error as error:
        raise AdmissionError("tenant model cannot be parsed", "invalid") from error
    actual = {section: {key: _compact(value) for key, value in parser.items(section)} for section in parser.sections()}
    expected = {section: {key: _compact(value) for key, value in fields.items()} for section, fields in SCHEMA.items()}
    if parser.defaults() or actual != expected:
        raise AdmissionError("tenant model differs from the admitted five-field schema")
    rows, source_lines = [], []
    for number, raw in enumerate(policy_text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        row = [part.strip() for part in line.split(",")]
        if any(not named(value) for value in row) or len(rows) >= 512:
            raise AdmissionError("invalid tenant row or row envelope exceeded", "inconclusive")
        if row[0] == "p" and len(row) == 5:
            subject, pattern, methods, scope = row[1:]
            if (any(c in subject for c in '\"[]()') or not pattern.startswith("/")
                    or any(c in pattern for c in '\"[]()?#\\') or pattern.count("*") > 1
                    or "*" in pattern and not pattern.endswith("*")
                    or scope not in ("any", "tenant_match")):
                raise AdmissionError("unsupported tenant policy literal or scope")
            action_set(methods)
        elif row[0] == "g" and len(row) == 3:
            if any(any(c in value for c in '\"[]()') for value in row[1:]):
                raise AdmissionError("unsupported literal role edge")
        else:
            raise AdmissionError("undeclared tenant policy row type/width")
        rows.append(row)
        source_lines.append(number)
    _check_role_depth("tenant_routes", rows)
    return Configuration("tenant_routes", model_text, "\n".join(", ".join(row) for row in rows) or "# empty policy", rows, source_lines)


def path_partition(patterns):
    """Witness every exact point / longest-matching-prefix class.

    For a non-exact path, the matching prefix patterns form a chain. A fresh
    continuation outside all longer pattern edges witnesses that chain. Each
    exact point is included separately. This quotient concerns raw absolute
    paths only, not request dispatch, headers or URL normalization.
    """
    patterns = sorted(set(patterns))
    if len(patterns) > 32 or any(not p.startswith("/") or p.count("*") > 1 or "*" in p and not p.endswith("*") for p in patterns):
        raise AdmissionError("path partition requires at most 32 exact/trailing-prefix patterns", "inconclusive")
    prefixes = sorted({p[:-1] for p in patterns if p.endswith("*")})
    exact = {p for p in patterns if "*" not in p}
    candidates = set(exact)
    certificates = []
    roots = sorted(set(prefixes + ["/"]))
    for prefix in roots:
        if prefix:
            candidates.add(prefix)
        # Exclude first continuation characters of both exact and longer-prefix
        # patterns. At most 32 are blocked; this safe alphabet is larger.
        blocked = {p[len(prefix)] for p in [*prefixes, *exact] if p.startswith(prefix) and len(p) > len(prefix)}
        safe = "~!$&'()+,-.0123456789:;=@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
        character = next((value for value in safe if value not in blocked), None)
        if character is None:
            raise AdmissionError("no bounded fresh path witness", "inconclusive")
        witness = prefix + character
        if not witness.startswith("/") or len(witness) > 200:
            raise AdmissionError("path witness exceeds the named request envelope", "inconclusive")
        candidates.add(witness)
        certificates.append({"prefix": prefix, "fresh_character": character, "blocked_next_characters": sorted(blocked), "witness": witness})
    classes = {}
    for path in sorted(candidates, key=lambda value: (len(value), value)):
        if path.startswith("/"):
            signature = tuple(path_matches(path, pattern) for pattern in patterns)
            classes.setdefault(signature, path)
    return {"patterns": patterns, "representatives": sorted(classes.values()),
            "prefix_witnesses": certificates,
            "scope": "exact/trailing-prefix signature quotient for raw absolute paths; no arbitrary regex or application URL claim"}


def _atom(field, name, negated=False):
    return {"field": field, "name": name, "negated": negated}


def convert_tenant_configuration(configuration):
    policies = [row[1:] for row in configuration.rows if row[0] == "p"]
    edges = [(row[1], row[2]) for row in configuration.rows if row[0] == "g"]
    roles = sorted({row[0] for row in policies})
    users = sorted(set(roles) | {value for edge in edges for value in edge})
    outside = "outside-role"
    while outside in users:
        outside += "-other"
    users.append(outside)
    actions = sorted({method for _, _, methods, _ in policies for method in action_set(methods)})
    other_method = "UNLISTED"
    while other_method in actions:
        other_method += "X"
    actions.append(other_method)
    partition = path_partition([row[1] for row in policies])
    partition["outside_subject"] = outside
    partition["outside_action"] = other_method
    resources = [json.dumps([path, equal], separators=(",", ":")) for path in partition["representatives"] for equal in (False, True)]
    policy = {"principals": users, "resources": resources, "actions": actions, "roles": roles,
              "members": [[user, role] for user in users for role in roles if role in closure(edges, user)],
              "state": [], "aliases": [], "rules": []}
    for subject, pattern, methods, scope in policies:
        allowed = action_set(methods)
        excluded = [method for method in actions if method not in allowed]
        for resource in resources:
            path, equal = json.loads(resource)
            if not path_matches(path, pattern) or scope == "tenant_match" and not equal:
                continue
            base = [_atom("role", subject), _atom("resource", resource)]
            # Choose a semantics-preserving literal/complement representation
            # within the existing AST bound; do not remove that bound.
            alternatives = ([[_atom("action", method, True) for method in excluded]]
                            if 1 + len(base) + len(excluded) <= len(allowed) * (2 + len(base))
                            else [[_atom("action", method)] for method in sorted(allowed)])
            for guards in alternatives:
                policy["rules"].append({"decision": "allow", "guard": base + guards, "updates": []})
    try:
        policy = normalize(policy)
    except PolicyError as error:
        raise AdmissionError(str(error), "inconclusive" if error.category == "LIMIT" else "invalid") from error
    return policy, partition


def compare_tenant_routes(model_text, policy_text):
    configuration = admit_tenant_routes(model_text, policy_text)
    policy, partition = convert_tenant_configuration(configuration)
    native = _engine(configuration)
    alphabet = [[user, resource, action] for user in policy["principals"] for resource in policy["resources"] for action in policy["actions"]]
    transitions = []
    for user, resource, action in alphabet:
        path, equal = json.loads(resource)
        try:
            result = native.enforce(user, 1, path, action, 1 if equal else 2)
        except Exception as error:
            raise AdmissionError("native five-field tenant check failed: " + type(error).__name__, "native_error") from error
        if type(result) is not bool:
            raise AdmissionError("native tenant decision is not Boolean", "native_error")
        transitions.append(["allow" if result else "deny", 0])
    machine = {"state_names": [], "alphabet": alphabet, "observations": [0], "initial": 0, "transitions": [transitions]}
    comparison = verify_reachable(policy, machine)
    return {"status": comparison["status"], "accepted": comparison["accepted"], "native_runtime": engine_identity(),
            "native_enforce_calls": len(alphabet), "path_partition": partition,
            "tenant_abstraction": "per-request equality relation only; no global two-tenant state or credential-producer claim",
            "resource_tenant_origin_verified": False, "whole_application_verified": False,
            "policy": policy, "machine": machine, "comparison": comparison}


def abstract_request(report, subject, tenant, path, action, resource_tenant):
    if (not named(subject) or not named(path) or not path.startswith("/") or not named(action)
            or type(tenant) is not int or type(resource_tenant) is not int):
        raise AdmissionError("tenant request needs named strings and integer tenant identifiers", "invalid")
    policy = report["policy"]
    subjects = policy["principals"]
    if subject not in subjects:
        # The source policy has no link from an unlisted subject. The generated
        # outside role is the only principal not mentioned by a source rule/link.
        outside = report["path_partition"].get("outside_subject")
        if outside not in subjects:
            raise AdmissionError("ambiguous outside-role request class", "invalid")
        subject = outside
    patterns = report["path_partition"]["patterns"]
    signature = [path_matches(path, pattern) for pattern in patterns]
    witnesses = [value for value in report["path_partition"]["representatives"]
                 if [path_matches(value, pattern) for pattern in patterns] == signature]
    if len(witnesses) != 1:
        raise AdmissionError("path quotient lacks a unique request-signature witness", "invalid")
    if action not in policy["actions"]:
        outside = report["path_partition"].get("outside_action")
        if outside not in policy["actions"]:
            raise AdmissionError("ambiguous outside-method request class", "invalid")
        action = outside
    return [subject, json.dumps([witnesses[0], tenant == resource_tenant], separators=(",", ":")), action]
