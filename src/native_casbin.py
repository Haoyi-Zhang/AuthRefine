"""Compare admitted Casbin configurations with the actual pinned Python engine.

This module never imports application code, executes repository scripts, guesses
custom matcher semantics, or treats a configuration comparison as an audit of
all authorization entry points in the surrounding application.
"""
from __future__ import annotations

import argparse
import configparser
from dataclasses import dataclass
import json
from pathlib import Path
import re

from checker import Rejected, verify_reachable
from language import PolicyError, named
from public_inputs import EXPECTED_EFFECT, EXPECTED_MATCHER, MODELS, translate

MAX_TEXT_BYTES = 1_048_576
MAX_ROWS = 8192
MAX_NATIVE_WORK = 1_000_000
EXTRA_MATCHERS = {
    "rbac_wildcards": '(p.sub == "*" || g(r.sub, p.sub)) && r.obj == p.obj && (p.act == "*" || r.act == p.act)',
    "rbac_path_wildcards": '(p.sub == "*" || g(r.sub, p.sub)) && (r.obj == p.obj || keyMatch(r.obj, p.obj)) && (p.act == "*" || r.act == p.act)',
}
FAMILIES = MODELS + tuple(EXTRA_MATCHERS)


class AdmissionError(ValueError):
    def __init__(self, reason: str, status: str = "unsupported"):
        self.status = status
        super().__init__(reason)


@dataclass(frozen=True)
class Configuration:
    family: str
    model_text: str
    policy_text: str
    rows: list[list[str]]
    source_lines: list[int]


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _schema(name: str) -> dict[str, dict[str, str]]:
    fields = "sub, dom, obj, act" if name == "rbac_with_domains" else "sub, obj, act"
    expected = {
        "request_definition": {"r": fields},
        "policy_definition": {"p": fields + (", eft" if name in ("priority", "rbac_with_deny") else "")},
        "matchers": {"m": EXTRA_MATCHERS[name] if name in EXTRA_MATCHERS else EXPECTED_MATCHER[name]},
        "policy_effect": {"e": EXPECTED_EFFECT.get(name, "some(where (p.eft == allow))")},
    }
    if name != "basic":
        expected["role_definition"] = {"g": "_, _, _" if name == "rbac_with_domains" else "_, _"}
        if name == "rbac_with_resource_roles":
            expected["role_definition"]["g2"] = "_, _"
    return expected


def admit_configuration(model_text: str, policy_text: str) -> Configuration:
    for text in (model_text, policy_text):
        if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            raise AdmissionError("configuration text exceeds input envelope", "inconclusive")
    config = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=True)
    try:
        config.read_string(model_text)
    except configparser.Error as error:
        raise AdmissionError("unreadable model configuration: " + str(error), "invalid") from error
    if config.defaults():
        raise AdmissionError("inherited model defaults require an additional conversion")
    actual = {section: {key: _compact(value) for key, value in config.items(section)}
              for section in config.sections()}
    family = next((name for name in FAMILIES
                   if actual == {section: {key: _compact(value) for key, value in values.items()}
                                 for section, values in _schema(name).items()}), None)
    if family is None:
        raise AdmissionError("matcher, request schema, effect, or role definition is outside the admitted fragment")
    rows, lines, native_lines = [], [], []
    for number, raw in enumerate(policy_text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # The native line loader is not a CSV quote decoder. Do not silently
        # interpret quoted or nested fields differently from that loader.
        if any(character in line for character in '\"[]()'):
            raise AdmissionError(f"policy line {number}: quoted or nested fields need a separate conversion")
        row = [cell.strip() for cell in line.split(",")]
        if not all(named(cell) for cell in row):
            raise AdmissionError(f"policy line {number}: invalid or empty name", "invalid")
        kind = row[0]
        width = 4 if family == "rbac_with_domains" else 3
        width += int(family in ("priority", "rbac_with_deny"))
        valid = kind == "p" and len(row) == width + 1
        valid |= kind == "g" and family != "basic" and len(row) == (4 if family == "rbac_with_domains" else 3)
        valid |= kind == "g2" and family == "rbac_with_resource_roles" and len(row) == 3
        if not valid:
            raise AdmissionError(f"policy line {number}: undeclared policy type or field count")
        if kind == "p" and family in ("priority", "rbac_with_deny") and row[-1] not in ("allow", "deny"):
            raise AdmissionError(f"policy line {number}: unsupported decision")
        if "unlisted" in row:
            raise AdmissionError("a source name collides with this conversion's outside-name representative")
        rows.append(row)
        lines.append(number)
        native_lines.append(line)
        if len(rows) > MAX_ROWS:
            raise AdmissionError("policy row envelope exceeded", "inconclusive")
    _check_role_depth(family, rows)
    return Configuration(family, model_text, "\n".join(native_lines) or "# empty policy", rows, lines)


def _check_role_depth(family: str, rows: list[list[str]]) -> None:
    """Unbounded closure agrees with the pinned manager only within its depth.

    Its default bound is ten BFS layers, including the start node: a path of
    nine edges is admitted; a reachable pair requiring ten edges is not.
    """
    relations: dict[tuple[str, str | None], list[tuple[str, str]]] = {}
    for row in rows:
        if row[0] in ("g", "g2"):
            domain = row[3] if family == "rbac_with_domains" else None
            relations.setdefault((row[0], domain), []).append((row[1], row[2]))
    work = 0
    for edges in relations.values():
        adjacency = {}
        for left, right in edges:
            adjacency.setdefault(left, set()).add(right)
        for start in {value for edge in edges for value in edge}:
            distance, waiting = {start: 0}, [start]
            for node in waiting:
                work += 1
                if work > MAX_NATIVE_WORK:
                    raise AdmissionError("role graph admission work envelope exceeded", "inconclusive")
                for right in adjacency.get(node, ()):
                    work += 1
                    if work > MAX_NATIVE_WORK:
                        raise AdmissionError("role graph admission work envelope exceeded", "inconclusive")
                    if right not in distance:
                        distance[right] = distance[node] + 1
                        if distance[right] >= 10:
                            raise AdmissionError("role reachability exceeds the pinned native hierarchy depth")
                        waiting.append(right)


def _engine(configuration: Configuration):
    from native_runtime import engine_identity
    identity = engine_identity()
    try:
        import casbin
        if identity["profile"] == "casbin-1.37.0":
            # This pinned release predates StringAdapter. The owned transport
            # delegates every line to its real native loader; it does not
            # reimplement row parsing or matcher evaluation.
            from casbin.persist import Adapter, load_policy_line
            class NativeLineTransport(Adapter):
                def __init__(self, line):
                    self.line = line
                def load_policy(self, target):
                    for line in self.line.splitlines():
                        load_policy_line(line.strip(), target)
            adapter = NativeLineTransport(configuration.policy_text)
        else:
            from casbin.persist.adapters import StringAdapter
            adapter = StringAdapter(configuration.policy_text)
    except ImportError as error:
        raise AdmissionError("install the pinned native-runtime dependencies", "dependency_missing") from error
    model = casbin.Model()
    model.load_model_from_text(configuration.model_text)
    engine = casbin.Enforcer(model, adapter)
    engine.enable_auto_save(False)
    for key, role_manager in engine.rm_map.items():
        if getattr(role_manager, "max_hierarchy_level", None) != 10:
            raise AdmissionError(f"native role manager {key} has an unreviewed depth setting")
    # Native parsers and the admitted source representation must load identical
    # ordered rows; this is checked before any semantic agreement is reported.
    for section in ("p", "g"):
        for key, assertion in engine.model.model.get(section, {}).items():
            expected = [row[1:] for row in configuration.rows if row[0] == key]
            if assertion.policy != expected:
                raise AdmissionError("native policy loader disagrees with admitted ordered source rows", "invalid")
    return engine


def export_native(configuration: Configuration) -> tuple[dict, dict, dict]:
    """Export static native decisions, not a reimplementation of the matcher."""
    if configuration.family in EXTRA_MATCHERS:
        raise AdmissionError("wildcard models require an explicit finite request domain; use finite_routes")
    try:
        policy = translate(configuration.family, configuration.rows)
    except PolicyError as error:
        status = "inconclusive" if error.category == "LIMIT" else "unsupported"
        raise AdmissionError(str(error), status) from error
    alphabet = [[u, o, a] for u in policy["principals"] for o in policy["resources"] for a in policy["actions"]]
    if len(alphabet) * max(1, len(configuration.rows)) > MAX_NATIVE_WORK:
        raise AdmissionError("native request/row work envelope exceeded", "inconclusive")
    try:
        engine = _engine(configuration)
    except AdmissionError:
        raise
    except Exception as error:
        raise AdmissionError("native model loading failed: " + type(error).__name__ + ": " + str(error),
                             "native_error") from error
    transitions, native_calls, added_cells = [], 0, 0
    for triple in alphabet:
        request = triple
        if configuration.family == "rbac_with_domains":
            subject, domain = json.loads(triple[0])
            resource, other_domain = json.loads(triple[1])
            if domain != other_domain:
                # This cell has no source four-field request. Its denial is an
                # embedding obligation, not a claimed native Enforce execution.
                transitions.append(["deny", 0])
                added_cells += 1
                continue
            request = [subject, domain, resource, triple[2]]
        try:
            decision = engine.enforce(*request)
        except Exception as error:
            # A native parser/evaluator failure is not semantic equivalence and
            # is not evidence of a security defect in the source application.
            raise AdmissionError("native request evaluation failed: " + type(error).__name__ + ": " + str(error),
                                 "native_error") from error
        if type(decision) is not bool:
            raise AdmissionError("native result is not a Boolean decision", "invalid")
        native_calls += 1
        transitions.append(["allow" if decision else "deny", 0])
    machine = {"state_names": [], "alphabet": alphabet, "observations": [0],
               "initial": 0, "transitions": [transitions]}
    counts = {"native_enforce_calls": native_calls, "added_cross_domain_cells": added_cells,
              "converted_request_cells": len(alphabet), "source_policy_rows": len(configuration.rows)}
    return policy, machine, counts


def compare_native(model_text: str, policy_text: str, work_budget: int = 2_000_000) -> dict:
    from native_runtime import engine_identity
    configuration = admit_configuration(model_text, policy_text)
    policy, machine, counts = export_native(configuration)
    comparison = verify_reachable(policy, machine, work_budget=work_budget)
    return {"status": "equivalent" if comparison["accepted"] else "mismatch",
            "accepted": comparison["accepted"], "framework": "casbin", "native_runtime": engine_identity(),
            "family": configuration.family, "scope": "fixed configuration; static finite request abstraction",
            "application_entry_points_verified": False, "source_lines": configuration.source_lines,
            "counts": counts, "comparison": comparison, "policy": policy, "machine": machine}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model")
    parser.add_argument("policy")
    parser.add_argument("--output")
    parser.add_argument("--work-budget", type=int, default=2_000_000)
    args = parser.parse_args()
    try:
        texts = []
        for filename in (args.model, args.policy):
            with Path(filename).open("rb") as stream:
                data = stream.read(MAX_TEXT_BYTES + 1)
            if len(data) > MAX_TEXT_BYTES:
                raise AdmissionError("input exceeds byte envelope", "inconclusive")
            texts.append(data.decode("utf-8-sig"))
        report = compare_native(*texts, work_budget=args.work_budget)
        code = 0 if report["accepted"] else 1
    except (AdmissionError, Rejected, PolicyError, OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
        status = getattr(error, "status", getattr(error, "kind", "invalid"))
        report = {"status": status, "accepted": None, "reason": str(error)}
        code = 2
    if args.output:
        from policy import output
        output(args.output, report)
    print(json.dumps(report, ensure_ascii=False))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
