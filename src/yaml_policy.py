"""Source policy producer/consumer comparison on an explicit finite domain.

YAML metadata is preserved. Only source-supported condition keys are interpreted;
ignored condition/metadata fields are reported, not certified as enforced.
"""
import configparser
from copy import deepcopy
from importlib import metadata
import itertools
from pathlib import Path
import re
import tempfile

from checker import verify_reachable
from language import named, normalize
from native_casbin import AdmissionError, Configuration, _engine, _schema, _check_role_depth, admit_configuration
from native_runtime import engine_identity
from policy_slice import PolicyInterpreter, extract_policy_program, program_descriptor

MATCHER = 'g(r.sub, p.sub) && (p.obj == "*" || r.obj == p.obj || regexMatch(p.obj, r.obj)) && (p.act == "*" || r.act == p.act)'
CONDITIONS = {"user", "action", "mcp_server", "tool_name_pattern"}


def parse_yaml(text):
    if not isinstance(text, str) or len(text.encode("utf-8")) > 1_048_576:
        raise AdmissionError("YAML input exceeds byte envelope", "inconclusive")
    try:
        import yaml
        distribution = metadata.distribution("PyYAML")
    except (ImportError, metadata.PackageNotFoundError) as error:
        raise AdmissionError("the bound YAML decoder is not installed", "dependency_missing") from error
    if distribution.version != "6.0.2" or Path(yaml.__file__).resolve() != Path(distribution.locate_file("yaml/__init__.py")).resolve():
        raise AdmissionError("YAML decoder must use the bound source-declared PyYAML 6.0.2", "dependency_missing")
    try:
        for number, token in enumerate(yaml.scan(text), 1):
            if number > 20000:
                raise AdmissionError("YAML syntax budget exceeded", "inconclusive")
            if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken)):
                raise AdmissionError("YAML aliases/tags need a separate conversion")
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise AdmissionError("YAML data does not parse", "invalid") from error
    validate_data(data)
    return data


def validate_data(data):
    if type(data) is not dict or not set(data) <= {"roles", "user_roles", "group_roles", "rules", "default_policy"}:
        raise AdmissionError("YAML policy requires the declared root fields", "invalid")
    def string(value):
        if not named(value) or any(char in value for char in ',\"[]()'):
            raise AdmissionError("YAML identifier cannot be safely transported by this native line contract")
    for field in ("roles", "user_roles", "group_roles"):
        mapping = data.get(field, {})
        if type(mapping) is not dict or len(mapping) > 128:
            raise AdmissionError("YAML role mapping is not bounded plain data")
        for name, value in mapping.items():
            string(name)
            if field == "roles":
                if type(value) is not dict or not set(value) <= {"description", "permissions"}:
                    raise AdmissionError("YAML role declaration is outside the supported fields")
                permissions = value.get("permissions", [])
                if type(permissions) is not list or len(permissions) > 128:
                    raise AdmissionError("YAML permission list exceeds envelope", "inconclusive")
                for item in permissions:
                    if type(item) is not dict or not set(item) <= {"resource", "actions"}:
                        raise AdmissionError("YAML permission declaration has unmodeled fields")
                    string(item.get("resource", "*"))
                    actions = item.get("actions", [])
                    if type(actions) is not list or len(actions) > 32:
                        raise AdmissionError("YAML action list is not bounded")
                    for action in actions:
                        string(action)
            else:
                if type(value) is not list or len(value) > 128:
                    raise AdmissionError("YAML subject-role list is not bounded")
                for role in value:
                    string(role)
    rules = data.get("rules", [])
    if type(rules) is not list or len(rules) > 128:
        raise AdmissionError("YAML rules exceed bounded list envelope", "inconclusive")
    for rule in rules:
        if type(rule) is not dict or not set(rule) <= {"name", "condition", "action", "priority", "metadata"}:
            raise AdmissionError("YAML rule fields require a separate contract")
        if type(rule.get("priority", 0)) is not int or abs(rule.get("priority", 0)) > 1_000_000:
            raise AdmissionError("YAML priority must be a bounded integer", "invalid")
        if rule.get("action", "deny") not in ("allow", "deny"):
            raise AdmissionError("YAML rule decision is not supported")
        if (type(rule.get("metadata", {})) is not dict
                or len(rule.get("metadata", {})) > 128
                or any(type(key) is not str for key in rule.get("metadata", {}))):
            raise AdmissionError("YAML metadata needs bounded string-keyed plain data")
        if "name" in rule and type(rule["name"]) is not str:
            raise AdmissionError("YAML rule name must be a string")
        condition = rule.get("condition", {})
        if type(condition) is not dict or any(type(key) is not str for key in condition):
            raise AdmissionError("YAML rule condition must be a plain dictionary")
        for key in CONDITIONS & set(condition):
            value = condition[key]
            if key == "tool_name_pattern":
                if type(value) is not str or len(value) > 256 or not re.fullmatch(r"\.\*[A-Za-z_]+\.\*(?:\|\.\*[A-Za-z_]+\.\*)*", value):
                    raise AdmissionError("custom regex requires the admitted literal-word pattern")
            else:
                string(value)
    if data.get("default_policy", "deny") not in ("allow", "deny"):
        raise AdmissionError("YAML default decision is outside the typed contract")


def reference_rows(data):
    validate_data(data)
    policies = [["p", role, item.get("resource", "*"), action]
                for role, value in data.get("roles", {}).items()
                for item in value.get("permissions", []) for action in item.get("actions", [])]
    groups = [["g", subject, role] for field in ("user_roles", "group_roles")
              for subject, roles in data.get(field, {}).items() for role in roles]
    # Native add APIs retain the first occurrence, not duplicate policy records.
    return [list(row) for row in dict.fromkeys(tuple(row) for row in policies + groups)]


def configuration(model_text, policy_text):
    parsed = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=True)
    try:
        parsed.read_string(model_text)
    except configparser.Error as error:
        raise AdmissionError("YAML gateway model does not parse", "invalid") from error
    actual = {section: dict(parsed.items(section)) for section in parsed.sections()}
    expected = _schema("rbac")
    expected["matchers"]["m"] = MATCHER
    compact = lambda table: {key: {name: re.sub(r"\s+", "", value) for name, value in row.items()} for key, row in table.items()}
    if parsed.defaults() or compact(actual) != compact(expected):
        raise AdmissionError("YAML gateway model schema/matcher changed")
    # Row admission is shared with the strict native line contract. The full
    # matcher is separately checked above; it is not converted as literal RBAC.
    literal_model = model_text.replace(actual["matchers"]["m"], _schema("rbac")["matchers"]["m"])
    base = admit_configuration(literal_model, policy_text)
    return Configuration("rbac", model_text, base.policy_text, base.rows, base.source_lines)


class NativePolicyStore:
    def __init__(self, model_text, initial_policy):
        conf = configuration(model_text, initial_policy)
        _engine(conf)  # Bound distribution, parser-row agreement and role depth.
        import casbin
        self.directory = tempfile.TemporaryDirectory(prefix="authrefine-owned-policy-")
        try:
            self.model = Path(self.directory.name) / "model.conf"
            self.path = Path(self.directory.name) / "policy.csv"
            self.model.write_text(model_text, encoding="utf-8")
            self.path.write_text(conf.policy_text, encoding="utf-8")
            self.engine = casbin.Enforcer(str(self.model), str(self.path))
        except Exception:
            self.directory.cleanup()
            raise
        self.counts = {}

    def invoke(self, method, arguments):
        if method not in {"clear_policy", "add_policy", "add_grouping_policy", "save_policy", "enforce"}:
            raise AdmissionError("native policy operation is not bound")
        self.counts[method] = self.counts.get(method, 0) + 1
        try:
            result = getattr(self.engine, method)(*arguments)
        except Exception as error:
            raise AdmissionError("native policy operation failed: " + type(error).__name__, "native_error") from error
        if method == "enforce" and type(result) is not bool:
            raise AdmissionError("native permission result is not Boolean", "native_error")
        return result

    def rows(self):
        return [["p", *row] for row in self.engine.get_policy()] + [["g", *row] for row in self.engine.get_grouping_policy()]

    def close(self):
        self.directory.cleanup()


def reference_decision(data, rows, user, resource, action, groups):
    # Independently organized declarative rule and graph contract. Only the
    # four supported condition names have meaning; omissions stay explicit.
    for rule in sorted(data.get("rules", []), key=lambda item: item.get("priority", 0), reverse=True):
        condition = rule.get("condition", {})
        parts = resource.split(":")
        if condition.get("user", user) != user or condition.get("action", action) != action:
            continue
        if "mcp_server" in condition and (len(parts) < 2 or parts[1] != condition["mcp_server"]):
            continue
        if "tool_name_pattern" in condition:
            if len(parts) < 3:
                continue
            words = re.findall(r"[A-Za-z_]+", condition["tool_name_pattern"])
            if not any(word in parts[2] for word in words):
                continue
        return rule.get("action", "deny") == "allow"
    for subject in [user, *groups]:
        waiting, reached = [subject], set()
        while waiting:
            current = waiting.pop()
            if current in reached:
                continue
            reached.add(current)
            waiting.extend(row[2] for row in rows if row[0] == "g" and row[1] == current)
        for row in rows:
            if row[0] != "p" or row[1] not in reached or row[3] not in ("*", action):
                continue
            if row[2] == "*" or resource == row[2] or re.match(resource, row[2]):
                return True
    return data.get("default_policy", "deny") == "allow"


def compare_yaml_policy(source, model_text, initial_policy, data, contexts, domain, *, class_name="PolicyEngine"):
    validate_data(data)
    if (type(contexts) is not list or not 1 <= len(contexts) <= 32 or type(domain) is not dict
            or set(domain) != {"resources", "actions"}):
        raise AdmissionError("supply bounded contexts and a finite resource/action domain", "invalid")
    for values in domain.values():
        if type(values) is not list or not 1 <= len(values) <= 16 or len(set(values)) != len(values) or not all(named(value) for value in values):
            raise AdmissionError("finite policy domain exceeds its envelope", "inconclusive")
    # Native regex's pattern is the REQUEST resource, because the actual model
    # uses regexMatch(p.obj,r.obj). No unbounded/user-chosen regex is run.
    if any(not re.fullmatch(r"[A-Za-z0-9_:./-]+", resource) for resource in domain["resources"]):
        raise AdmissionError("finite request resources must be literal regex-safe strings")
    if len(contexts) * len(domain["resources"]) * len(domain["actions"]) > 4096:
        raise AdmissionError("YAML comparison cell budget exceeded", "inconclusive")
    for context in contexts:
        if (type(context) is not dict or set(context) != {"user", "groups"} or not named(context["user"])
                or type(context["groups"]) is not list or len(context["groups"]) > 16 or not all(named(item) for item in context["groups"])):
            raise AdmissionError("context needs a bounded user and supplied group strings", "input_rejected")
    program = extract_policy_program(source, class_name=class_name)
    original = deepcopy(data)
    expected_rows = reference_rows(data)
    _check_role_depth("rbac", expected_rows)
    store = NativePolicyStore(model_text, initial_policy)
    try:
        producer = PolicyInterpreter(program, deepcopy(data), store)
        producer.run("_sync_yaml_to_casbin", [])
        observed_rows = store.rows()
        _check_role_depth("rbac", observed_rows)
        persisted = configuration(model_text, store.path.read_text(encoding="utf-8")).rows
        producer_agrees = observed_rows == expected_rows and persisted == observed_rows
        comparisons, samples = [], []
        for index, context in enumerate(contexts):
            user = context["user"]
            policy = {"principals": [user], **deepcopy(domain), "roles": [], "members": [], "state": [], "aliases": [], "rules": []}
            observed = {}
            for resource, action in itertools.product(domain["resources"], domain["actions"]):
                expected = reference_decision(data, expected_rows, user, resource, action, context["groups"])
                if expected:
                    policy["rules"].append({"decision": "allow", "guard": [{"field": "resource", "name": resource, "negated": False},
                        {"field": "action", "name": action, "negated": False}], "updates": []})
                interpreter = PolicyInterpreter(program, deepcopy(data), store)
                outcome = interpreter.run("check_permission", [user, resource, action, list(context["groups"])])
                if type(outcome) is not tuple or len(outcome) != 2 or type(outcome[0]) is not bool or type(outcome[1]) is not str:
                    raise AdmissionError("policy consumer did not return a typed decision/reason pair", "invalid")
                observed[(resource, action)] = outcome[0]
                samples.append({"context": index, "resource": resource, "action": action, "allow": outcome[0], "reference_allow": expected,
                                "native_calls": interpreter.native_calls})
            policy = normalize(policy)
            alphabet = [[user, resource, action] for resource in policy["resources"] for action in policy["actions"]]
            machine = {"state_names": [], "alphabet": alphabet, "observations": [0], "initial": 0,
                       "transitions": [[["allow" if observed[(row[1], row[2])] else "deny", 0] for row in alphabet]]}
            comparisons.append({"context": context, "comparison": verify_reachable(policy, machine), "policy": policy, "machine": machine})
        if data != original:
            raise AdmissionError("comparison mutated the supplied YAML data", "invalid")
        if store.rows() != observed_rows:
            raise AdmissionError("consumer changed the policy store; static observation no longer sufficient", "unsupported")
        ignored = [{"rule": rule.get("name", "unnamed rule"), "condition_keys": sorted(set(rule.get("condition", {})) - CONDITIONS),
                    "metadata_keys": sorted(rule.get("metadata", {}))} for rule in data.get("rules", [])
                   if set(rule.get("condition", {})) - CONDITIONS or rule.get("metadata")]
        accepted = producer_agrees and all(row["comparison"]["accepted"] for row in comparisons)
        return {"status": "equivalent" if accepted else "mismatch", "accepted": accepted, "scope": "selected YAML producer and policy consumer on declared finite supplied inputs",
            "producer_rows_agree": producer_agrees, "expected_rows": expected_rows, "observed_rows": observed_rows,
            "persisted_rows": persisted, "source_descriptor": program_descriptor(program), "contexts": comparisons, "cells": samples,
            "counts": {"contexts": len(contexts), "consumer_cells": len(samples), "native_operations": dict(store.counts),
                       "producer_interpretation_steps": producer.steps},
            "ignored_input_fields_not_certified_as_enforced": ignored, "whole_application_verified": False,
            "jwt_issuer_or_live_groups_verified": False, "native_runtime": engine_identity()}
    finally:
        store.close()
