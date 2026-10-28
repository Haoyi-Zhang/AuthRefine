"""Selected version-tagged policy cache and request snapshot source boundary.

Repository reads are owned immutable epoch providers. This does not execute
MySQL/transactions, establish their isolation, or certify concurrent snapshots.
"""
import configparser
from itertools import product

from effect_slice import (Capability, DataRecord, EffectInterpreter, ErrorType, RecordType, SerialContext,
                          SliceFault, extract_effect_program)
from native_casbin import AdmissionError
from native_runtime import engine_identity
from observation_protocol import compare_observations
from source_bindings import require_import_bindings


METHODS = ("authorize", "require", "build_snapshot", "_get_cache", "_subjects")
SNAPSHOT_FIELDS = ("allowed_metrics", "allowed_tables", "allowed_columns", "allowed_department_ids")
PREFIXES = ("metric:", "table:", "column:", "row:department:")


def admit_model(model):
    parsed = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=True)
    try:
        parsed.read_string(model)
    except configparser.Error as error:
        raise AdmissionError("version cache model does not parse", "invalid") from error
    expected = {"request_definition": {"r": "subjects,obj,act"}, "policy_definition": {"p": "sub,obj,act,eft"},
                "policy_effect": {"e": "some(where(p_eft==allow))&&!some(where(p_eft==deny))"},
                "matchers": {"m": "subjectMatch(r.subjects,p.sub)&&r.obj==p.obj&&r.act==p.act"}}
    actual = {section: {name: "".join(value.split()) for name, value in parsed.items(section)} for section in parsed.sections()}
    if parsed.defaults() or actual != expected:
        raise AdmissionError("tuple-subject/deny-overrides model changed; no guessed conversion")


def admit_epochs(epochs):
    if type(epochs) is not list or not 1 <= len(epochs) <= 8:
        raise AdmissionError("version cache needs one through eight owned epochs", "inconclusive")
    versions = set()
    for epoch in epochs:
        if (type(epoch) is not dict or set(epoch) != {"version", "rows"} or type(epoch["version"]) is not int
                or not 0 <= epoch["version"] <= 1_000_000 or epoch["version"] in versions
                or type(epoch["rows"]) is not list or len(epoch["rows"]) > 64):
            raise AdmissionError("epoch identity/row envelope is invalid")
        versions.add(epoch["version"])
        for row in epoch["rows"]:
            if (type(row) is not list or len(row) != 4 or any(type(value) is not str or not value or len(value) > 256 for value in row)
                    or not row[0].startswith(("user:", "role:")) or "*" in row[0] or "*" in row[1]
                    or row[2] not in {"execute", "read", "review", "manage"} or row[3] not in {"allow", "deny"}):
                raise AdmissionError("policy epoch contains an unadmitted literal row")


def reference_allow(rows, user, roles, resource, action):
    subjects = {"user:" + user, *("role:" + role for role in roles)}
    effects = {effect for subject, obj, act, effect in rows if subject in subjects and obj == resource and act == action}
    return "allow" in effects and "deny" not in effects


class VersionedEvaluation:
    def __init__(self, source, model, epochs, *, limit=50000, class_name="AuthorizationService"):
        require_import_bindings(source, {"casbin": ("casbin", 0, None),
            "AuthContext": ("app.entities.auth", 0, "AuthContext"), "PermissionSnapshot": ("app.entities.auth", 0, "PermissionSnapshot")})
        admit_model(model)
        admit_epochs(epochs)
        self.identity, self.epochs, self.epoch = engine_identity(), epochs, 0
        self.counts = {"version_reads": 0, "policy_reads": 0, "native_constructions": 0, "native_enforce": 0,
                       "native_add_policy": 0, "serial_lock_entries": 0}
        self.fault = None
        self.cache_state = DataRecord("cache_state", {"cache": None}, frozenset({"cache"}))
        def current_version():
            self.counts["version_reads"] += 1
            if self.fault == "version":
                raise SliceFault("RepositoryError", "owned version failure")
            return self.epochs[self.epoch]["version"]
        def active():
            self.counts["policy_reads"] += 1
            if self.fault == "policies":
                raise SliceFault("RepositoryError", "owned active-row failure")
            return [DataRecord("policy", dict(zip(("subject", "resource", "action", "effect"), row))) for row in self.epochs[self.epoch]["rows"]]
        def enter():
            self.counts["serial_lock_entries"] += 1
        self.cache_state.fields["reload_lock"] = SerialContext(enter, lambda: None)
        receiver = DataRecord("receiver", {"repository": DataRecord("repository", {"current_version": Capability("version", current_version, True),
            "list_active": Capability("active", active, True)}), "_cache_state": self.cache_state, "model_path": "owned-source-model"})
        program = extract_effect_program(source, class_name, METHODS, ("_subject_match",))
        self.interpreter = EffectInterpreter(program, receiver, {"casbin": DataRecord("native_module", {"Enforcer": Capability("Enforcer", self.engine)}),
            "_PolicyCache": RecordType("cache", ("version", "enforcer", "policies")),
            "PermissionSnapshot": RecordType("snapshot", ("policy_version", *SNAPSHOT_FIELDS, "sql_fallback_allowed")),
            "AuthorizationUnavailableError": ErrorType("AuthorizationUnavailableError"),
            "AuthorizationError": ErrorType("AuthorizationError"), "Exception": ErrorType("Exception")}, limit)
        self.model = model

    def engine(self, path):
        if path != "owned-source-model":
            raise AdmissionError("native construction path no longer binds the supplied model")
        import casbin
        model = casbin.Model()
        model.load_model_from_text(self.model)
        engine = casbin.Enforcer(model)
        engine.enable_auto_save(False)
        self.counts["native_constructions"] += 1
        def register(name, callback):
            if name != "subjectMatch":
                raise AdmissionError("unknown custom matcher function")
            def subject_match(subjects, subject):
                return self.interpreter.invoke(callback, [subjects, subject], {})
            engine.add_function(name, subject_match)
        def add(*row):
            if len(row) != 4 or any(type(value) is not str for value in row):
                raise AdmissionError("produced native row has invalid types")
            self.counts["native_add_policy"] += 1
            return engine.add_policy(*row)
        def enforce(subjects, resource, action):
            if type(subjects) is not tuple or any(type(value) is not str for value in subjects):
                raise AdmissionError("native principal must be the produced tuple, not one string")
            self.counts["native_enforce"] += 1
            try:
                result = engine.enforce(subjects, resource, action)
            except AdmissionError:
                raise
            except Exception as error:
                raise SliceFault("NativeError", type(error).__name__) from error
            if type(result) is not bool:
                raise AdmissionError("native tuple authorization did not return Boolean", "native_error")
            return result
        return DataRecord("native_enforcer", {"add_function": Capability("register", register), "add_policy": Capability("add", add), "enforce": Capability("enforce", enforce)})

    def call(self, method, user, roles, *arguments):
        auth = DataRecord("auth", {"user_id": user, "roles": frozenset(roles)})
        return self.interpreter.run(method, [auth, *arguments])


def compare_versioned_cache(source, model, epochs, requests, *, class_name="AuthorizationService"):
    admit_epochs(epochs)
    if (type(requests) is not list or not 1 <= len(requests) <= 32
            or any(type(row) is not list or len(row) != 2 or any(type(value) is not str or not value for value in row) for row in requests)):
        raise AdmissionError("version cache request envelope is invalid")
    reference, observed, cases, counts = [], [], [], []
    for user, mask in product(("alice", "bob"), range(4)):
        roles = [role for index, role in enumerate(("reader", "blocked")) if mask & (1 << index)]
        evaluation = VersionedEvaluation(source, model, epochs, class_name=class_name)
        for epoch_index in [i for i in range(len(epochs)) for _ in range(2)]:
            evaluation.epoch = epoch_index
            epoch = epochs[epoch_index]
            for resource, action in requests:
                decision = evaluation.call("authorize", user, roles, resource, action)
                expected = reference_allow(epoch["rows"], user, roles, resource, action)
                cache = evaluation.cache_state.fields["cache"]
                reference.append({"decision": "allow" if expected else "deny", "flags": {"version_current": True}})
                observed.append({"decision": "allow" if decision else "deny", "flags": {"version_current": cache.fields["version"] == epoch["version"]}})
                cases.append({"kind": "authorize", "user": user, "roles": roles, "epoch": epoch["version"], "resource": resource, "action": action,
                              "expected": expected, "observed": decision, "cached_version": cache.fields["version"]})
            snapshot = evaluation.call("build_snapshot", user, roles)
            flags, expected_sets = {}, {}
            for field, prefix in zip(SNAPSHOT_FIELDS, PREFIXES):
                expected_sets[field] = {resource[len(prefix):] for subject, resource, action, effect in epoch["rows"]
                    if resource.startswith(prefix) and action == "read" and reference_allow(epoch["rows"], user, roles, resource, action)}
                flags[field + "_exact"] = snapshot.fields[field] == frozenset(expected_sets[field])
            expected_fallback = reference_allow(epoch["rows"], user, roles, "api:sql-fallback", "execute")
            # Snapshot comparisons retain exact field values below. Their
            # Boolean equality observations use a separate fixed six-bit schema.
            cases.append({"kind": "snapshot", "user": user, "roles": roles, "epoch": epoch["version"],
                "expected_sets": {key: sorted(value) for key, value in expected_sets.items()},
                "observed_sets": {field: sorted(snapshot.fields[field]) for field in SNAPSHOT_FIELDS},
                "expected_fallback": expected_fallback, "observed_fallback": snapshot.fields["sql_fallback_allowed"],
                "snapshot_version": snapshot.fields["policy_version"], "field_equalities": flags})
        counts.append({"user": user, "roles": roles, **evaluation.counts})
    auth_result = compare_observations(reference, observed, "version-checked native tuple-subject authorization under stable owned repository epochs")
    snapshots = [row for row in cases if row["kind"] == "snapshot"]
    expected_snapshots = [{"decision": "allow" if row["expected_fallback"] else "deny", "flags": {**{name: True for name in row["field_equalities"]}, "version_current": True}} for row in snapshots]
    actual_snapshots = [{"decision": "allow" if row["observed_fallback"] else "deny", "flags": {**row["field_equalities"], "version_current": row["snapshot_version"] == row["epoch"]}} for row in snapshots]
    snapshot_result = compare_observations(expected_snapshots, actual_snapshots, "exact returned snapshot fields against independent epoch row/filter contract, not unrestricted trace reconstruction")
    accepted = auth_result["accepted"] and snapshot_result["accepted"]
    return {"accepted": accepted, "status": "equivalent" if accepted else "mismatch", "authorization": auth_result, "snapshots": snapshot_result,
            "scope": "selected versioned cache and snapshot fields on stable owned epochs; database isolation and concurrent histories unverified",
            "cases": cases, "counts_by_identity": counts, "stable_epoch_within_each_call": True,
            "source_modules_or_database_executed": False, "mysql_isolation_or_concurrent_snapshot_consistency_verified": False,
            "whole_application_verified": False}
