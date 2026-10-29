"""H19 selected metadata-to-consumer comparison; no ORM import or request.

The declared minimum ORM profile is explicit, not a historical installed lock.
Only ordinary field names / booleans are used. No session, credential value,
query, database, HTTP route or advisory example is executed.
"""
import ast
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent / "source/h19"
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from effect_slice import Capability, DataRecord, EffectInterpreter, RecordType, extract_effect_program
from native_casbin import AdmissionError
from source_bindings import require_import_bindings, require_static_class_members, require_static_definitions

CASE = ROOT
ORM = CASE / "orm-contract"
FIELDS = ("id", "token", "user_id", "expiry_date", "max_expiry_date")


def shape(node):
    return ast.dump(node, include_attributes=False)


def definition(raw, class_name, name):
    tree = ast.parse(raw)
    require_static_definitions(tree, [class_name], ())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    require_static_class_members(cls, [name])
    return next(node for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name)


def selected_program(crud):
    require_import_bindings(crud, {"create_pydantic_model": ("piccolo.utils.pydantic", 0, "create_pydantic_model")})
    filters = definition(crud, "PiccoloCRUD", "pydantic_model_filters")
    if [shape(node) for node in filters.decorator_list] != [shape(ast.Name(id="property", ctx=ast.Load()))]:
        raise AdmissionError("selected filter getter is not a plain property")
    last = filters.body[-1]
    if (not isinstance(last, ast.If)
            or shape(last.test) != shape(ast.parse("multidimensional_array_columns or email_columns", mode="eval").body)
            or len(last.orelse) != 1 or shape(last.orelse[0]) != shape(ast.parse("return base_model").body[0])):
        raise AdmissionError("the declared no-array/no-email filter branch changed")
    # Given SessionsBase has no array / email columns, the exact else body is
    # selected. The discarded branch's model factories are not interpreted.
    selected = copy.deepcopy(filters)
    selected.decorator_list = []
    selected.body = copy.deepcopy(filters.body[:-1] + last.orelse)
    getter = definition(crud, "PiccoloCRUD", "get_all")
    calls = [node for node in ast.walk(getter) if isinstance(node, ast.Assign) and len(node.targets) == 1
        and shape(node.targets[0]) == shape(ast.Name(id="query", ctx=ast.Store()))
        and isinstance(node.value, ast.Call) and shape(node.value.func) == shape(ast.parse("self.table.select", mode="eval").body)]
    if len(calls) != 1:
        raise AdmissionError("selected get_all query construction is ambiguous")
    # Do not substitute copied flags: interpret the actual select-call AST.
    wrapper = ast.parse("def selected_select(self, visible_fields, readable_columns):\n    return None\n").body[0]
    wrapper.body = [ast.Return(value=copy.deepcopy(calls[0].value))]
    module = ast.Module(body=[ast.ClassDef(name="Selected", bases=[], keywords=[], body=[selected, wrapper], decorator_list=[])], type_ignores=[])
    program = extract_effect_program(ast.unparse(ast.fix_missing_locations(module)).encode(), "Selected",
        ("pydantic_model_filters", "selected_select"))
    init = definition(crud, "PiccoloCRUD", "__init__")
    defaults = dict(zip([arg.arg for arg in init.args.args][-len(init.args.defaults):], init.args.defaults))
    default = ast.literal_eval(defaults["exclude_secrets"])
    if type(default) is not bool:
        raise AdmissionError("output-exclusion default is not a literal boolean")
    return program, default, {"filter_getter": [filters.lineno, filters.end_lineno],
        "selected_query_call": [calls[0].lineno, calls[0].end_lineno], "array_columns_and_email_columns_given_empty": True}


def token_secret(table_source):
    require_import_bindings(table_source, {"Varchar": ("piccolo.columns", 0, "Varchar")})
    tree = ast.parse(table_source)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "SessionsBase")
    nodes = [node for node in cls.body if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(isinstance(target, ast.Name) and target.id == "token" for target in
            ([node.target] if isinstance(node, ast.AnnAssign) else node.targets))]
    if len(nodes) != 1 or not isinstance(nodes[0].value, ast.Call) or not isinstance(nodes[0].value.func, ast.Name) or nodes[0].value.func.id != "Varchar":
        raise AdmissionError("the selected token declaration changed")
    call = nodes[0].value
    if call.args or any(keyword.arg is None for keyword in call.keywords):
        raise AdmissionError("dynamic token constructor inputs are not admitted")
    secret = [keyword.value for keyword in call.keywords if keyword.arg == "secret"]
    value = ast.literal_eval(secret[0]) if len(secret) == 1 else False if not secret else None
    if type(value) is not bool:
        raise AdmissionError("token secrecy is not a boolean declaration")
    return value


def minimum_registry_program():
    raw = (ORM / "piccolo/table.py").read_bytes()
    tree = ast.parse(raw)
    candidates = [node for node in ast.walk(tree) if isinstance(node, ast.If) and any(
        isinstance(item, ast.Expr) and shape(item.value) == shape(ast.parse("secret_columns.append(column)", mode="eval").body)
        for item in node.body)]
    if len(candidates) != 1:
        raise AdmissionError("ORM secret registry classification is ambiguous")
    test = candidates[0].test
    if shape(test) != shape(ast.parse("isinstance(column, Secret)", mode="eval").body):
        raise AdmissionError("declared minimum registry classification changed")
    function = ast.parse("def registry_member(column):\n    return False\n").body[0]
    function.body = [ast.Return(value=copy.deepcopy(test))]
    module = ast.Module(body=[function], type_ignores=[])
    return extract_effect_program(ast.unparse(ast.fix_missing_locations(module)).encode(), None, (), ("registry_member",))


def observe(crud, table_source, requested, configured, *, corrected_registry=False):
    if (configured is not None and type(configured) is not bool
            or type(corrected_registry) is not bool
            or requested is not None and (type(requested) is not tuple or not requested
                or len(requested) > len(FIELDS) or any(type(name) is not str or name not in FIELDS for name in requested)
                or len(set(requested)) != len(requested))):
        raise AdmissionError("selected comparison needs bounded, unique ordinary field names and literal flags")
    program, default, _ = selected_program(crud)
    secret = token_secret(table_source)
    columns = [DataRecord("Column", {"_meta": DataRecord("column_meta", {"name": name, "secret": secret if name == "token" else False})}) for name in FIELDS]
    registry = EffectInterpreter(minimum_registry_program(), DataRecord("unused", {}), {"Secret": RecordType("Secret", ())})
    registry_columns = ([column for column in columns if column.fields["_meta"].fields["secret"]] if corrected_registry else
        [column for column in columns if registry.run("registry_member", [column])])
    meta = DataRecord("given_table_meta", {"columns": columns, "array_columns": [], "email_columns": [], "secret_columns": registry_columns})
    table = DataRecord("given_table", {"__name__": "SessionsBase", "_meta": meta})
    # This selected dependency method is interpreted, not rewritten as an
    # always-successful external query. No actual SQL / ORM instance is made.
    remove_raw = (ORM / "piccolo/query/mixins.py").read_bytes()
    require_import_bindings(remove_raw, {"Column": ("piccolo.columns", 0, "Column")})
    method = definition(remove_raw, "ColumnsDelegate", "remove_secret_columns")
    # The given receiver supplies already constructed dataclass fields. Only
    # the unmodified ordinary method body is selected; no dataclass creation.
    module = ast.Module(body=[ast.ClassDef(name="SelectedDelegate", bases=[], keywords=[],
        body=[copy.deepcopy(method)], decorator_list=[])], type_ignores=[])
    remove = extract_effect_program(ast.unparse(ast.fix_missing_locations(module)).encode(), "SelectedDelegate", ("remove_secret_columns",))

    def select(*values, exclude_secrets):
        if type(exclude_secrets) is not bool:
            raise AdmissionError("nonboolean selected-query exclusion")
        receiver = DataRecord("given_delegate", {"selected_columns": list(values)}, frozenset({"selected_columns"}))
        if exclude_secrets:
            EffectInterpreter(remove, receiver, {"Column": RecordType("Column", ())}).run("remove_secret_columns", [])
        return [value.fields["_meta"].fields["name"] for value in receiver.fields["selected_columns"]]

    def model(given_table, *, include_default_columns, exclude_columns, all_optional, model_name):
        if given_table is not table or not include_default_columns or not all_optional or model_name != "SessionsBaseFilters":
            raise AdmissionError("filter field observer received an undeclared model configuration")
        # The no-joins, same-table ordinary field-identity subset of
        # create_pydantic_model is observed, not its validators or HTTP parsing.
        return [column.fields["_meta"].fields["name"] for column in columns if not any(column is other for other in exclude_columns)]

    table.fields["select"] = Capability("selected_query_fields", select)
    receiver = DataRecord("given_crud", {"table": table, "exclude_secrets": default if configured is None else configured})
    interpreter = EffectInterpreter(program, receiver, {"create_pydantic_model": Capability("given_model_field_observer", model)})
    selected = columns if requested is None else [column for name in requested for column in columns if column.fields["_meta"].fields["name"] == name]
    return {"query_fields": interpreter.run("selected_select", [selected, []]),
        "filter_fields": interpreter.run("pydantic_model_filters", []),
        "token_metadata_secret": secret, "registry_fields": [column.fields["_meta"].fields["name"] for column in registry_columns]}


def check_bindings():
    trace = json.loads((CASE / "source-trace.json").read_text(encoding="utf-8"))
    for row in trace["sources"]:
        raw = (CASE / row["label"] / row["path"]).read_bytes()
        if len(raw) != row["bytes"] or hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != row["git_blob"]:
            raise AdmissionError("historical API source identity changed")
    binding = json.loads((ORM / "binding.json").read_text(encoding="utf-8"))
    manifest = (ORM / "api-requirements.txt").read_bytes()
    if (binding["version"] != "1.16.0" or b"piccolo[postgres]>=1.16.0\n" not in manifest
            or hashlib.sha1(b"blob " + str(len(manifest)).encode() + b"\0" + manifest).hexdigest() != binding["api_source_requirements_blob"]):
        raise AdmissionError("minimum ORM profile is not from the bound dependency source manifest")
    for row in binding["members"]:
        raw = (ORM / row["member"]).read_bytes()
        if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise AdmissionError("declared minimum ORM source identity changed")
    base = ast.parse((ORM / "piccolo/columns/base.py").read_bytes())
    column = next(node for node in base.body if isinstance(node, ast.ClassDef) and node.name == "Column")
    init = next(node for node in column.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
    defaults = dict(zip([node.arg for node in init.args.args][-len(init.args.defaults):], init.args.defaults))
    if ast.literal_eval(defaults["secret"]) is not False:
        raise AdmissionError("omitted secret keyword no longer means the declared minimum's False default")
    metadata_calls = [node for node in ast.walk(init) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "ColumnMeta"]
    if len(metadata_calls) != 1 or not any(keyword.arg == "secret" and shape(keyword.value) == shape(ast.Name(id="secret", ctx=ast.Load())) for keyword in metadata_calls[0].keywords):
        raise AdmissionError("column constructor no longer forwards the secret metadata")
    return trace, binding


def evaluate():
    trace, binding = check_bindings()
    choices = [None, ("token",), ("user_id",), ("token", "user_id"), FIELDS, ("expiry_date", "max_expiry_date")]
    rows = []
    for selected in choices:
        for flag in (None, True, False):
            requested = list(FIELDS if selected is None else selected)
            expected = {"query_fields": [name for name in requested if name != "token" or flag is False],
                "filter_fields": [name for name in FIELDS if name != "token"]}
            observed = {}
            for label in ("before", "after"):
                crud = (CASE / label / "piccolo_api/crud/endpoints.py").read_bytes()
                table = (CASE / label / "piccolo_api/session_auth/tables.py").read_bytes()
                observed[label] = observe(crud, table, selected, flag)
            control = observe((CASE / "after/piccolo_api/crud/endpoints.py").read_bytes(),
                (CASE / "after/piccolo_api/session_auth/tables.py").read_bytes(), selected, flag, corrected_registry=True)
            rows.append({"selected_fields": selected, "exclude_secrets_override": flag, "expected": expected,
                "observed": observed, "owned_metadata_registry_control": control})
    differences = {label: {part: sum(row["observed"][label][part] != row["expected"][part] for row in rows)
        for part in ("query_fields", "filter_fields")} for label in ("before", "after")}
    controlled = sum(any(row["owned_metadata_registry_control"][part] != row["expected"][part] for part in ("query_fields", "filter_fields")) for row in rows)
    if controlled:
        raise RuntimeError("the explicitly owned registry control does not meet the independently stated field contract")
    report = {"completed_utc": datetime.now(timezone.utc).isoformat(), "case": "H19", "contexts": len(rows),
        "dependency_fix": trace["dependency_fix"], "orm_source_profile": binding["version"],
        "profile_is_declared_minimum_not_installed_deployment_or_historical_lock": True,
        "different_selected_observations": differences, "owned_control_different_contexts": controlled,
        "interpretation": "The fixed token declaration reaches metadata-based output exclusion; the minimum ORM registers only Secret subclasses, not every Varchar(secret=True), so the new filter-model exclusion does not remove this token in this selected source profile.",
        "installed_version_or_live_vulnerability_conclusion": False, "historical_fix_fully_verified": False,
        "reading_scope": {"api_session_table": "complete before/after files",
            "api_crud": "constructor/default and filter getter complete; get_all selected query-call region",
            "ORM_1_16": {"piccolo/columns/base.py": [[144, 175], [406, 429], [455, 514]],
                "piccolo/columns/column_types.py": [[285, 353], [372, 380]],
                "piccolo/table.py": [[271, 358], [1003, 1030]],
                "piccolo/query/mixins.py": [[496, 525]], "piccolo/query/methods/select.py": [[155, 165], [539, 565]],
                "piccolo/utils/pydantic.py": [[114, 245], [258, 284]]}},
        "selected_source_AST_interpreted": True, "foreign_modules_imported_or_executed": False,
        "database_http_session_or_credentials_used": False, "new_security_finding_claimed": False,
        "premises": ["given ordinary same-table field descriptors", "no array, email, foreign key or readable columns",
            "given get_all selection point after earlier request parsing", "minimum ORM source profile, not historical installation",
            "field-name model observer, not Pydantic validation or SQL execution"],
        "rows": rows}
    return report


if __name__ == "__main__":
    result = evaluate()
    print(json.dumps({key: value for key, value in result.items() if key != "rows"}, indent=2))
