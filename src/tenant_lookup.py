"""A narrow source-bound permission -> tenant-filtered UUID lookup interface.

This does not execute the source endpoint. ORM relationship loading, response
serialization, credential validation and the application DB remain outside the
interface. The selected query runs against an owned in-memory UUID table.
"""
import ast
from uuid import UUID

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from tenant_dependency import TenantPrincipal, evaluate_tenant_dependency
from tenant_query import apply_query_filter, extract_query_filter, query_runtime
from source_bindings import require_import_bindings


def _same(left, right):
    return ast.dump(left, include_attributes=False) == ast.dump(ast.parse(right, mode="eval").body, include_attributes=False)


def extract_tenant_lookup(source, function_name):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("lookup source exceeds byte envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("lookup source does not parse", "invalid") from error
    bindings = require_import_bindings(source, {
        "uuid": ("uuid", 0, None), "Depends": ("fastapi", 0, "Depends"),
        "HTTPException": ("fastapi", 0, "HTTPException"), "select": ("sqlalchemy", 0, "select"),
        "selectinload": ("sqlalchemy.orm", 0, "selectinload"),
        "require_perm": ("dlw.authz.deps", 0, "require_perm"),
        "tenant_filtered": ("dlw.db.tenant_scope", 0, "tenant_filtered"),
        "DownloadTask": ("dlw.db.models.task", 0, "DownloadTask"),
        "TaskDetail": ("dlw.schemas.task", 0, "TaskDetail")})
    functions = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function_name]
    if len(functions) != 1 or not isinstance(functions[0], ast.AsyncFunctionDef):
        raise AdmissionError("lookup must be a unique async endpoint")
    f = functions[0]
    if len(f.decorator_list) != 1 or not _same(f.decorator_list[0], 'router.get("/{task_id}")'):
        raise AdmissionError("lookup decorator differs from its admitted literal route")
    a = f.args
    if ([p.arg for p in a.args] != ["task_id", "principal", "session"] or a.posonlyargs or a.kwonlyargs
            or a.vararg or a.kwarg or len(a.defaults) != 2 or not _same(a.defaults[1], "Depends(_session)")
            or a.args[0].annotation is None or not _same(a.args[0].annotation, "uuid.UUID")):
        raise AdmissionError("lookup input dependencies are outside the interface")
    default = a.defaults[0]
    if not (isinstance(default, ast.Call) and isinstance(default.func, ast.Name) and default.func.id == "Depends"
            and len(default.args) == 1 and not default.keywords):
        raise AdmissionError("lookup principal is not obtained through its declared dependency")
    guard = default.args[0]
    if not (isinstance(guard, ast.Call) and isinstance(guard.func, ast.Name) and guard.func.id == "require_perm"
            and len(guard.args) == 2 and not guard.keywords and all(isinstance(n, ast.Constant) and type(n.value) is str for n in guard.args)):
        raise AdmissionError("lookup permission factory must have two literal arguments")
    statements = [n for n in f.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]
    if len(statements) != 3:
        raise AdmissionError("lookup contains additional unreviewed endpoint effects")
    assignment, missing, response = statements
    if not (isinstance(assignment, ast.Assign) and len(assignment.targets) == 1 and isinstance(assignment.targets[0], ast.Name)
            and assignment.targets[0].id == "row"):
        raise AdmissionError("lookup query assignment is not bound to row")
    expression = assignment.value
    if not (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Attribute)
            and expression.func.attr == "scalar_one_or_none" and not expression.args and not expression.keywords
            and isinstance(expression.func.value, ast.Await)):
        raise AdmissionError("lookup scalar result consumption is unsupported")
    execute = expression.func.value.value
    if not (isinstance(execute, ast.Call) and _same(execute.func, "session.execute")
            and len(execute.args) == 1 and not execute.keywords):
        raise AdmissionError("lookup query is not bound to its supplied session")
    query = execute.args[0]
    options_omitted = False
    if (isinstance(query, ast.Call) and isinstance(query.func, ast.Attribute) and query.func.attr == "options"):
        if len(query.args) != 1 or query.keywords or not _same(query.args[0], "selectinload(DownloadTask.subtasks)"):
            raise AdmissionError("unreviewed ORM query options")
        query = query.func.value
        options_omitted = True
    if not (isinstance(query, ast.Call) and isinstance(query.func, ast.Name) and query.func.id == "tenant_filtered"
            and len(query.args) == 3 and not query.keywords and _same(query.args[1], "DownloadTask")
            and _same(query.args[2], "principal") and _same(query.args[0], "select(DownloadTask).where(DownloadTask.id == task_id)")):
        raise AdmissionError("lookup model, identifier or tenant-filter principal binding changed")
    if not (isinstance(missing, ast.If) and _same(missing.test, "row is None") and not missing.orelse
            and len(missing.body) == 1 and isinstance(missing.body[0], ast.Raise)
            and missing.body[0].cause is None and _same(missing.body[0].exc, 'HTTPException(status_code=404, detail="task not found")')):
        raise AdmissionError("missing-row behavior differs from its declared 404 result")
    if not isinstance(response, ast.Return) or not _same(response.value, "TaskDetail.model_validate(row)"):
        raise AdmissionError("lookup response binding changed")
    return {"function": function_name, "line": f.lineno, "end_line": f.end_lineno,
            "permission_object": guard.args[0].value, "permission_action": guard.args[1].value,
            "query_input": "UUID", "orm_relationship_loading_omitted": options_omitted,
            "source_bindings": bindings,
            "response_fields_or_relationship_access_verified": False}


def compare_tenant_lookup(source, function_name, dependency, engine, query_source):
    runtime = query_runtime()
    from sqlalchemy import Column, Integer, MetaData, Table, Uuid, create_engine, select
    lookup = extract_tenant_lookup(source, function_name)
    filtering = extract_query_filter(query_source)
    db = create_engine("sqlite+pysqlite:///:memory:")
    table = Table("owned_tasks", MetaData(), Column("id", Uuid(as_uuid=True), primary_key=True), Column("tenant_id", Integer, nullable=False))
    records = [{"id": UUID(int=value), "tenant_id": tenant} for value, tenant in ((11, 1), (22, 2), (33, 3))]
    table.metadata.create_all(db)
    cases, native_queries, native_authorizations = [], 0, 0
    try:
        with db.begin() as connection:
            connection.execute(table.insert(), records)
        with db.connect() as connection:
            for role in ("tenant_operator", "tenant_viewer", "unlisted"):
                for tenant in (1, 2, 99):
                    for identifier in (11, 22, 33, 999):
                        principal = TenantPrincipal(11, tenant, role)
                        auth = evaluate_tenant_dependency(dependency, engine, principal, lookup["permission_object"], lookup["permission_action"])
                        native_authorizations += len(auth["native_calls"])
                        selected = []
                        if auth["decision"] == "deny":
                            response = 403
                        else:
                            query = select(table.c.id, table.c.tenant_id).where(table.c.id == UUID(int=identifier))
                            query = apply_query_filter(filtering, query, table, tenant)
                            selected = [{"id": str(row["id"]), "tenant_id": row["tenant_id"]} for row in connection.execute(query).mappings()]
                            native_queries += 1
                            response = 200 if selected else 404
                        # Independently specified read-only object ownership contract.
                        # Current upstream source assertions/documentation constrain
                        # the role permissions and cross-tenant 404 behavior.
                        exists_owned = any(row["id"] == UUID(int=identifier) and row["tenant_id"] == tenant for row in records)
                        expected = 403 if role == "unlisted" else 200 if exists_owned else 404
                        cases.append({"role": role, "caller_tenant": tenant, "object_id": str(UUID(int=identifier)),
                                      "expected_status": expected, "observed_status": response, "selected_rows": selected,
                                      "matches": expected == response, "source_dependency": auth})
    finally:
        db.dispose()
    accepted = all(row["matches"] for row in cases)
    return {"status": "agreement" if accepted else "mismatch", "accepted": accepted,
            "source_lookup": lookup, "source_query_filter": filtering, "query_runtime": runtime,
            "cases": cases, "native_select_executions": native_queries, "native_enforce_calls": native_authorizations,
            "scope": "selected source-bound authorization -> filtered UUID lookup on owned native SQL records",
            "application_endpoint_or_database_executed": False, "whole_application_verified": False,
            "native_orm_relationship_loading_or_response_serialization_verified": False}
