"""Interpret one typed query-scope expression with native SQLAlchemy values.

Only SELECT statements over the supplied owned integer table are evaluated.
No application import, external database, transaction routine or route is run.
"""
import ast
from importlib import metadata
from pathlib import Path

from native_casbin import AdmissionError, MAX_TEXT_BYTES


def query_runtime():
    import sqlalchemy
    distribution = metadata.distribution("SQLAlchemy")
    if distribution.version != "2.0.55" or Path(sqlalchemy.__file__).resolve() != Path(distribution.locate_file("sqlalchemy/__init__.py")).resolve():
        raise AdmissionError("query check needs its isolated reviewed SQLAlchemy runtime", "dependency_missing")
    return {"distribution": "SQLAlchemy", "release": distribution.version, "module": sqlalchemy.__file__}


def extract_query_filter(source):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("query source exceeds input envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("query helper source does not parse", "invalid") from error
    matches = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "tenant_filtered"]
    if len(matches) != 1 or not isinstance(matches[0], ast.FunctionDef):
        raise AdmissionError("query helper must be one synchronous function")
    function = matches[0]
    args = function.args
    if (function.decorator_list or [a.arg for a in args.args] != ["stmt", "model", "principal"]
            or args.posonlyargs or args.vararg or args.kwarg or args.kwonlyargs or args.defaults):
        raise AdmissionError("query helper interface is outside the typed fragment")
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body.pop(0)
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        raise AdmissionError("query helper contains unsupported statements")
    expression = body[0].value
    if isinstance(expression, ast.Name) and expression.id == "stmt":
        # Deliberately admitted: an identity helper must be checkable as an
        # owned missing-filter negative control, not assumed correct by shape.
        return {"operation": "identity", "line": function.lineno}
    if not (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Attribute)
            and isinstance(expression.func.value, ast.Name) and expression.func.value.id == "stmt"
            and expression.func.attr == "where" and len(expression.args) == 1 and not expression.keywords):
        raise AdmissionError("query helper is not a single typed where expression")
    comparison = expression.args[0]
    if not (isinstance(comparison, ast.Compare) and len(comparison.ops) == 1 and isinstance(comparison.ops[0], ast.Eq)
            and len(comparison.comparators) == 1):
        raise AdmissionError("query predicate must be a typed equality")
    operands = []
    for node in (comparison.left, comparison.comparators[0]):
        if not (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id in ("model", "principal") and node.attr == "tenant_id"):
            raise AdmissionError("query predicate references an unbound field")
        operands.append(node.value.id)
    return {"operation": "where_equal", "operands": operands, "line": function.lineno,
            "end_line": function.end_lineno}


def apply_query_filter(extraction, statement, table, tenant):
    if type(tenant) is not int:
        raise AdmissionError("query principal needs an integer tenant", "invalid")
    if extraction["operation"] == "identity":
        return statement
    if extraction["operation"] != "where_equal":
        raise AdmissionError("unknown extracted query operation")
    values = {"model": table.c.tenant_id, "principal": tenant}
    left, right = (values[operand] for operand in extraction["operands"])
    return statement.where(left == right)


def compare_query_filter(source):
    runtime = query_runtime()
    from sqlalchemy import Column, Integer, MetaData, Table, create_engine, select
    extraction = extract_query_filter(source)
    engine = create_engine("sqlite+pysqlite:///:memory:")
    metadata_table = MetaData()
    table = Table("owned_records", metadata_table, Column("id", Integer, primary_key=True), Column("tenant_id", Integer, nullable=False))
    records = [{"id": 11, "tenant_id": 1}, {"id": 22, "tenant_id": 2}, {"id": 33, "tenant_id": 3}]
    metadata_table.create_all(engine)
    outputs = []
    try:
        with engine.begin() as connection:
            connection.execute(table.insert(), records)
        with engine.connect() as connection:
            for tenant in (1, 2, 3, 99):
                for base in ("all", "id_22", "id_ge_22"):
                    query = select(table.c.id, table.c.tenant_id)
                    if base == "id_22":
                        query = query.where(table.c.id == 22)
                    elif base == "id_ge_22":
                        query = query.where(table.c.id >= 22)
                    query = apply_query_filter(extraction, query, table, tenant).order_by(table.c.id)
                    observed = [dict(row) for row in connection.execute(query).mappings()]
                    expected = [row for row in records if row["tenant_id"] == tenant and
                                (base == "all" or base == "id_22" and row["id"] == 22 or base == "id_ge_22" and row["id"] >= 22)]
                    compiled = query.compile(dialect=engine.dialect)
                    outputs.append({"principal_tenant": tenant, "base_query": base, "expected": expected,
                                    "observed": observed, "matches": observed == expected,
                                    "native_sql": str(compiled), "bind_parameters": compiled.params})
    finally:
        engine.dispose()
    return {"status": "agreement" if all(row["matches"] for row in outputs) else "mismatch",
            "accepted": all(row["matches"] for row in outputs), "query_runtime": runtime,
            "source_extraction": extraction, "native_select_executions": len(outputs), "cases": outputs,
            "scope": "source helper expression, native SQLAlchemy SELECT/SQLite on owned integer records",
            "application_database_or_all_query_sites_verified": False,
            "postgresql_async_transactions_verified": False, "source_module_executed": False}
