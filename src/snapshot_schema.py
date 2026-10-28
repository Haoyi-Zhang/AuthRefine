"""Bind the declared scalar projection of two source ORM tables, without ORM."""
import ast

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from source_bindings import require_import_bindings, require_static_definitions

TABLES = {"CasbinRule": {"ptype", *("v" + str(i) for i in range(6))},
    "ResourceOwner": {"user_id", "resource_type", "resource_id"}}


def bind_snapshot_schema(source):
    if type(source) is not bytes or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("snapshot schema exceeds its byte envelope")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("snapshot schema does not parse", "invalid") from error
    require_import_bindings(source, {"fields": ("tortoise", 0, "fields"), "Model": ("tortoise.models", 0, "Model")})
    require_static_definitions(tree, TABLES)
    result = {}
    for name, columns in TABLES.items():
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name)
        if (cls.decorator_list or cls.keywords or len(cls.bases) != 1
                or not isinstance(cls.bases[0], ast.Name) or cls.bases[0].id != "Model"):
            raise AdmissionError("snapshot table requires its direct declared Model base")
        declarations = {}
        for node in cls.body:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id in columns):
                field = node.targets[0].id
                if field in declarations:
                    raise AdmissionError("snapshot projected field is redeclared")
                declarations[field] = node
        if set(declarations) != columns:
            raise AdmissionError("snapshot scalar projection is incomplete")
        # A conditional/class-body rebinding cannot hide behind the one direct
        # declaration. Other ORM fields/Meta/functions are outside the projection.
        for node in cls.body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in columns:
                raise AdmissionError("snapshot table overwrites a projected field with a definition")
            if node in declarations.values() or isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del))
                    and item.id in columns for item in ast.walk(node)):
                raise AdmissionError("snapshot projected field has another class-body write")
        fields = {}
        for field, declaration in declarations.items():
            value = declaration.value
            expected = "IntField" if field in ("user_id", "resource_id") else "CharField"
            if (not isinstance(value, ast.Call) or value.args or not isinstance(value.func, ast.Attribute)
                    or not isinstance(value.func.value, ast.Name) or value.func.value.id != "fields"
                    or value.func.attr != expected or any(item.arg is None for item in value.keywords)
                    or len({item.arg for item in value.keywords}) != len(value.keywords)):
                raise AdmissionError("snapshot projected column constructor differs")
            nulls = [item.value for item in value.keywords if item.arg == "null"]
            if any(not isinstance(item, ast.Constant) or type(item.value) is not bool for item in nulls):
                raise AdmissionError("snapshot column nullability is dynamic")
            nullable = bool(nulls and nulls[0].value)
            if nullable != (field.startswith("v") and len(field) == 2):
                raise AdmissionError("snapshot projected nullability differs from the typed row contract")
            fields[field] = {"constructor": expected, "nullable": nullable, "line": declaration.lineno}
            if expected == "CharField":
                sizes = [item.value for item in value.keywords if item.arg == "max_length"]
                if (len(sizes) != 1 or not isinstance(sizes[0], ast.Constant) or type(sizes[0].value) is not int
                        or not 1 <= sizes[0].value <= 1_000_000):
                    raise AdmissionError("snapshot text column needs its declared bounded literal capacity")
                fields[field]["max_length"] = sizes[0].value
        result[name] = fields
    return result


def validate_projected_rows(schema, rules, owners):
    for table, rows in (("CasbinRule", rules), ("ResourceOwner", owners)):
        for row in rows:
            for name, value in row.items():
                field = schema[table][name]
                if value is None and field["nullable"]:
                    continue
                if field["constructor"] == "CharField" and (type(value) is not str or len(value) > field["max_length"]):
                    raise AdmissionError("supplied snapshot value exceeds its source text-column projection", "input_rejected")
