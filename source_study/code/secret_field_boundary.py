"""Owned metadata-to-model boundary repair; no application import or execution.

Complete a supplied exclusion list from literal column secrecy metadata. This
does not change a table, a query's explicit inclusion flag or historical source.
Unsupported descriptor/identity inputs stop admission instead of guessing.
"""
from effect_slice import DataRecord
from native_casbin import AdmissionError


def complete_secret_exclusions(table, excluded):
    if not isinstance(table, DataRecord):
        raise AdmissionError("field boundary requires the supplied table record")
    meta = table.fields.get("_meta")
    columns = meta.fields.get("columns") if isinstance(meta, DataRecord) else None
    if type(columns) is not list or type(excluded) not in (tuple, list):
        raise AdmissionError("field boundary requires finite column and exclusion lists")
    if len({id(c) for c in columns}) != len(columns):
        raise AdmissionError("ambiguous repeated column identity")
    names = set()
    secrets = []
    for column in columns:
        cm = column.fields.get("_meta") if isinstance(column, DataRecord) else None
        name = cm.fields.get("name") if isinstance(cm, DataRecord) else None
        secret = cm.fields.get("secret") if isinstance(cm, DataRecord) else None
        if type(name) is not str or not name or name in names or type(secret) is not bool:
            raise AdmissionError("column identity and literal secrecy metadata required")
        names.add(name)
        if secret:
            secrets.append(column)
    result = []
    for column in excluded:
        if not any(column is candidate for candidate in columns):
            raise AdmissionError("cross-table exclusion identity is not admitted")
        if not any(column is candidate for candidate in result):
            result.append(column)
    for column in secrets:
        if not any(column is candidate for candidate in result):
            result.append(column)
    return result
