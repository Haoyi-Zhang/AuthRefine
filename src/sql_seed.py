"""Read selected literal rows from a bounded MySQL dump, never execute SQL.

Only CREATE column order and single-row literal INSERTs for explicitly selected
tables are admitted. Columns not requested by the caller are discarded. No dump
is sent to a database, and error messages do not include input literal values.
"""
import re

from native_casbin import AdmissionError


def _row(text):
    position, values = 0, []
    def space():
        nonlocal position
        while position < len(text) and text[position].isspace():
            position += 1
    space()
    if position == len(text) or text[position] != "(":
        raise AdmissionError("seed INSERT needs one literal row")
    position += 1
    while True:
        space()
        if position >= len(text):
            raise AdmissionError("unterminated seed row", "invalid")
        if text[position] == "'":
            position += 1
            result = []
            while position < len(text):
                value = text[position]
                position += 1
                if value == "'":
                    if position < len(text) and text[position] == "'":
                        result.append("'")
                        position += 1
                    else:
                        break
                elif value == "\\":
                    if position >= len(text):
                        raise AdmissionError("unterminated seed string escape", "invalid")
                    escaped = text[position]
                    position += 1
                    mapping = {"0": "\0", "b": "\b", "n": "\n", "r": "\r", "t": "\t", "Z": "\x1a", "\\": "\\", "'": "'", '"': '"'}
                    if escaped not in mapping:
                        raise AdmissionError("seed string escape is outside its admitted literal grammar")
                    result.append(mapping[escaped])
                else:
                    result.append(value)
                if len(result) > 16384:
                    raise AdmissionError("seed string envelope exceeded", "inconclusive")
            else:
                raise AdmissionError("unterminated seed string", "invalid")
            value = "".join(result)
        else:
            match = re.match(r"NULL|[-+]?\d+", text[position:])
            if match is None:
                raise AdmissionError("seed value is not an admitted string/integer/NULL literal")
            literal = match.group(0)
            if len(literal) > 21:
                raise AdmissionError("seed integer envelope exceeded", "inconclusive")
            position += len(literal)
            value = None if literal == "NULL" else int(literal)
            if type(value) is int and not -(2 ** 63) <= value < 2 ** 63:
                raise AdmissionError("seed integer is outside the owned signed-64-bit reference domain")
        values.append(value)
        if len(values) > 128:
            raise AdmissionError("seed column envelope exceeded", "inconclusive")
        space()
        if position >= len(text):
            raise AdmissionError("unterminated seed row", "invalid")
        delimiter = text[position]
        position += 1
        if delimiter == ")":
            break
        if delimiter != ",":
            raise AdmissionError("seed literal has an invalid delimiter", "invalid")
    space()
    if text[position:] != ";":
        raise AdmissionError("only a single-row INSERT without SQL expressions is supported")
    return values


def project_seed(source, requested):
    if not isinstance(source, bytes) or len(source) > 4 * 1024 * 1024:
        raise AdmissionError("seed byte envelope exceeded", "inconclusive")
    if (not isinstance(requested, dict) or not 1 <= len(requested) <= 8
            or any(not isinstance(table, str) or not re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", table)
                   or not isinstance(fields, (list, tuple)) or not fields
                   or any(not isinstance(field, str) or not re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", field) for field in fields)
                   or len(set(fields)) != len(fields)
                   for table, fields in requested.items())):
        raise AdmissionError("seed table/column projection is invalid", "invalid")
    try:
        text = source.decode("utf-8-sig", errors="strict")
    except UnicodeError as error:
        raise AdmissionError("seed encoding is not admitted", "invalid") from error
    columns, records = {}, {table: [] for table in requested}
    for table, selected in requested.items():
        pattern = r"^CREATE TABLE `" + re.escape(table) + r"` \((.*?)^\)"
        blocks = list(re.finditer(pattern, text, re.M | re.S))
        if len(blocks) != 1:
            raise AdmissionError("selected seed table needs one explicit CREATE declaration")
        fields = re.findall(r"^\s*`([^`]+)`", blocks[0].group(1), re.M)
        if len(set(fields)) != len(fields) or not set(selected) <= set(fields):
            raise AdmissionError("selected seed column is missing or ambiguous")
        columns[table] = fields
    seen_rows = 0
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^INSERT INTO `([^`]+)`(.*)$", line)
        if match is None or match.group(1) not in requested:
            continue
        table, suffix = match.groups()
        if not suffix.startswith(" VALUES "):
            raise AdmissionError("selected seed INSERT column list or syntax is unsupported")
        values = _row(suffix[len(" VALUES "):])
        if len(values) != len(columns[table]):
            raise AdmissionError("selected seed row width differs from its CREATE declaration", "invalid")
        indices = {field: index for index, field in enumerate(columns[table])}
        records[table].append({"line": number, "fields": {field: values[indices[field]] for field in requested[table]}})
        seen_rows += 1
        if seen_rows > 10000:
            raise AdmissionError("selected seed row envelope exceeded", "inconclusive")
    # Detect unsupported multiline/custom statements targeting selected tables;
    # do not silently treat their absence from the admitted parser as empty data.
    for match in re.finditer(r"^\s*INSERT\s+(?:IGNORE\s+)?INTO\s+`?([a-zA-Z_][a-zA-Z_0-9]*)`?", text, re.M | re.I):
        if match.group(1) in requested:
            start = text.rfind("\n", 0, match.end()) + 1
            if not text[start:].startswith("INSERT INTO `" + match.group(1) + "` VALUES "):
                raise AdmissionError("selected seed statement is outside the single-line literal grammar")
    for match in re.finditer(r"^\s*(?:UPDATE|DELETE\s+FROM|REPLACE\s+INTO|TRUNCATE(?:\s+TABLE)?)\s+`?([a-zA-Z_][a-zA-Z_0-9]*)`?", text, re.M | re.I):
        if match.group(1) in requested:
            raise AdmissionError("selected seed has an additional data mutation, not a literal INSERT snapshot")
    return {"tables": records, "projected_columns": {table: list(fields) for table, fields in requested.items()},
            "source_rows": seen_rows, "sql_executed": False,
            "scope": "explicit projection of a bundled seed snapshot; not a live database or current deployment state"}
