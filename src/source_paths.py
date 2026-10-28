"""Bounded syntactic caller-to-enforce discovery; not a dynamic call-graph proof.

Direct same-file names and self.method candidates are retained, including
ambiguous definitions. No target application or database operation is run.
"""
import ast
from collections import deque

from native_casbin import AdmissionError, MAX_TEXT_BYTES


def discover_authorization_paths(source):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("call-path source exceeds byte envelope", "inconclusive")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("call-path source does not parse", "invalid") from error
    definitions = []

    def collect(body, prefix="", class_name=None, conditional=False):
        for node in body:
            if isinstance(node, ast.ClassDef):
                collect(node.body, prefix + node.name + ".", prefix + node.name, conditional)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                definitions.append({"selector": prefix + node.name, "node": node, "class": class_name,
                                    "conditional": conditional})
                collect(node.body, prefix + node.name + ".", class_name, conditional)
            else:
                children = list(ast.iter_child_nodes(node))
                if children:
                    collect(children, prefix, class_name, True)
    collect(tree.body)
    if len(definitions) > 256:
        raise AdmissionError("source definition envelope exceeded", "inconclusive")
    indices = {}
    for index, row in enumerate(definitions):
        indices.setdefault(row["selector"], []).append(index)
    edges, sinks, sink_protocols, unresolved = [], {}, {}, []
    parents = {id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for index, row in enumerate(definitions):
        pending = list(row["node"].body)
        local_bindings = {p.arg for p in row["node"].args.posonlyargs + row["node"].args.args + row["node"].args.kwonlyargs}
        for parameter in (row["node"].args.vararg, row["node"].args.kwarg):
            if parameter is not None:
                local_bindings.add(parameter.arg)
        # Shadowed free-function names are not resolved as global functions.
        bindings_pending = list(row["node"].body)
        while bindings_pending:
            statement = bindings_pending.pop()
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                local_bindings.add(statement.name)
                continue
            if isinstance(statement, ast.Lambda):
                continue
            if isinstance(statement, ast.Name) and isinstance(statement.ctx, ast.Store):
                local_bindings.add(statement.id)
            bindings_pending.extend(ast.iter_child_nodes(statement))
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                continue
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "enforce":
                    sinks.setdefault(index, []).append(node.lineno)
                    parent = parents.get(id(node))
                    sink_protocols.setdefault(index, []).append({"line": node.lineno,
                        "callee_syntax": ast.unparse(node.func),
                        "directly_awaited": isinstance(parent, ast.Await) and parent.value is node,
                        "native_return_protocol_verified": False})
                else:
                    target, dynamic = None, False
                    if isinstance(node.func, ast.Name):
                        if node.func.id in local_bindings:
                            unresolved.append({"function": row["selector"], "line": node.lineno,
                                               "reason": "local/dynamic callee, not a resolved module binding"})
                        else:
                            target = node.func.id
                    elif (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                          and node.func.value.id == "self" and row["class"]):
                        target, dynamic = row["class"] + "." + node.func.attr, True
                    if target in indices:
                        for dest in indices[target]:
                            edges.append({"caller": index, "callee": dest, "line": node.lineno,
                                          "resolution": "syntactic self candidate" if dynamic else "same-file free-name candidate",
                                          "ambiguous": len(indices[target]) > 1 or definitions[dest]["conditional"],
                                          "runtime_binding_verified": False})
            pending.extend(ast.iter_child_nodes(node))
    reverse = {}
    for edge in edges:
        reverse.setdefault(edge["callee"], []).append(edge)
    paths, queue = {}, deque()
    for index in sorted(sinks):
        paths[index] = []
        queue.append(index)
    while queue:
        callee = queue.popleft()
        for edge in reverse.get(callee, []):
            if edge["caller"] not in paths:
                paths[edge["caller"]] = [edge] + paths[callee]
                queue.append(edge["caller"])
    records = []
    for index, path in sorted(paths.items()):
        row = definitions[index]
        records.append({"function": row["selector"], "line": row["node"].lineno,
                        "end_line": row["node"].end_lineno, "conditional_definition": row["conditional"],
                        "direct_sink_lines": sorted(sinks.get(index, [])),
                        "direct_sink_protocols": sorted(sink_protocols.get(index, []), key=lambda item: item["line"]),
                        "candidate_path": [{"caller": definitions[e["caller"]]["selector"], "callee": definitions[e["callee"]]["selector"],
                                            "line": e["line"], "ambiguous": e["ambiguous"], "runtime_binding_verified": False} for e in path],
                        "source_interface_verified": False})
    return {"candidate_functions": records, "total_definitions": len(definitions),
            "direct_enforce_functions": len(sinks), "indirect_candidate_functions": len(paths) - len(sinks),
            "unresolved_local_calls": unresolved,
            "scope": "same-file syntactic path discovery, including indirect callers; not complete dynamic dispatch, import or data-flow analysis",
            "source_module_executed": False, "whole_application_verified": False}
