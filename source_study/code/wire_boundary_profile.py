"""Source-bound normal-record wire functions; application modules never execute."""
import ast
from importlib import metadata
from pathlib import Path
from effect_slice import DataRecord, EffectInterpreter
from native_casbin import AdmissionError
from persistent_store import shape, strip_docstring
from record_projection import extract_record_projection, project_record
from source_bindings import require_import_bindings, require_static_class_members, require_static_definitions
from boundary_repairs import repeated_string_values


SNAPSHOT = "453f98df141cd7cc4f9431eda88e1a1fc51a9be5"

PRODUCER = "interface-partition/interface_setup/server_methods.py"

SENDER = "interface-partition/grpc_request_handler/grpc_request_handler.py"

RECEIVER = "intermediate-vor-partition/request_message_handler/request_message_handler.py"

PB = "intermediate-vor-partition/request_pb2.py"

PROTOS = ("interface-partition/grpc_request_handler/proto/request.proto",
    "intermediate-vor-partition/grpc_request_handler/proto/request.proto")

FIELDS = ("issuer_id", "issuer_characteristics", "timestamp", "description", "impact",
    "parameters", "modification", "priority", "request_id")

def function(source, name, class_name=None):
    tree = ast.parse(source)
    require_static_definitions(tree, [class_name or name])
    scope = tree.body
    if class_name:
        cls = next(node for node in scope if isinstance(node, ast.ClassDef) and node.name == class_name)
        require_static_class_members(cls, [name])
        scope = cls.body
    return next(node for node in scope if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name)

def keyword_call(node, wanted):
    matches = [call for call in ast.walk(node) if isinstance(call, ast.Call) and ast.unparse(call.func) == wanted]
    if len(matches) != 1 or matches[0].args or len(matches[0].keywords) != len(FIELDS) or {kw.arg for kw in matches[0].keywords} != set(FIELDS):
        raise AdmissionError("wire constructor has no unique complete keyword-field projection")
    return {kw.arg: shape(kw.value) for kw in matches[0].keywords}

def bind_sources(bundle, *, with_projection=False):
    if bundle.archive.comment.decode("ascii") != SNAPSHOT:
        raise ValueError("the reserved development snapshot changed")
    producer_source = bundle.read(PRODUCER)
    barrier = ast.parse('_logger.info(f"Request: {request_dict}")').body[0]
    projection = extract_record_projection(producer_source, "submit_request", "request_dict", barrier)
    sender_source = bundle.read(SENDER)
    require_import_bindings(sender_source, {"request_pb2": ("request_pb2", 0, None)})
    sender = function(sender_source, "send", "GrpcRequestSender")
    expected_sender = ast.parse('''request_pb2.SubmitRequest(issuer_id=request["issuer_id"], issuer_characteristics=request["issuer_characteristics"], timestamp=request["timestamp"], description=request["description"], impact=request["impact"], parameters=request["parameters"], modification=request["modification"], priority=int(request["prio"]), request_id=request["request_id"])''').body[0]
    if keyword_call(sender, "request_pb2.SubmitRequest") != keyword_call(expected_sender, "request_pb2.SubmitRequest"):
        raise AdmissionError("sender source field order/names/transforms changed")
    receiver_source = bundle.read(RECEIVER)
    require_import_bindings(receiver_source, {"Request": ("request", 0, "Request")})
    receiver = function(receiver_source, "handle_grpc_submit", "RequestMessageHandler")
    expected_receiver = ast.parse('''Request(issuer_id=req_pb.issuer_id, issuer_characteristics=issuer_characteristics, request_id=getattr(req_pb, "request_id", ""), timestamp=req_pb.timestamp, description=description, impact=req_pb.impact, parameters=str(req_pb.parameters), modification=str(req_pb.modification), priority=int(req_pb.priority))''').body[0]
    if keyword_call(receiver, "Request") != keyword_call(expected_receiver, "Request"):
        raise AdmissionError("receiver source DTO field projection changed")
    normalizer = function(receiver_source, "_as_list_str", "RequestMessageHandler")
    normalizer_body = ast.parse('''if items is None:
 return []
return [str(x) for x in items]
''').body
    receiver_body = strip_docstring(receiver.body)
    aliases = ast.parse('''issuer_characteristics = self._as_list_str(req_pb.issuer_characteristics)
description = self._as_list_str(req_pb.description)
''').body
    if ([shape(s) for s in strip_docstring(normalizer.body)] != [shape(s) for s in normalizer_body]
            or [shape(s) for s in receiver_body[:2]] != [shape(s) for s in aliases]):
        raise AdmissionError("receiver's repeated-field normalization changed")
    proto = bundle.read(PROTOS[0])
    if proto.rstrip(b"\r\n") != bundle.read(PROTOS[1]).rstrip(b"\r\n"):
        raise AdmissionError("sender and receiver declared schemas differ")
    # Both application partitions explicitly pin this dependency. No current
    # system protobuf or generated application module is imported as a shortcut.
    for path, encoding in (("interface-partition/requirements.txt", "utf-16"),
            ("intermediate-vor-partition/requirements.txt", "utf-8-sig")):
        if "protobuf==6.32.1" not in bundle.read(path).decode(encoding).splitlines():
            raise AdmissionError("source-declared protobuf dependency changed")
    tree = ast.parse(bundle.read(PB))
    descriptors = [node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call)
        and ast.unparse(node.func) == "_descriptor_pool.Default().AddSerializedFile"
        and len(node.args) == 1 and not node.keywords and isinstance(node.args[0], ast.Constant)
        and type(node.args[0].value) is bytes]
    if len(descriptors) != 1 or len(descriptors[0]) > 4096:
        raise AdmissionError("generated descriptor is not one bounded literal")
    binding = {"producer": PRODUCER, "sender": SENDER, "receiver": RECEIVER,
        "protobuf_descriptor_source": PB, "schema_sources": list(PROTOS),
        "schema_bytes_equal_except_terminal_newline": True,
        "producer_projection": projection["descriptor"],
        "projection_kind": "actual selected producer AST block interpretation; sender/receiver constructor templates and schema bindings remain explicit; not full function execution",
        "given_preconditions": ["already authenticated and authorized ordinary request", "canonical string modification accepted by the source normalizer",
            "successful sender channel setup and reachability of its selected constructor are supplied, not executed",
            "the reviewed serializer and receiver bodies and matching schema, not arbitrary dispatch"],
        "full_source_execution_or_dispatch_proved": False}
    result = (descriptors[0], proto, binding)
    return (*result, projection) if with_projection else result

def message_type(descriptor, proto):
    import google.protobuf
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
    from google.protobuf.internal import api_implementation
    distribution = metadata.distribution("protobuf")
    if (distribution.version != "6.32.1" or google.protobuf.__version__ != "6.32.1"
            or Path(google.protobuf.__file__).resolve() != Path(distribution.locate_file("google/protobuf/__init__.py")).resolve()):
        raise AdmissionError("wire runtime is not the reviewed source-declared dependency")
    decoded = descriptor_pb2.FileDescriptorProto.FromString(descriptor)
    selected = [m for m in decoded.message_type if m.name == "SubmitRequest"]
    declared = [(name, i, 3 if name in ("issuer_characteristics", "description") else 1, 5 if name == "priority" else 9)
        for i, name in enumerate(FIELDS, 1)]
    if len(selected) != 1 or [(f.name, f.number, f.label, f.type) for f in selected[0].field] != declared or decoded.package != "request" or decoded.syntax != "proto3":
        raise AdmissionError("literal descriptor differs from the reviewed ordinary request schema")
    schema_lines = [f'  {"repeated " if label == 3 else ""}{"int32" if typ == 5 else "string"} {name} = {number};'
        for name, number, label, typ in declared]
    expected_proto = 'syntax = "proto3";\npackage request;\n\nmessage SubmitRequest {\n' + '\n'.join(schema_lines) + '''
}

message SubmitResponse {
  string ack = 1;
  string server_timestamp = 2;
}

service RequestService {
  rpc Submit(SubmitRequest) returns (SubmitResponse);
}'''
    if proto.decode().strip() != expected_proto:
        raise AdmissionError("wire descriptor does not match the reviewed .proto fields")
    pool = descriptor_pool.DescriptorPool()
    pool.AddSerializedFile(descriptor)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName("request.SubmitRequest")), {
        "distribution": "protobuf", "release": "6.32.1", "backend": api_implementation.Type(),
        "module": google.protobuf.__file__, "source_distribution_requirement_satisfied": True}

def wire_case(cls, chars, descriptions, priority, issuer, *, projection, owned_values_control=False, boundary_repair=False):
    if type(owned_values_control) is not bool or type(boundary_repair) is not bool or owned_values_control and boundary_repair:
        raise AdmissionError('choose one explicit wire candidate/control mode')
    given = {"issuer_id": issuer, "issuer_characteristics": list(chars), "description": list(descriptions),
        "timestamp": "2026-01-01T00:00:00Z", "impact": "owned-impact", "parameters": "owned-parameter",
        "modification": "12", "priority": priority, "request_id": "owned-request"}
    if not set(projection["required"]) <= set(given):
        raise AdmissionError("source producer block requires additional unavailable bindings")
    projected = project_record(projection, {key: given[key] for key in projection["required"]})
    request = projected["value"]
    fields = {name: request["prio" if name == "priority" else name] for name in FIELDS}
    fields["priority"] = int(fields["priority"])
    if owned_values_control:
        for name in ("issuer_characteristics", "description"):
            if type(fields[name]) is not dict:
                raise AdmissionError("values-list owned control requires source-produced plain dictionaries")
            fields[name] = list(fields[name].values())
    if boundary_repair:
        for name in ('issuer_characteristics','description'):
            fields[name]=repeated_string_values(fields[name],name)
    encoded = cls(**fields).SerializeToString()
    decoded = cls.FromString(encoded)
    actual = {name: list(getattr(decoded, name)) if name in ("issuer_characteristics", "description") else getattr(decoded, name) for name in FIELDS}
    # Reference values come from the given original inputs, not the source's
    # projected scalar fields. An incorrect source actor/resource must differ.
    expected = {**given, "issuer_characteristics": [v for v in chars if v], "description": [v for v in descriptions if v]}
    return {"supplied": {"issuer_characteristics": list(chars), "description": list(descriptions), "priority": priority, "issuer": issuer},
        "expected": expected, "actual": actual, "different_fields": [name for name in FIELDS if actual[name] != expected[name]],
        "protobuf_encoded_bytes": len(encoded), "owned_values_control": owned_values_control,
        "producer_source_ast_interpreted": True, "producer_field_mapping_hand_transcribed": False,
        "source_interpretation_steps": projected["source_interpretation_steps"]}
