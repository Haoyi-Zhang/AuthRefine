"""Admitted decoded-claim -> role-edge -> authorization boundary.

Only reviewed AST slices and typed, owned decoded dictionaries are interpreted.
JWT cryptography, issuers, HTTP services and application modules are not run.
The reference claim contract is explicit and separate from native decisions.
"""
import ast
from copy import deepcopy
import itertools

from checker import verify_reachable
from native_casbin import AdmissionError, MAX_TEXT_BYTES, MAX_NATIVE_WORK, admit_configuration, _engine, _check_role_depth
from native_runtime import engine_identity
from public_inputs import translate
from source_bindings import require_import_bindings


def _tree(source):
    if not isinstance(source, bytes) or len(source) > MAX_TEXT_BYTES:
        raise AdmissionError("claim source exceeds byte envelope", "inconclusive")
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError("claim source does not parse", "invalid") from error


def _body(fn):
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "_logger" and node.func.attr == "debug"):
            if node.keywords or any(not (isinstance(arg, ast.Constant) or isinstance(arg, ast.Name) and arg.id in ("obj", "act")
                or isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id == "self" and arg.attr == "username") for arg in node.args):
                raise AdmissionError("logging argument contains an unreviewed computation")
    return [n for n in fn.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and type(n.value.value) is str)
            and not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                and isinstance(n.value.func, ast.Attribute) and isinstance(n.value.func.value, ast.Name)
                and n.value.func.value.id == "_logger" and n.value.func.attr == "debug")]


def _shape(fn, expected):
    return [ast.dump(n, include_attributes=False) for n in _body(fn)] == [ast.dump(n, include_attributes=False) for n in ast.parse(expected).body]


def extract_claim_boundary(user_source, enum_source):
    require_import_bindings(user_source, {"TokenFields": ("moderate_api.authz.enums", 0, "TokenFields"),
        "dataclasses": ("dataclasses", 0, None), "HTTPException": ("fastapi", 0, "HTTPException"), "status": ("fastapi", 0, "status")})
    require_import_bindings(enum_source, {"enum": ("enum", 0, None)})
    enum_tree = _tree(enum_source)
    from relational_policy import _one_class
    _one_class(enum_tree, "TokenFields")
    classes = [n for n in enum_tree.body if isinstance(n, ast.ClassDef) and n.name == "TokenFields"]
    if len(classes) != 1 or classes[0].decorator_list or [ast.unparse(n) for n in classes[0].bases] != ["enum.Enum"]:
        raise AdmissionError("claim field enumeration is not the admitted direct enum")
    fields = {}
    for node in classes[0].body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str:
            continue
        if (not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name)
                or not isinstance(node.value, ast.Constant) or type(node.value.value) is not str or node.targets[0].id in fields):
            raise AdmissionError("claim enum has a dynamic or duplicate field")
        fields[node.targets[0].id] = node.value.value
    if set(fields) != {"REALM_ACCESS", "RESOURCE_ACCESS", "ROLES", "PREFERRED_USERNAME"} or len(set(fields.values())) != 4:
        raise AdmissionError("claim enum fields are missing or aliased")
    user = _one_class(_tree(user_source), "User")
    if user.bases or [ast.unparse(node) for node in user.decorator_list] != ["dataclasses.dataclass"]:
        raise AdmissionError("claim User needs the admitted direct dataclass declaration")
    methods = {}
    for name in ("username", "roles", "_extend_enforcer", "is_admin", "enforce_raise"):
        found = [n for n in user.body if isinstance(n, ast.FunctionDef) and n.name == name]
        if len(found) != 1:
            raise AdmissionError("claim consumer method is absent or ambiguous: " + name)
        def writes(node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return int(node.name == name)
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id == name:
                return 1
            return sum(writes(child) for child in ast.iter_child_nodes(node))
        if sum(writes(node) for node in user.body) != 1:
            raise AdmissionError("claim consumer method is rebound in its class: " + name)
        methods[name] = found[0]
        a = found[0].args
        parameters = ["self", "obj", "act", "admin_bypass"] if name == "enforce_raise" else ["self", "enforcer"] if name == "_extend_enforcer" else ["self"]
        expected_defaults = [ast.dump(ast.Constant(value=True), include_attributes=False)] if name == "enforce_raise" else []
        decorators = [ast.unparse(d) for d in found[0].decorator_list]
        if (a.posonlyargs or a.kwonlyargs or a.vararg or a.kwarg or [p.arg for p in a.args] != parameters
                or [ast.dump(n, include_attributes=False) for n in a.defaults] != expected_defaults
                or decorators != (["property"] if name in ("username", "roles", "is_admin") else [])):
            raise AdmissionError("claim consumer signature/decorator is outside the admitted fragment")
    if not _shape(methods["username"], "return self.token_decoded[TokenFields.PREFERRED_USERNAME.value]"):
        raise AdmissionError("claim subject binding changed")
    # The separator is source data, so an owned changed separator can be
    # compared against the unchanged client-role contract rather than rejected.
    roles = methods["roles"]
    joins = [n for n in ast.walk(roles) if isinstance(n, ast.JoinedStr)]
    if len(joins) != 1 or len(joins[0].values) != 3 or not isinstance(joins[0].values[1], ast.Constant):
        raise AdmissionError("client-role projection needs one literal separator")
    separator = joins[0].values[1].value
    if type(separator) is not str or separator not in (":", "-", "/"):
        raise AdmissionError("client-role separator is outside the admitted fragment")
    expected = '''roles = self.token_decoded.get(TokenFields.REALM_ACCESS.value, {}).get(TokenFields.ROLES.value, [])
resource_roles = self.token_decoded.get(TokenFields.RESOURCE_ACCESS.value, {})
for key, val in resource_roles.items():
    roles.extend([f"{key}SEP{r}" for r in val.get(TokenFields.ROLES.value, [])])
return roles'''.replace("SEP", separator)
    if not _shape(roles, expected):
        raise AdmissionError("decoded-role producer is outside the admitted source projection")
    expected_methods = {
        "_extend_enforcer": "for role in self.roles:\n enforcer.add_role_for_user(self.username, role)\nreturn enforcer",
        "is_admin": "return self.enforcer.has_role_for_user(self.username, self.settings.role_admin)",
        "enforce_raise": "if admin_bypass and self.is_admin:\n _logger.debug(\"Admin '%s' is allowed to perform any action\", self.username)\n return\nif not self.enforcer.enforce(self.username, obj, act):\n raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)"}
    for name, expected in expected_methods.items():
        if not _shape(methods[name], expected):
            raise AdmissionError("claim edge/consumer data flow changed: " + name)
    return {"field_bindings": fields, "source_client_separator": separator, "realm_roles_list_is_aliased": True,
            "alias_condition": "an existing realm_access.roles list is aliased; a missing list uses a fresh default",
            "method_lines": {name: [method.lineno, method.end_lineno] for name, method in methods.items()},
            "source_module_executed": False, "issuer_or_jwt_verification_verified": False,
            "primitive_contracts": ["debug logging is observational only", "the supplied engine/settings represent the selected User instance"],
            "scope": "selected User properties and role-enforcement methods under supplied decoded-claim/settings contracts"}


def _typed_claims(claims):
    if not isinstance(claims, dict) or set(claims) - {"preferred_username", "realm_access", "resource_access"}:
        raise AdmissionError("owned decoded claims need the explicit identity/role fields", "invalid")
    subject = claims.get("preferred_username")
    if not isinstance(subject, str) or not subject or len(subject) > 128:
        raise AdmissionError("decoded subject is not a bounded nonempty string", "invalid")
    realm = claims.get("realm_access", {})
    resources = claims.get("resource_access", {})
    if not isinstance(realm, dict) or set(realm) - {"roles"} or not isinstance(resources, dict) or len(resources) > 8:
        raise AdmissionError("decoded realm/client structures are outside the typed contract", "invalid")
    lists = [realm.get("roles", [])]
    for client, value in resources.items():
        if not isinstance(client, str) or not client or len(client) > 64 or not isinstance(value, dict) or set(value) - {"roles"}:
            raise AdmissionError("decoded client roles are outside the typed contract", "invalid")
        lists.append(value.get("roles", []))
    if any(not isinstance(items, list) or len(items) > 16 or any(type(role) is not str or not role or len(role) > 64 for role in items) for items in lists):
        raise AdmissionError("decoded roles need bounded string lists", "invalid")
    from language import named
    strings = [subject, *resources, *(role for items in lists for role in items)]
    if any(not named(value) or value == "unlisted" or any(c in value for c in ',"[]()') for value in strings):
        raise AdmissionError("claim identity cannot be represented losslessly in the admitted policy domain")


def project_claims(descriptor, claims):
    _typed_claims(claims)
    # Only canonical input names are currently admitted; source field changes
    # are preserved as an unsupported mapping, not silently canonicalized.
    canonical = {"REALM_ACCESS": "realm_access", "RESOURCE_ACCESS": "resource_access", "ROLES": "roles", "PREFERRED_USERNAME": "preferred_username"}
    if descriptor["field_bindings"] != canonical:
        raise AdmissionError("source token-field identity differs from the supplied decoded-claim contract")
    roles = claims.get("realm_access", {}).get("roles", [])
    for client, value in claims.get("resource_access", {}).items():
        roles.extend([client + descriptor["source_client_separator"] + role for role in value.get("roles", [])])
    return list(roles)


def reference_roles(claims):
    _typed_claims(claims)
    return [*claims.get("realm_access", {}).get("roles", []),
            *(client + ":" + role for client, value in claims.get("resource_access", {}).items() for role in value.get("roles", []))]


def compare_claim_boundary(user_source, enum_source, model_text, policy_text, claims, admin_role, admin_bypass, *, include_models=False):
    if type(include_models) is not bool:
        raise AdmissionError("model export flag must be Boolean", "invalid")
    descriptor = extract_claim_boundary(user_source, enum_source)
    if type(admin_bypass) is not bool or type(admin_role) is not str or not admin_role:
        raise AdmissionError("admin bypass/settings need explicit typed input values", "invalid")
    # The caller supplies a decoded record. Keep the original intact; preserve
    # source aliasing only in the owned interpretation copy.
    interpreted = deepcopy(claims)
    source_roles = project_claims(descriptor, interpreted)
    expected_roles = reference_roles(claims)
    config = admit_configuration(model_text, policy_text)
    if config.family != "rbac_with_deny":
        raise AdmissionError("claim boundary requires the admitted equality/deny-overrides schema")
    subject = claims["preferred_username"]
    reference_rows = config.rows + [["g", subject, role] for role in dict.fromkeys(expected_roles)]
    _check_role_depth(config.family, reference_rows)
    _check_role_depth(config.family, config.rows + [["g", subject, role] for role in dict.fromkeys(source_roles)])
    model = translate(config.family, reference_rows)
    # This source method uses a direct role check for its explicit admin branch,
    # not an inferred implicit hierarchy or a universal privileged username.
    reference_direct = {row[2] for row in reference_rows if row[0] == "g" and row[1] == subject}
    engine = _engine(config)
    for role in dict.fromkeys(source_roles):
        engine.add_role_for_user(subject, role)
    alphabet = [[subject, resource, action] for resource, action in itertools.product(model["resources"], model["actions"])]
    if len(alphabet) * max(1, len(config.rows) + len(source_roles)) > MAX_NATIVE_WORK:
        raise AdmissionError("claim consumer work envelope exceeded", "inconclusive")
    # Restrict this machine to the supplied principal. Normalization also checks
    # that every rule/member name still belongs to its declared global domains.
    model["principals"] = [subject]
    model["members"] = [edge for edge in model["members"] if edge[0] == subject]
    # This admitted deny-overrides translation has role/resource/action guards;
    # retain role identities, while checking only this supplied principal.
    if admin_bypass and admin_role in reference_direct:
        model["rules"].insert(0, {"decision": "allow", "guard": [{"field": "principal", "name": subject, "negated": False}], "updates": []})
    from language import normalize
    model = normalize(model)
    cells, native_calls, admin_checks = [], 0, 0
    for request in alphabet:
        direct_admin = False
        if admin_bypass:
            direct_admin = engine.has_role_for_user(subject, admin_role)
            admin_checks += 1
            if type(direct_admin) is not bool:
                raise AdmissionError("native direct role result is not Boolean", "native_error")
        if direct_admin:
            allowed = True
        else:
            allowed = engine.enforce(*request)
            native_calls += 1
        if type(allowed) is not bool:
            raise AdmissionError("native claim consumer is not Boolean", "native_error")
        cells.append(["allow" if allowed else "deny", 0])
    machine = {"state_names": [], "alphabet": alphabet, "observations": [0], "initial": 0, "transitions": [cells]}
    comparison = verify_reachable(model, machine)
    result = {"status": comparison["status"], "accepted": comparison["accepted"], "comparison": comparison,
            "source_descriptor": descriptor, "source_roles": source_roles, "reference_roles": expected_roles,
            "owned_decoded_input_changed_by_source_projection": interpreted != claims,
            "native_runtime": engine_identity(), "native_enforce_calls": native_calls,
            "native_direct_admin_checks": admin_checks, "wrapper_request_cells": len(alphabet),
            "scope": "source-selected decoded-claim/role-edge/consumer boundary on supplied finite identities and static policy",
            "expected_decisions_from": "independent realm/client claim contract and converted source static policy; never native output",
            "whole_application_verified": False, "credential_issuer_verified": False}
    if include_models:
        result.update(policy=model, machine=machine)
    return result
