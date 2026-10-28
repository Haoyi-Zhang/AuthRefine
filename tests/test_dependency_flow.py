from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from dependency_flow import AuthInput, FlowInterpreter, extract_dependency, extract_function
from native_casbin import AdmissionError, _engine, admit_configuration, _schema

API = b'''
def _check_with_casbin(role, resource, action):
    try:
        from ..auth.rbac import check_permission
        return check_permission(role, resource, action)
    except Exception as error:
        logger.debug(f"Backend not available: {error}")
        return None

def require_permission(permission):
    async def check(request, api_key=Security(api_key_header)):
        config = await get_current_auth(request, api_key)
        if isinstance(config, SessionAuth):
            segments = request.url.path.strip("/").split("/")
            resource = segments[2] if len(segments) > 2 else "unknown"
            allowed = _check_with_casbin(config.role, resource, permission)
            if allowed is not None:
                if not allowed:
                    raise HTTPException(status_code=403, detail="Policy denied the request")
                return config
        if permission not in config.permissions:
            raise HTTPException(status_code=403, detail="Permission absent")
        return config
    return check

def require_scope(scope):
    async def check(request, api_key=Security(api_key_header)):
        config = await get_current_auth(request, api_key)
        if "all" not in config.scopes and scope not in config.scopes:
            raise HTTPException(status_code=403, detail="Scope absent")
        return config
    return check

def require_role(role):
    levels = {"admin": 1, "viewer": 0}
    async def check(request, api_key=Security(api_key_header)):
        config = await get_current_auth(request, api_key)
        if not isinstance(config, SessionAuth):
            raise HTTPException(status_code=403, detail="Session required")
        if levels.get(config.role, 0) < levels.get(role, 0):
            raise HTTPException(status_code=403, detail="Role too low")
        return config
    return check
'''
BACKEND = b'''
def check_permission(role, resource, action):
    instance = get_enforcer()
    return instance.enforce(role, resource, action)
'''


def engine():
    model = "\n".join("[" + section + "]\n" + "\n".join(k + " = " + v for k, v in values.items())
                      for section, values in _schema("rbac").items())
    return _engine(admit_configuration(model, "p, viewer, documents, read\ng, admin, viewer"))


class DependencyFlowTests(unittest.TestCase):
    def run_flow(self, auth, factory="require_permission", argument="read", path="/api/v1/documents", source=API, available=True, native=None):
        return FlowInterpreter(auth, path, engine() if native is None else native,
                               extract_function(source, "_check_with_casbin", "api.auth"),
                               extract_function(BACKEND, "check_permission", "auth.rbac"), available).evaluate(
                                   extract_dependency(source, factory), argument)

    def test_source_call_chain_reaches_native_engine(self):
        result = self.run_flow(AuthInput("session", "viewer", ("read",), ("all",)))
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["native_calls"], 1)
        self.assertEqual(result["trace"][-1]["native_request"], ["viewer", "documents", "read"])

    def test_real_native_denial_is_not_replaced_with_fallback(self):
        result = self.run_flow(AuthInput("session", "viewer", ("write",), ("all",)), argument="write")
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["http_status"], 403)

    def test_api_key_permissions_skip_native_session_checks(self):
        result = self.run_flow(AuthInput("api_key", "unused", ("write",), ("all",)), argument="write")
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["native_calls"], 0)

    def test_scope_and_role_factories_are_separate_source_dependencies(self):
        session = AuthInput("session", "viewer", ("read",), ("documents",))
        self.assertEqual(self.run_flow(session, "require_scope", "documents")["decision"], "allow")
        self.assertEqual(self.run_flow(session, "require_scope", "accounts")["decision"], "deny")
        self.assertEqual(self.run_flow(session, "require_role", "admin")["decision"], "deny")
        admin = AuthInput("session", "admin", ("read",), ("all",))
        self.assertEqual(self.run_flow(admin, "require_role", "viewer")["decision"], "allow")
        self.assertEqual(self.run_flow(AuthInput("api_key", "admin", ("read",), ("all",)), "require_role", "viewer")["decision"], "deny")

    def test_explicit_owned_outage_is_distinct_from_a_native_execution_error(self):
        auth = AuthInput("session", "viewer", ("write",), ("all",))
        result = self.run_flow(auth, argument="write", available=False)
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["native_calls"], 0)
        class BrokenEngine:
            def enforce(self, *args):
                raise ValueError("owned failing native control")
        with self.assertRaises(AdmissionError) as caught:
            self.run_flow(auth, argument="write", native=BrokenEngine())
        self.assertEqual(caught.exception.status, "native_error")

    def test_dead_unsupported_calls_are_not_admitted(self):
        altered = API.replace(b'        config = await get_current_auth(request, api_key)',
                              b'        if False:\n            unreviewed_call()\n        config = await get_current_auth(request, api_key)', 1)
        with self.assertRaises(AdmissionError):
            extract_dependency(altered, "require_permission")

    def test_source_modules_and_dependency_defaults_are_never_executed(self):
        source = b'raise RuntimeError("never import this module")\n' + API
        self.assertEqual(self.run_flow(AuthInput("session", "viewer", (), ("all",)), source=source)["decision"], "allow")
        with self.assertRaises(AdmissionError):
            extract_dependency(API.replace(b'Security(api_key_header)', b'unknown_default()'), "require_permission")

    def test_rebinding_typed_primitives_is_rejected(self):
        source = API.replace(b'        config = await get_current_auth(request, api_key)',
                             b'        get_current_auth = None\n        config = await get_current_auth(request, api_key)', 1)
        with self.assertRaises(AdmissionError):
            self.run_flow(AuthInput("session", "viewer", (), ("all",)), source=source)

    def test_changed_resource_index_changes_the_actual_native_request(self):
        source = API.replace(b'segments[2]', b'segments[1]')
        result = self.run_flow(AuthInput("session", "viewer", ("read",), ("all",)), source=source)
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["trace"][-1]["native_request"], ["viewer", "v1", "read"])


if __name__ == "__main__":
    unittest.main()
