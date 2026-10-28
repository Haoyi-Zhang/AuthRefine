import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from native_casbin import AdmissionError, _engine
from tenant_dependency import TenantPrincipal, extract_tenant_dependency, evaluate_tenant_dependency
from tenant_routes import SCHEMA, admit_tenant_routes


SOURCE = b'''
from fastapi import Depends, HTTPException
from dlw.auth.principal import require_principal
from dlw.services.audit import write_audit
def require_perm(obj: str, act: str):
    async def _dep(request, principal=Depends(require_principal), session=Depends(_session)):
        if principal.is_service or principal.role == "system_admin":
            return principal
        enforcer = request.app.state.casbin
        rtenant = principal.tenant_id
        if not enforcer.enforce(f"role:{principal.role}", principal.tenant_id, obj, act, rtenant):
            await write_audit(session, action="permission_denied", actor_user_id=principal.user_id or None)
            await session.commit()
            raise HTTPException(403, detail={"code": "RBAC_DENIED"})
        return principal
    return _dep
'''


class TenantDependencyTests(unittest.TestCase):
    def setUp(self):
        model = "\n".join("[" + section + "]\n" + "\n".join(k + " = " + v for k, v in fields.items())
                          for section, fields in SCHEMA.items())
        policy = "p, role:viewer, /tasks*, ^GET$, tenant_match"
        self.engine = _engine(admit_tenant_routes(model, policy))

    def evaluate(self, source=SOURCE, role="viewer", tenant=1, service=False, act="GET"):
        return evaluate_tenant_dependency(extract_tenant_dependency(source), self.engine,
                                          TenantPrincipal(11, tenant, role, service), "/tasks/11", act)

    def test_source_native_chain(self):
        result = self.evaluate()
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["native_calls"][0]["arguments"], ["role:viewer", 1, "/tasks/11", "GET", 1])

    def test_denial_records_not_executes_sinks(self):
        result = self.evaluate(act="POST")
        self.assertEqual(result["decision"], "deny")
        self.assertEqual([r["sink"] for r in result["audit_effects"]], ["write_audit", "session.commit"])
        self.assertFalse(result["audit_or_application_database_executed"])

    def test_service_and_admin_are_explicit_bypasses(self):
        for kw in ({"service": True}, {"role": "system_admin"}):
            result = self.evaluate(act="POST", **kw)
            self.assertEqual(result["decision"], "allow")
            self.assertFalse(result["native_calls"])

    def test_changed_argument_and_polarity_are_observed(self):
        changed = SOURCE.replace(b'rtenant = principal.tenant_id', b'rtenant = 999')
        self.assertEqual(self.evaluate(changed)["decision"], "deny")
        changed = SOURCE.replace(b'if not enforcer.enforce', b'if enforcer.enforce')
        self.assertEqual(self.evaluate(changed)["decision"], "deny")

    def test_unbound_receiver_cannot_pass(self):
        changed = SOURCE.replace(b'enforcer = request.app.state.casbin', b'enforcer = "not-an-engine"')
        with self.assertRaises(AdmissionError):
            self.evaluate(changed)

    def test_untrusted_module_is_not_imported(self):
        self.assertEqual(self.evaluate(b'raise RuntimeError("never run")\n' + SOURCE)["decision"], "allow")

    def test_wrong_provider_and_unknown_calls_rejected(self):
        for changed in (SOURCE.replace(b'Depends(require_principal)', b'Depends(unreviewed)'),
                        SOURCE.replace(b'await session.commit()', b'await run_attack()')):
            with self.assertRaises(AdmissionError):
                extract_tenant_dependency(changed)

    def test_bad_principal_type_rejected(self):
        with self.assertRaises(AdmissionError):
            self.evaluate(tenant=True)

    def test_fallthrough_is_not_success(self):
        changed = SOURCE.replace(b'        return principal\n    return _dep', b'        "no decision"\n    return _dep')
        with self.assertRaises(AdmissionError):
            self.evaluate(changed)


if __name__ == "__main__":
    unittest.main()
