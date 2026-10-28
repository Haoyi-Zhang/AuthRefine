from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from token_roles import extract_claim_boundary, project_claims, reference_roles, compare_claim_boundary

ENUM = b'''import enum
class TokenFields(enum.Enum):
 REALM_ACCESS = "realm_access"
 RESOURCE_ACCESS = "resource_access"
 ROLES = "roles"
 PREFERRED_USERNAME = "preferred_username"
'''
USER = b'''import dataclasses
from fastapi import HTTPException, status
from moderate_api.authz.enums import TokenFields
@dataclasses.dataclass
class User:
 @property
 def username(self):
  return self.token_decoded[TokenFields.PREFERRED_USERNAME.value]
 @property
 def roles(self):
  roles = self.token_decoded.get(TokenFields.REALM_ACCESS.value, {}).get(TokenFields.ROLES.value, [])
  resource_roles = self.token_decoded.get(TokenFields.RESOURCE_ACCESS.value, {})
  for key, val in resource_roles.items():
   roles.extend([f"{key}:{r}" for r in val.get(TokenFields.ROLES.value, [])])
  return roles
 def _extend_enforcer(self, enforcer):
  for role in self.roles:
   enforcer.add_role_for_user(self.username, role)
  return enforcer
 @property
 def is_admin(self):
  return self.enforcer.has_role_for_user(self.username, self.settings.role_admin)
 def enforce_raise(self, obj, act, admin_bypass=True):
  if admin_bypass and self.is_admin:
   _logger.debug("Admin '%s' is allowed to perform any action", self.username)
   return
  if not self.enforcer.enforce(self.username, obj, act):
   raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
'''
MODEL = (Path(__file__).resolve().parents[1] / "external_inputs/casbin/rbac_with_deny_model.conf").read_text(encoding="utf-8")
POLICY = "p, app:viewer, record, read, allow\np, app:viewer, record, write, deny\ng, app:admin, app:viewer"


def token(role="viewer"):
    return {"preferred_username": "alice", "realm_access": {"roles": []}, "resource_access": {"app": {"roles": [role]}}}


class TokenRoleTests(unittest.TestCase):
    def check(self, claims=None, source=USER, bypass=True):
        return compare_claim_boundary(source, ENUM, MODEL, POLICY, token() if claims is None else claims, "app:admin", bypass)

    def test_source_claim_mapping_and_native_consumer_agree(self):
        claims = token()
        before = deepcopy(claims)
        result = self.check(claims)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["native_enforce_calls"], 6)
        self.assertTrue(result["owned_decoded_input_changed_by_source_projection"])
        self.assertEqual(claims, before)
        self.assertFalse(result["whole_application_verified"])

    def test_admin_bypass_is_distinct_from_deny_overrides(self):
        bypass = self.check(token("admin"), bypass=True)
        denied_by_policy = self.check(token("admin"), bypass=False)
        self.assertTrue(bypass["accepted"])
        self.assertEqual(bypass["native_enforce_calls"], 0)
        self.assertTrue(denied_by_policy["accepted"])
        self.assertGreater(denied_by_policy["native_enforce_calls"], 0)

    def test_owned_separator_control_is_a_composed_mismatch(self):
        result = self.check(source=USER.replace(b'f"{key}:{r}"', b'f"{key}-{r}"'))
        self.assertFalse(result["accepted"])
        self.assertEqual(result["comparison"]["length"], 1)

    def test_missing_roles_is_an_admitted_empty_projection_not_a_pass_for_issuer(self):
        result = self.check({"preferred_username": "new-user"})
        self.assertTrue(result["accepted"])
        self.assertEqual(result["source_roles"], [])
        self.assertFalse(result["credential_issuer_verified"])

    def test_repeated_reads_preserve_the_actual_source_aliasing(self):
        descriptor = extract_claim_boundary(USER, ENUM)
        claims = token()
        expected = reference_roles(claims)
        first = project_claims(descriptor, claims)
        second = project_claims(descriptor, claims)
        self.assertEqual(first, expected)
        self.assertEqual(second, ["app:viewer", "app:viewer"])
        self.assertEqual(set(first), set(second))

    def test_invalid_claim_types_and_csv_collisions_are_not_guessed(self):
        for claims in ({"preferred_username": "alice", "realm_access": {"roles": "admin"}},
                       {"preferred_username": "alice", "resource_access": {"app": {"roles": [None]}}},
                       {"preferred_username": "unlisted"}, {"preferred_username": "a,b"}):
            with self.assertRaises(AdmissionError):
                self.check(claims)

    def test_changed_subject_or_native_argument_order_is_not_admitted(self):
        for changed in (USER.replace(b"TokenFields.PREFERRED_USERNAME.value]", b"TokenFields.ROLES.value]"),
                        USER.replace(b"self.username, obj, act", b"self.username, act, obj"),
                        USER + b'\n roles = other_property\n',
                        USER + b'\n if condition:\n  roles = other_property\n'):
            with self.assertRaises(AdmissionError):
                self.check(source=changed)

    def test_source_http_binding_and_logging_expressions_are_checked(self):
        for changed in (USER.replace(b"from fastapi import", b"from other import"),
                        USER.replace(b' self.username)\n   return', b' unknown())\n   return')):
            with self.assertRaises(AdmissionError):
                self.check(source=changed)
        with self.assertRaises(AdmissionError):
            compare_claim_boundary(USER, ENUM + b'\nTokenFields.ROLES = "other"\n', MODEL, POLICY, token(), "app:admin", True)

    def test_role_name_as_subject_is_not_assumed_disjoint(self):
        claims = {"preferred_username": "app:viewer", "realm_access": {"roles": []}}
        self.assertTrue(self.check(claims)["accepted"])

    def test_claim_cli_keeps_mismatch_and_source_scope(self):
        import contextlib
        import io
        import json
        import tempfile
        from native_pipeline import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (("user.py", USER), ("enums.py", ENUM), ("model.conf", MODEL.encode()), ("policy.csv", POLICY.encode())):
                (root / name).write_bytes(value)
            (root / "claims.json").write_text(json.dumps(token()), encoding="utf-8")
            args = ["claim-boundary", "--source", str(root / "user.py"), "--enum-source", str(root / "enums.py"),
                "--model", str(root / "model.conf"), "--policy", str(root / "policy.csv"), "--claims", str(root / "claims.json"), "--admin-role", "app:admin"]
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(args)
            self.assertEqual(code, 0)
            (root / "user.py").write_bytes(USER.replace(b'f"{key}:{r}"', b'f"{key}-{r}"'))
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(args)
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
