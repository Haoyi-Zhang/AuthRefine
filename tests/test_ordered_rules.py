from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from effect_slice import DataRecord, SliceFault
from native_casbin import AdmissionError
from ordered_rules import extract_ordered_rules, run_ordered_check

SOURCE = b'''from dataclasses import dataclass
from app.api.token_context import current_token_ctx
from app.core import casbin_enforcer as _casbin_mod
from fastapi.concurrency import run_in_threadpool
from app.repositories.group import GroupRepository
from app.repositories.tenant import UserTenantRepository

@dataclass(frozen=True)
class CheckContext:
 user_id: str
 tenant_id: str
 obj: str
 act: str
 platform_role: object
 db: object
 token_ctx: object

@dataclass(frozen=True)
class CheckRule:
 name: str
 objs: object
 acts: object
 needs_db: bool
 decision: str
 predicate: object
 def applies(self, ctx):
  if self.objs is not None and ctx.obj not in self.objs:
   return False
  if self.acts is not None and ctx.act not in self.acts:
   return False
  if self.needs_db and ctx.db is None:
   return False
  return True

class PermissionService:
 async def check(self, user_id, tenant_id, obj, act, platform_role=None, *, db=None):
  ctx = CheckContext(user_id, tenant_id, obj, act, platform_role, db, current_token_ctx.get())
  for rule in CHECK_RULES:
   if rule.applies(ctx) and await rule.predicate(ctx):
    return rule.decision == "allow"
  def _do():
   e = _casbin_mod.get_enforcer()
   with _casbin_mod.enforcer_lock():
    return bool(e.enforce(user_id, tenant_id, obj, act))
  return await run_in_threadpool(_do)
 async def require(self, user_id, tenant_id, obj, act, platform_role=None, *, db=None):
  if not await self.check(user_id, tenant_id, obj, act, platform_role=platform_role, db=db):
   raise PermissionError("denied")

async def gate(ctx):
 return ctx.token_ctx is not None and ctx.token_ctx.scope_mode == "restricted"
def is_platform_writer(role):
 return role in PLATFORM_WRITER_ROLES
async def _is_group_admin_of(db, user_id, group):
 return False
PLATFORM_WRITER_ROLES = ("staff",)
GROUP_ADMIN_HQ_ROLES = frozenset({"owner"})
CHECK_RULES = (CheckRule(name="gate", objs=None, acts=None, needs_db=False, decision="deny", predicate=gate),)
'''


def context(**changes):
    return {"user_id": "owned-user", "tenant_id": "owned-tenant", "obj": "normal", "act": "read",
        "platform_role": None, "token": None, "db_present": False, "group": None, "membership": None, **changes}


class OrderedRuleTests(unittest.TestCase):
    def test_selected_source_fallback_has_one_capture_and_one_native_call(self):
        calls = []
        result = run_ordered_check(extract_ordered_rules(SOURCE), context(), lambda *args: calls.append(args) or True)
        self.assertEqual(result["status"], "allow")
        self.assertEqual(result["token_reads"], 1)
        self.assertEqual(result["native_calls"], 1)
        self.assertEqual(calls, [("owned-user", "owned-tenant", "normal", "read")])
        self.assertEqual(result["effects"][-5:], ["serial_bridge", "engine_get", "serial_enter", "native_enforce", "serial_exit"])

    def test_gate_denies_before_native_and_owned_inversion_is_observable(self):
        ctx = context(token=DataRecord("token", {"scope_mode": "restricted"}))
        for source, expected in ((SOURCE, "deny"), (SOURCE.replace(b'decision="deny"', b'decision="allow"'), "allow")):
            result = run_ordered_check(extract_ordered_rules(source), ctx, lambda *args: self.fail("short circuit lost"))
            self.assertEqual(result["status"], expected)
            self.assertEqual(result["native_calls"], 0)

    def test_require_retains_denial_category_and_uses_same_single_check(self):
        result = run_ordered_check(extract_ordered_rules(SOURCE), context(), lambda *args: False, required=True)
        self.assertEqual(result["status"], "denied_by_require")
        self.assertEqual(result["source_function_calls"]["check"], 1)
        self.assertEqual(result["source_function_calls"]["require"], 1)
        self.assertEqual(result["token_reads"], 1)

    def test_rule_applicability_short_circuits_predicate_without_database(self):
        source = SOURCE.replace(b"needs_db=False", b"needs_db=True")
        result = run_ordered_check(extract_ordered_rules(source), context(
            token=DataRecord("token", {"scope_mode": "restricted"})), lambda *args: True)
        self.assertEqual(result["status"], "allow")
        self.assertNotIn("predicate:gate", result["effects"])
        self.assertEqual(result["native_calls"], 1)

    def test_native_fault_remains_fault_and_serial_exit_is_observed(self):
        def fail(*args):
            raise SliceFault("OwnedStoreFailure", "injected own test fault")
        result = run_ordered_check(extract_ordered_rules(SOURCE), context(), fail)
        self.assertEqual(result["status"], "error:OwnedStoreFailure")
        self.assertEqual(result["effects"][-1], "serial_exit")

    def test_rebound_registry_or_import_never_becomes_current_success(self):
        for suffix in (b"\nCHECK_RULES = ()\n", b"\nGroupRepository = other\n", b"\nPermissionError = other\n"):
            with self.assertRaises(AdmissionError):
                extract_ordered_rules(SOURCE + suffix)

    def test_dynamic_predicate_or_nonliteral_scope_requires_other_translation(self):
        for source in (SOURCE.replace(b"predicate=gate", b"predicate=factory()"),
                       SOURCE.replace(b"objs=None", b"objs=scopes()"),
                       SOURCE.replace(b'decision="deny"', b'decision="maybe"')):
            with self.assertRaises(AdmissionError):
                extract_ordered_rules(source)

    def test_source_modules_are_not_executed_and_records_are_explicit(self):
        program = extract_ordered_rules(b"raise RuntimeError('never run')\n" + SOURCE)
        result = run_ordered_check(program, context(), lambda *args: True)
        self.assertEqual(result["status"], "allow")
        self.assertFalse(program[-1]["dataclass_constructors_and_decorators_executed"])
        with self.assertRaises(AdmissionError):
            run_ordered_check(program, {}, lambda *args: True)


if __name__ == "__main__":
    unittest.main()
