from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from async_snapshot import SnapshotInterpreter, extract_snapshot_program
from native_casbin import AdmissionError
from snapshot_policy import MATCHER, NativeSnapshot, compare_snapshot, validate_snapshot

PROGRAM = b'''from app.models.permission import CasbinRule, ResourceOwner
class PermissionService:
 @property
 def enforcer(self):
  if self._enforcer is None:
   raise RuntimeError("not initialized")
  return self._enforcer
 async def _ensure_initialized(self):
  if not self._initialized:
   await self.init()
 async def _load_policy_from_db(self):
  rules = await CasbinRule.all()
  for rule in rules:
   values = [rule.v0, rule.v1, rule.v2, rule.v3, rule.v4, rule.v5]
   values = [v for v in values if v is not None]
   if rule.ptype.startswith("p"):
    self._enforcer.add_policy(*values)
   elif rule.ptype == "g":
    self._enforcer.add_grouping_policy(*values)
   elif rule.ptype == "g2":
    self._enforcer.add_named_grouping_policy("g2", *values)
 async def get_global_roles(self, user_id: int):
  await self._ensure_initialized()
  rules = await CasbinRule.filter(ptype="g2", v0=str(user_id)).all()
  return [rule.v1 for rule in rules if rule.v1]
 async def is_system_admin(self, user_id: int):
  await self._ensure_initialized()
  roles = await self.get_global_roles(user_id)
  return "system_admin" in roles
 async def is_resource_owner(self, user_id: int, resource_type: str, resource_id: int):
  await self._ensure_initialized()
  return await ResourceOwner.exists(user_id=user_id, resource_type=resource_type, resource_id=resource_id)
 async def enforce(self, user_id: int, domain: str, resource: str, action: str):
  await self._ensure_initialized()
  if await self.is_system_admin(user_id):
   return True
  return self.enforcer.enforce(str(user_id), domain, resource, action)
 async def check_permission(self, user_id: int, resource_type: str, resource_id: int, action: str):
  await self._ensure_initialized()
  if await self.is_system_admin(user_id):
   return True
  if await self.is_resource_owner(user_id, resource_type, resource_id):
   return True
  domain = f"{resource_type}_{resource_id}"
  return self.enforcer.enforce(str(user_id), domain, resource_type, action)
'''
MODEL = '''[request_definition]
r = sub, dom, obj, act
[policy_definition]
p = sub, dom, obj, act
[role_definition]
g = _, _, _
g2 = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = ''' + MATCHER


def row(kind, *values):
    return {"ptype": kind, **{"v" + str(i): values[i] if i < len(values) else None for i in range(6)}}


RULES = [row("p", "reader", "board_7", "board", "read"), row("g", "1", "reader", "board_7"),
         row("g2", "2", "system_admin"), row("g2", "3", "admin")]
OWNERS = [{"user_id": 4, "resource_type": "board", "resource_id": 7}]
REQUESTS = [{"user_id": user, "resource_type": kind, "resource_id": rid, "action": action}
            for user in range(1, 6) for kind, rid in (("board", 7), ("board", 8), ("task", 7)) for action in ("read", "delete")]


class SnapshotPolicyTests(unittest.TestCase):
    def compare(self, source=PROGRAM, rules=RULES, owners=OWNERS):
        return compare_snapshot(source, MODEL, deepcopy(rules), deepcopy(owners), REQUESTS)

    def test_source_db_loader_admin_owner_and_native_consumers_agree(self):
        result = self.compare()
        self.assertTrue(result["accepted"])
        self.assertEqual(result["expected_rows"], result["observed_rows"])
        self.assertEqual(result["counts"]["consumer_cells"], 30)
        self.assertFalse(result["initialization_admin_sync_transactions_or_orm_verified"])

    def test_owner_changes_only_matching_type_and_id(self):
        result = self.compare()
        owner = [cell for cell in result["cells"] if cell["request"]["user_id"] == 4]
        self.assertEqual([cell["allow"] for cell in owner], [True, True, False, False, False, False])

    def test_global_admin_not_ordinary_admin_bypasses_the_policy(self):
        result = self.compare()
        self.assertTrue(all(cell["allow"] for cell in result["cells"] if cell["request"]["user_id"] == 2))
        self.assertFalse(any(cell["allow"] for cell in result["cells"] if cell["request"]["user_id"] == 3))

    def test_domain_name_join_control_is_not_normalized_away(self):
        result = self.compare(PROGRAM.replace(b'{resource_type}_{resource_id}', b'{resource_type}-{resource_id}'))
        self.assertFalse(result["accepted"])
        self.assertTrue(result["producer_rows_agree"])
        self.assertFalse(result["comparison"]["accepted"])

    def test_owner_predicate_must_include_user_type_and_resource(self):
        result = self.compare(PROGRAM.replace(b'ResourceOwner.exists(user_id=user_id, resource_type=resource_type, resource_id=resource_id)',
                                              b'ResourceOwner.exists(resource_type=resource_type, resource_id=resource_id)'))
        self.assertFalse(result["accepted"])

    def test_ordinary_admin_is_not_silently_given_system_admin_rights(self):
        result = self.compare(PROGRAM.replace(b'return "system_admin" in roles', b'return "admin" in roles'))
        self.assertFalse(result["accepted"])

    def test_producer_field_swap_is_detected(self):
        result = self.compare(PROGRAM.replace(b'[rule.v0, rule.v1, rule.v2, rule.v3, rule.v4, rule.v5]',
                                              b'[rule.v1, rule.v0, rule.v2, rule.v3, rule.v4, rule.v5]'))
        self.assertFalse(result["accepted"])
        self.assertFalse(result["producer_rows_agree"])

    def test_enforce_interface_has_no_owner_bypass(self):
        requests = [{"user_id": user, "domain": "board_7", "resource": "board", "action": "read"} for user in range(1, 6)]
        result = compare_snapshot(PROGRAM, MODEL, RULES, OWNERS, requests, method="enforce")
        self.assertTrue(result["accepted"])
        self.assertEqual([cell["allow"] for cell in result["cells"]], [True, True, False, False, False])

    def test_ready_precondition_is_not_an_implicit_initialization_proof(self):
        with self.assertRaises(AdmissionError) as error:
            compare_snapshot(PROGRAM, MODEL, RULES, OWNERS, REQUESTS, ready=False)
        self.assertEqual(error.exception.status, "input_rejected")

    def test_changed_initialization_guard_is_not_ignored(self):
        with self.assertRaises(AdmissionError):
            self.compare(PROGRAM.replace(b'if not self._initialized:', b'if self._initialized:'))

    def test_accessor_changes_or_class_rebinding_are_not_ignored(self):
        for source in (PROGRAM.replace(b'  return self._enforcer\n', b'  return other_engine\n'),
                       PROGRAM + b'\n enforce = None\n', PROGRAM + b'\n def __getattr__(self, name):\n  return None\n'):
            with self.assertRaises(AdmissionError):
                self.compare(source)

    def test_missing_await_does_not_become_a_truthy_coroutine(self):
        with self.assertRaises(AdmissionError):
            self.compare(PROGRAM.replace(b'if await self.is_system_admin(user_id):', b'if self.is_system_admin(user_id):'))

    def test_discarded_unawaited_coroutine_cannot_execute_in_the_interpreter(self):
        for source in (PROGRAM.replace(b'  await self._ensure_initialized()', b'  self._ensure_initialized()'),
                       PROGRAM.replace(b'  rules = await CasbinRule.all()', b'  CasbinRule.all()\n  rules = await CasbinRule.all()')):
            with self.assertRaises(AdmissionError):
                self.compare(source)

    def test_deferred_coroutine_alias_is_unsupported_not_executed_eagerly(self):
        source = PROGRAM.replace(b'  roles = await self.get_global_roles(user_id)', b'  fetch = self.get_global_roles\n  roles = await fetch(user_id)')
        with self.assertRaises(AdmissionError):
            self.compare(source)

    def test_query_shadowing_import_rebinding_and_module_code_do_not_run(self):
        for source in (PROGRAM.replace(b'  rules = await CasbinRule.all()', b'  CasbinRule = 1\n  rules = await CasbinRule.all()'),
                       PROGRAM + b'\nCasbinRule = 1\n', PROGRAM.replace(b'  return "system_admin" in roles', b'  return dangerous_external_action()')):
            with self.assertRaises(AdmissionError):
                self.compare(source)

    def test_nullable_holes_unknown_policy_types_and_cycles_are_not_certified(self):
        malformed = deepcopy(RULES)
        malformed[0]["v1"] = None
        for rules in (malformed, [row("p2", "r", "d", "o", "a")], [row("g2", "a", "b"), row("g2", "b", "a")]):
            with self.assertRaises(AdmissionError):
                self.compare(rules=rules)

    def test_snapshot_query_fields_cannot_escape_projection(self):
        with self.assertRaises(AdmissionError):
            self.compare(PROGRAM.replace(b'v0=str(user_id)', b'password=str(user_id)'))

    def test_input_snapshots_are_unchanged(self):
        before = deepcopy((RULES, OWNERS))
        compare_snapshot(PROGRAM, MODEL, RULES, OWNERS, REQUESTS)
        self.assertEqual((RULES, OWNERS), before)

    def test_changed_model_is_not_assumed_to_have_same_global_role_semantics(self):
        with self.assertRaises(AdmissionError):
            compare_snapshot(PROGRAM, MODEL.replace('"system_admin"', '"admin"'), RULES, OWNERS, REQUESTS)

    def test_empty_policy_rows_and_duplicate_rows_have_explicit_native_results(self):
        self.assertTrue(self.compare(rules=[])["accepted"])
        self.assertTrue(self.compare(rules=[row("g2", "2", "system_admin")])["accepted"])
        result = self.compare(rules=RULES + [RULES[0]])
        self.assertTrue(result["accepted"])
        self.assertEqual(len(result["observed_rows"]), len(RULES))

    def test_budget_exhaustion_is_not_a_pass(self):
        native = NativeSnapshot(MODEL)
        interpreter = SnapshotInterpreter(extract_snapshot_program(PROGRAM), RULES, OWNERS, native, step_limit=1)
        with self.assertRaises(AdmissionError) as error:
            interpreter.run("_load_policy_from_db", [])
        self.assertEqual(error.exception.status, "inconclusive")

    def test_checker_domain_chunks_retain_a_mismatch_after_the_first_chunk(self):
        outside = {"user_id": 5, "resource_type": "board", "resource_id": 8, "action": "read"}
        reader = {"user_id": 1, "resource_type": "board", "resource_id": 7, "action": "read"}
        requests = [deepcopy(outside) for _ in range(32)] + [reader]
        source = PROGRAM.replace(b'{resource_type}_{resource_id}', b'{resource_type}-{resource_id}')
        result = compare_snapshot(source, MODEL, RULES, OWNERS, requests)
        self.assertFalse(result["accepted"])
        self.assertEqual([part["comparison"]["accepted"] for part in result["all_core_comparisons"]], [True, False])


if __name__ == "__main__":
    unittest.main()
