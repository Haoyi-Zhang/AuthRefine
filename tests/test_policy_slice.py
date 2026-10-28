from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from policy_slice import PolicyInterpreter, extract_policy_program

# Owned data-only fixture, never imported as an application.
PROGRAM = '''import re
class PolicyEngine:
 def _sync_yaml_to_casbin(self):
  self.enforcer.clear_policy()
  for role, info in self.yaml_policy.get("roles", {}).items():
   for permission in info.get("permissions", []):
    for verb in permission.get("actions", []):
     self.enforcer.add_policy(role, permission.get("resource", "*"), verb)
  for user, roles in self.yaml_policy.get("user_roles", {}).items():
   for role in roles:
    self.enforcer.add_grouping_policy(user, role)
  for group, roles in self.yaml_policy.get("group_roles", {}).items():
   for role in roles:
    self.enforcer.add_grouping_policy(group, role)
  self.enforcer.save_policy()
 def check_permission(self, user, resource, action, groups=None):
  decision, reason = self._check_custom_rules(user, resource, action)
  if decision is not None:
   return decision, reason
  if self.enforcer.enforce(user, resource, action):
   return True, "user"
  if groups:
   for group in groups:
    if self.enforcer.enforce(group, resource, action):
     return True, f"group:{group}"
  if self.yaml_policy.get("default_policy", "deny") == "allow":
   return True, "default allow"
  return False, "default deny"
 def _check_custom_rules(self, user, resource, action):
  rules = sorted(self.yaml_policy.get("rules", []), key=lambda item: item.get("priority", 0), reverse=True)
  for rule in rules:
   if self._match_rule_condition(rule.get("condition", {}), user, resource, action):
    if rule.get("action", "deny") == "allow":
     return True, "rule allow"
    elif rule.get("action", "deny") == "deny":
     return False, "rule deny"
  return None, None
 def _match_rule_condition(self, condition, user, resource, action):
  if "user" in condition:
   if condition["user"] != user:
    return False
  if "action" in condition:
   if condition["action"] != action:
    return False
  if "mcp_server" in condition:
   parts = resource.split(":")
   if len(parts) >= 2:
    if parts[1] != condition["mcp_server"]:
     return False
   else:
    return False
  if "tool_name_pattern" in condition:
   parts = resource.split(":")
   if len(parts) >= 3:
    if not re.match(condition["tool_name_pattern"], parts[2]):
     return False
   else:
    return False
  return True
'''.encode()


class OwnedNative:
    def __init__(self, allow=False):
        self.allow = allow
        self.operations = []
    def invoke(self, method, arguments):
        self.operations.append((method, arguments))
        return self.allow if method == "enforce" else None


class PolicySliceTests(unittest.TestCase):
    def test_source_projection_follows_nested_loops_and_argument_order(self):
        native = OwnedNative()
        data = {"roles": {"reader": {"permissions": [{"resource": "record", "actions": ["read"]}]}}, "user_roles": {"u": ["reader"]}}
        PolicyInterpreter(extract_policy_program(PROGRAM), data, native).run("_sync_yaml_to_casbin", [])
        self.assertEqual(native.operations, [("clear_policy", []), ("add_policy", ["reader", "record", "read"]),
                                             ("add_grouping_policy", ["u", "reader"]), ("save_policy", [])])

    def test_decision_and_reason_remain_a_tuple_not_a_boolean(self):
        outcome = PolicyInterpreter(extract_policy_program(PROGRAM), {}, OwnedNative()).run("check_permission", ["u", "r", "read"])
        self.assertEqual(outcome, (False, "default deny"))
        self.assertTrue(bool(outcome))

    def test_priority_sorting_is_stable_for_equal_keys(self):
        data = {"rules": [{"condition": {}, "action": "deny", "priority": 2}, {"condition": {}, "action": "allow", "priority": 2}]}
        outcome = PolicyInterpreter(extract_policy_program(PROGRAM), data, OwnedNative(True)).run("check_permission", ["u", "r", "read", []])
        self.assertEqual(outcome, (False, "rule deny"))

    def test_a_native_exception_is_not_policy_denial(self):
        class Broken(OwnedNative):
            def invoke(self, method, arguments):
                raise AdmissionError("owned native error", "native_error")
        with self.assertRaises(AdmissionError) as caught:
            PolicyInterpreter(extract_policy_program(PROGRAM), {}, Broken()).run("check_permission", ["u", "r", "read"])
        self.assertEqual(caught.exception.status, "native_error")

    def test_side_effectful_module_initializer_is_not_run(self):
        program = extract_policy_program(b'raise RuntimeError("do not import")\n' + PROGRAM)
        self.assertIn("check_permission", program)

    def test_forbidden_method_body_import_or_io_is_not_executed(self):
        for code in (b'  import os\n  self.enforcer.clear_policy()', b'  open("forbidden")\n  self.enforcer.clear_policy()'):
            changed = PROGRAM.replace(b'  self.enforcer.clear_policy()', code)
            if b'import os' in code:
                with self.assertRaises(AdmissionError):
                    extract_policy_program(changed)
            else:
                with self.assertRaises(AdmissionError):
                    PolicyInterpreter(extract_policy_program(changed), {}, OwnedNative()).run("_sync_yaml_to_casbin", [])

    def test_recursive_calls_and_work_exhaustion_are_inconclusive(self):
        program = extract_policy_program(PROGRAM)
        with self.assertRaises(AdmissionError) as caught:
            PolicyInterpreter(program, {}, OwnedNative(), step_limit=1).run("check_permission", ["u", "r", "a"])
        self.assertEqual(caught.exception.status, "inconclusive")
        changed = PROGRAM.replace(b'  self.enforcer.clear_policy()', b'  self._sync_yaml_to_casbin()')
        with self.assertRaises(AdmissionError):
            PolicyInterpreter(extract_policy_program(changed), {}, OwnedNative()).run("_sync_yaml_to_casbin", [])

    def test_unsupported_async_and_loops_are_not_silently_skipped(self):
        for changed in (PROGRAM.replace(b' def check_permission', b' async def check_permission'),
                        PROGRAM.replace(b'  self.enforcer.clear_policy()', b'  while True:\n   pass')):
            with self.assertRaises(AdmissionError):
                extract_policy_program(changed)

    def test_rebinding_primitive_is_not_allowed(self):
        changed = PROGRAM.replace(b'  self.enforcer.clear_policy()', b'  self = 1\n  self.enforcer.clear_policy()')
        with self.assertRaises(AdmissionError):
            PolicyInterpreter(extract_policy_program(changed), {}, OwnedNative()).run("_sync_yaml_to_casbin", [])

    def test_match_presence_preserves_none_and_truth_observations(self):
        changed = PROGRAM.replace(b'if not re.match(condition["tool_name_pattern"], parts[2]):', b'if re.match(condition["tool_name_pattern"], parts[2]) is None:')
        interpreter = PolicyInterpreter(extract_policy_program(changed), {}, OwnedNative())
        self.assertFalse(interpreter.run("_match_rule_condition", [{"tool_name_pattern": ".*delete.*"}, "u", "mcp:p:read", "a"]))
        self.assertTrue(interpreter.run("_match_rule_condition", [{"tool_name_pattern": ".*delete.*"}, "u", "mcp:p:delete_item", "a"]))


if __name__ == "__main__":
    unittest.main()
