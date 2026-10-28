import ast
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from effect_slice import Capability, DataRecord, EffectInterpreter, SliceFault
from guard_prefix import extract_guard_prefix
from native_casbin import AdmissionError

SOURCE = b'''class Gate(UnknownFramework):
 async def prepare(self):
  """A selected body, not framework dispatch."""
  user = self.current_user
  if user is None:
   raise Denied("missing")
  if not self.allowed(user):
   raise Denied("denied")
  dangerous_unexamined_tail()
'''
BARRIER = ast.parse("dangerous_unexamined_tail()").body[0]


class GuardPrefixTests(unittest.TestCase):
    def extract(self, source=SOURCE, count=3, barrier=BARRIER):
        return extract_guard_prefix(source, "Gate", "prepare", count, barrier)

    def test_selected_ast_and_tail_are_distinct(self):
        program, descriptor = self.extract()
        self.assertEqual(len(program["prepare"].body), 3)
        self.assertEqual(descriptor["unexamined_statements"], 1)
        self.assertFalse(descriptor["receiver_dispatch_or_inheritance_proved"])
        self.assertTrue(descriptor["continuation_is_not_an_access_grant"])

    def test_identity_denial_short_circuits_supplied_predicate(self):
        program, _ = self.extract()
        receiver = DataRecord("given", {"current_user": None})
        interpreter = EffectInterpreter(program, receiver,
            {"Denied": Capability("owned_denial", lambda text: SliceFault("Denied", text))})
        with self.assertRaises(SliceFault) as error:
            interpreter.run("prepare", [])
        self.assertEqual(error.exception.message, "missing")

    def test_owned_predicate_is_called_once_and_tail_never_runs(self):
        for allowed in (False, True):
            effects = []
            program, _ = self.extract()
            receiver = DataRecord("given", {"current_user": "owned-user",
                "allowed": Capability("given_predicate", lambda user: effects.append(user) or allowed)})
            interpreter = EffectInterpreter(program, receiver,
                {"Denied": Capability("owned_denial", lambda text: SliceFault("Denied", text))})
            if allowed:
                self.assertIsNone(interpreter.run("prepare", []))
            else:
                with self.assertRaises(SliceFault):
                    interpreter.run("prepare", [])
            self.assertEqual(effects, ["owned-user"])

    def test_unknown_prelude_is_not_skipped(self):
        with self.assertRaises(AdmissionError):
            self.extract(SOURCE.replace(b"  user =", b"  unknown_effect()\n  user ="))

    def test_changed_barrier_is_not_accepted(self):
        with self.assertRaises(AdmissionError):
            self.extract(barrier=ast.parse("other_tail()").body[0])

    def test_decorators_and_rebindings_require_separate_contract(self):
        for source in (b"@unknown\n" + SOURCE, SOURCE.replace(b" async def prepare", b" @unknown\n async def prepare"),
                SOURCE + b"Gate = other\n", SOURCE + b"\n if flag:\n  prepare = other\n"):
            with self.assertRaises(AdmissionError):
                self.extract(source)

    def test_bounds_and_unsupported_selected_syntax_fail_closed(self):
        for count in (True, 0, 17, 4):
            with self.assertRaises(AdmissionError):
                self.extract(count=count)
        changed = SOURCE.replace(b"  user = self.current_user", b"  import os")
        with self.assertRaises(AdmissionError):
            self.extract(changed)


if __name__ == "__main__":
    unittest.main()
