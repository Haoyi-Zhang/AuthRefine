"""Source registry admission, raw configuration and grant semantics controls."""
import ast
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'adaptation_study'))
import grant_binding as grants
from effect_slice import DataRecord, Generator
from native_casbin import AdmissionError
from policy_slice import Call


class GrantBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = grants.CoreGrants()
        cls.registry = (ROOT/'adaptation_study/pretix-core-registry.txt').read_bytes()
        cls.legacy = (ROOT/'adaptation_study/pretix-legacy-permissions.txt').read_bytes()

    def test_core_registry_not_given_read_write_powerset(self):
        self.assertEqual(len(self.core.groups),9)
        self.assertEqual(len(self.core.modern),12)
        self.assertNotIn('event.items:read',self.core.modern)
        self.assertEqual(self.core.groups['event.items'],('write',))

    def test_all_grants_and_legacy_alias_are_constructed_by_original_body(self):
        full = self.core.build(True,{})
        self.assertEqual(len(full),20)
        self.assertIn('can_change_settings',full)
        self.assertEqual(self.core.build(True,{},False),set(self.core.modern))

    def test_unknown_and_raw_legacy_names_do_not_become_core_grants(self):
        for raw in ({'event.items:read':True},{'can_change_items':True},{'owned.unregistered:read':True}):
            self.assertEqual(self.core.build(False,raw),set())
        self.assertEqual(self.core.build(False,{'event.items:write':True}),{'event.items:write','can_change_items'})

    def test_all_eight_profiles_match_separate_equation(self):
        for name,flag,stored in grants.raw_profiles():
            for include in (True,False):
                with self.subTest(name=name,include=include):
                    self.assertEqual(self.core.build(flag,stored,include),self.core.reference(flag,stored,include))

    def test_save_compatible_json_rejects_false_numbers_and_arbitrary_objects(self):
        for value in (False,1,0,None,[],{},DataRecord('X',{})):
            with self.subTest(value=type(value).__name__),self.assertRaises(AdmissionError):
                self.core.build(False,{'event.items:write':value})
        for flag in (0,1,None):
            with self.assertRaises(AdmissionError):
                self.core.build(flag,{})
        with self.assertRaises(AdmissionError):
            self.core.build(False,{},1)

    def test_lazy_all_preserves_short_circuit_and_empty_generator(self):
        machine = grants.GrantInterpreter({},DataRecord('Owned',{}),{})
        node = ast.parse('all(v for v in values)',mode='eval').body.args[0]
        # An unbound third value would fail if evaluation did not short circuit.
        gen = Generator(node,dict(values=[False,DataRecord('X',{})]))
        self.assertFalse(machine.call(Call('grant-all'),[gen],{},{}))
        self.assertTrue(gen.consumed)
        self.assertTrue(machine.call(Call('grant-all'),[Generator(node,dict(values=[]))],{},{}))

    def test_lazy_all_does_not_evaluate_tail_capability(self):
        calls = []
        node = ast.parse('all(probe(v) for v in values)',mode='eval').body.args[0]
        machine = grants.GrantInterpreter({},DataRecord('Owned',{}),{})
        def probe(v):
            calls.append(v)
            return v
        gen = Generator(node,dict(values=[False,True],probe=grants.Capability('owned probe',probe)))
        self.assertFalse(machine.call(Call('grant-all'),[gen],{},{}))
        self.assertEqual(calls,[False])

    def test_dynamic_duplicate_or_rebound_registry_is_not_admitted(self):
        for before,after in ((b'name="event.items"',b'name=dynamic_name'),
                (b'name="event.items"',b'name="event.orders"'),
                (b'actions=["cancel"]',b'actions=["cancel", "cancel"]')):
            self.assertIn(before,self.registry)
            with self.assertRaises(AdmissionError):
                grants.registry_projection(self.registry.replace(before,after))
        with self.assertRaises(AdmissionError):
            grants.registry_projection(self.registry+b'\nPermissionGroup = other\n')

    def test_legacy_duplicate_and_unregistered_targets_are_rejected(self):
        for suffix in (b'\nOLD_TO_NEW_EVENT_COMPAT = {}\n',):
            with self.assertRaises(AdmissionError):
                grants.legacy_projection(self.legacy+suffix,set(self.core.modern))
        with self.assertRaises(AdmissionError):
            grants.legacy_projection(self.legacy.replace(b'"event.items:write"',b'"event.items:read"'),set(self.core.modern))

    def test_container_bounds_and_host_methods_fail_closed(self):
        machine = grants.GrantInterpreter({},DataRecord('Owned',{}),{})
        for value in (object(),{str(i):True for i in range(129)}):
            with self.assertRaises(AdmissionError):
                machine.value(ast.parse('x.items',mode='eval').body,{'x':value})
        with self.assertRaises(AdmissionError):
            self.core.build(False,{str(i):True for i in range(129)})

    def test_cli_setup_failure_is_not_successful_control(self):
        for error in (ValueError('setup'),AdmissionError('unsupported')):
            with patch.object(sys,'argv',['grant_binding.py','--framework','owned','--control','raw_keys']),patch.object(grants,'run',side_effect=error):
                with self.assertRaises(type(error)):
                    grants.main()


if __name__ == '__main__':
    unittest.main()
