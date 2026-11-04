"""Owned source-transfer correctness checks; no upstream code or tests run."""
import ast
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
FILE=HERE/'study.py' if (HERE/'study.py').exists() else HERE.parent/'prospective_study/study.py'
spec=importlib.util.spec_from_file_location('authrefine_prospective_study',FILE)
s=importlib.util.module_from_spec(spec);sys.modules[spec.name]=s;spec.loader.exec_module(s)

class ProspectiveTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=s.load();cls.primary=s.run(False);cls.secondary=s.run(True)

    def test_fixed_population_and_reference_denominators_are_separate(self):
        self.assertEqual(len(self.data['projects']),12)
        self.assertEqual(sum(bool(p.get('acquired')) for p in self.data['projects']),10)
        refs=self.data['reference_input']['references']
        self.assertEqual(len(refs),9);self.assertEqual(sum(len(r['contexts']) for r in refs),78)
        self.assertEqual(len({r['repository'] for r in refs}),3)
        self.assertTrue(all(not p['known_family_overlap'] for p in self.data['projects']))
        self.assertFalse(self.secondary['whole_application_verified'])

    def test_frozen_primary_preserves_unknowns_and_nonadmissions(self):
        self.assertEqual((self.primary['complete_boundaries'],self.primary['unknown_contexts']),(5,55))
        self.assertEqual(self.primary['mismatching_boundaries'],0)
        self.assertEqual(self.primary['unresolved_reference_interfaces'],60)
        self.assertEqual(self.primary['candidate_interfaces'],69)

    def test_secondary_replays_every_normal_contract_without_a_new_blind_claim(self):
        self.assertEqual((self.secondary['complete_boundaries'],self.secondary['unknown_contexts']),(9,0))
        self.assertTrue(all(o['agrees'] is True for r in self.secondary['rows'] for o in r['observations']))
        self.assertTrue(self.secondary['secondary_is_not_another_blind_transfer'])
        self.assertFalse(self.secondary['independent_human_gold_claimed'])

    def test_source_resource_dispatch_and_override_are_actually_consumed(self):
        row=next(r for r in self.secondary['rows'] if r['id'].endswith('ResourcePermission.check_permissions'))
        self.assertEqual(row['contexts'],27)
        self.assertEqual(sum(o['observed']['value'] is True for o in row['observations']),9+6+4)
        self.assertTrue(all(o['function_calls'].get('ResourcePermission__check_permissions')==1 for o in row['observations']))
        self.assertTrue(any('Or__check_permissions' in o['function_calls'] for o in row['observations']))
        leaf=next(r for r in self.secondary['rows'] if r['id'].endswith('IsTheSameUser.check_permissions'))
        self.assertEqual(sum(o['observed']['value'] is None for o in leaf['observations']),3)

    def test_complete_entry_bodies_stay_identical_under_declared_adapters(self):
        for ref in self.data['reference_input']['references']:
            with self.subTest(function=ref['id']):
                program,key=s.prepare(self.data,ref,True)
                actual=s.sha(ast.dump(ast.Module(body=program[key].body,type_ignores=[])).encode())
                self.assertEqual(actual,ref['body_ast_sha256'])

    def test_owned_fault_controls_have_real_normal_observation_differences(self):
        for control in ('wrong_owner','drop_super','wrong_principal'):
            with self.subTest(control=control):
                value=s.run(True,control)
                self.assertGreater(sum(o.get('agrees') is False for r in value['rows'] for o in r['observations']),0)

    def test_unresolved_setup_is_not_relabelled_a_detected_fault_or_agreement(self):
        with patch.object(s,'setup',side_effect=s.AdmissionError('owned setup not admitted')):
            value=s.run(True)
        self.assertEqual(value['unknown_contexts'],78)
        self.assertEqual(value['mismatching_boundaries'],0)
        self.assertTrue(all(o['agrees'] is None for r in value['rows'] for o in r['observations']))

if __name__=='__main__':unittest.main()
