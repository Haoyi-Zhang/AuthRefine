"""Owned portable source-study checks;no target app or online calls."""
import ast
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'source_study'),str(ROOT/'source_study/code'),str(ROOT/'src')]
from credential_flow_ir import Machine,Ref,Unsupported,compile_function
from dependency_inventory import Inventory
from verify import verify


class SourceStudyControls(unittest.TestCase):
    def test_current_full_family_and_cases(self):
        result=verify();self.assertEqual(result['credential_bindings'],112);self.assertEqual(result['matching_bindings'],8)
        self.assertEqual(result['deep_cases'],8);self.assertEqual(result['explicit_unknown_cases'],1)
        self.assertFalse(result['independent_gold_accepted'])
    def test_analysis_unknown_not_caught_as_source_value_error(self):
        program=compile_function(ast.parse('def f():\n try: return len(())\n except ValueError: return False').body[0])
        class Primitive:
            def call(self,*args):raise Unsupported('owned unsupported primitive')
        with self.assertRaises(Unsupported):Machine({'f':program},{'len':Ref('len'),'ValueError':ValueError},Primitive()).call(Ref('f'),[])
    def test_source_value_error_still_has_source_meaning(self):
        program=compile_function(ast.parse('def f():\n try: return len(())\n except ValueError: return False').body[0])
        class Primitive:
            def call(self,*args):raise ValueError('owned ordinary primitive contract')
        self.assertIs(Machine({'f':program},{'len':Ref('len'),'ValueError':ValueError},Primitive()).call(Ref('f'),[]),False)
    def test_source_inventory_does_not_execute_top_level_code(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'input.zip'
            with zipfile.ZipFile(path,'w') as z:
                z.comment=b'owned-source';z.writestr('owned/app.py','raise RuntimeError("must never execute")\ndef permission(): return True\n')
            result=Inventory(path).scan()
        self.assertFalse(result['source_modules_or_tests_executed']);self.assertEqual(result['parsed_modules'],1)
