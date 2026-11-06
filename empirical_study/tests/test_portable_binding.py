"""Regression checks for the actual readiness defects, separate from frozen runs."""
import ast,json,unittest
from pathlib import Path
from predicate_runtime import body_identity,parse_definition,compile_source
from verify import load,verify,exact

O=Path(__file__).resolve().parent
class PortableSourceBinding(unittest.TestCase):
    def test_observation_types_are_not_numeric_equality(self):
        self.assertFalse(exact(True,1));self.assertFalse(exact(False,0))
        self.assertFalse(exact({'value':True},{'value':1}))
        self.assertTrue(exact({'a':1,'b':False},{'b':False,'a':1}))
    def test_docstring_indentation_preserved(self):
        source='    def f(self):\n        """First line.\n        Literal continuation.\n        """\n        return True\n'
        full=ast.parse('class OriginalOwner:\n'+source).body[0].body[0]
        self.assertEqual(body_identity(full.body),body_identity(parse_definition(source).body))
        self.assertEqual(body_identity(full.body),body_identity(compile_source(source)[0].body))
    def test_extracted_source_not_replaced_by_edited_logic(self):
        self.assertNotEqual(body_identity(parse_definition('def f():\n return True').body),body_identity(parse_definition('def f():\n return False').body))
    def test_literal_whitespace_is_significant(self):
        self.assertNotEqual(body_identity(parse_definition('def f():\n return " a"').body),body_identity(parse_definition('def f():\n return "a"').body))
    def test_all_bound_invocations_explicit(self):
        for case in load('inputs.json.gz')['primary']['cases']:
            f=parse_definition(case['source']);names={a.arg for a in [*f.args.args,*f.args.kwonlyargs]}
            for c in case['inputs']:self.assertEqual(set(c['arguments']),names)
    def test_current_source_and_observations_match(self):
        self.assertTrue(verify()['all_recorded_observations_consistent'])

if __name__=='__main__':unittest.main()
