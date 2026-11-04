"""Owned normal source controls for adaptation classifications and admission."""
import ast,importlib.util,json,gzip,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'adaptation_study'))
import study
from profiles import Body,Record,Ref,Unsupported,AuthFailure,QueryMiss

class Native:
    def attribute(self,obj,name):raise Unsupported('unknown attribute')
    def call(self,f,args,kwargs):
        if f.name=='missing':raise QueryMiss('absent')
        if f.name=='unknown':raise Unsupported('not admitted')
        if f.name=='authfail':return AuthFailure('not active')
        raise Unsupported('unknown capability')

class AdaptationStudyTests(unittest.TestCase):
    def body(self,text,globals=None):
        return Body(ast.parse(text).body[0],Native(),globals or {})
    def test_route_delete_decorator_is_not_a_body_mutation(self):
        fn=ast.parse('@router.delete("/item")\ndef endpoint():\n return 0').body[0]
        self.assertEqual(study.classify(fn),set())
        self.assertFalse(any('mutation_call' in study.classify(n) for stmt in fn.body for n in ast.walk(stmt)))
    def test_mutation_name_does_not_claim_durable_persistence(self):
        call=ast.parse('values.update(other)').body[0].value
        self.assertEqual(study.classify(call),{'mutation_call'})
        self.assertIn('case-level observation',study.TAXONOMY['mutation_call'])
    def test_scalar_assignment_and_return(self):
        self.assertEqual(self.body('def f(x):\n y=x\n return y').run([7]),7)
    def test_unknown_is_not_caught_as_missing_database_row(self):
        b=self.body('def f():\n try:\n  x=unknown()\n except Missing:\n  return 1\n return x',{'unknown':Ref('unknown'),'Missing':QueryMiss})
        with self.assertRaises(Unsupported):b.run([])
    def test_actual_missing_row_takes_explicit_handler(self):
        b=self.body('def f():\n try:\n  x=missing()\n except Missing:\n  return 1\n return x',{'missing':Ref('missing'),'Missing':QueryMiss})
        self.assertEqual(b.run([]),1)
    def test_unbound_call_cannot_execute_application_code(self):
        with self.assertRaises(Unsupported):self.body('def f():\n return unknown()',{'unknown':object()}).run([])
    def test_only_selected_business_fields_are_mutable(self):
        with self.assertRaises(Unsupported):self.body('def f(x):\n x.project_id=2\n return x').run([Record('Check',{'project_id':1})])
    def test_complete_original48_source_population_and_evidence_anchors(self):
        result=study.run();self.assertEqual(len(result['rows']),48)
        original=json.loads(gzip.decompress((ROOT/'source_study/data/source-transfer.json.gz').read_bytes()))
        self.assertEqual([r['repository_id'] for r in result['rows']],[r['repository_id'] for r in original['rows']])
        self.assertTrue(all(r['evidence'][k] for r in result['rows'] for k in study.TAXONOMY if r['features'][k]=='observed'))
        self.assertFalse(result['independent_gold_claimed'])

if __name__=='__main__':unittest.main()
