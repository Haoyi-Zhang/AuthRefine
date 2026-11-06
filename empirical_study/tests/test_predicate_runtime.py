"""Owned semantic and fail-closed controls, not upstream defect discoveries."""
import unittest
from predicate_runtime import Unsupported,compile_source,execute,unpack,pack,observation

def run(source,args):
    f,ir=compile_source(source)
    return observation(lambda:execute(ir,unpack(args))[1])

class PredicateControls(unittest.TestCase):
    def test_short_circuit_preserves_none(self):
        self.assertEqual(run('def f(x):\n return x and x.ok',{'x':None})['result'],pack(None))
    def test_short_circuit_skips_missing(self):
        self.assertEqual(run('def f(x):\n return x or missing.field',{'x':True})['result'],pack(True))
    def test_missing_is_unknown(self):
        self.assertEqual(run('def f(x):\n return x.ok',{'x':{'$record':{}}})['status'],'unsupported')
    def test_none_not_false(self):self.assertNotEqual(pack(None),pack(False))
    def test_tuple_not_list(self):self.assertNotEqual(pack((True,None)),pack([True,None]))
    def test_bare_return(self):self.assertEqual(run('def f():\n return',{})['result'],pack(None))
    def test_membership(self):self.assertEqual(run('def f(x):\n return x in {"a","b"}',{'x':'b'})['result'],pack(True))
    def test_local_branches(self):self.assertEqual(run('def f(x):\n y=x>2\n if y:\n  return x\n return None',{'x':3})['result'],pack(3))
    def test_chained_compare(self):self.assertEqual(run('def f(x):\n return 0 < x < 3',{'x':3})['result'],pack(False))
    def test_typed_handoff(self):self.assertEqual(run('def f():\n return {"token":None}',{})['result'],pack({'token':None}))
    def test_keywords_preserved(self):
        f,ir=compile_source('def f(*,x):\n return x')
        self.assertEqual([a.arg for a in f.args.kwonlyargs],['x'])
    def test_defaults_not_executed(self):
        f,_=compile_source('def f(x=forbidden()):\n return x')
        self.assertEqual(f.args.defaults,[])
    def test_reject_effects_and_hidden_runtime(self):
        for s in ['return open("x")','import os','x.ok=True','return x.__class__','return [v for v in x]','while True:\n  pass','raise ValueError()','return lambda:x']:
            with self.subTest(s=s),self.assertRaises(Unsupported):compile_source('def f(x):\n '+s.replace('\n','\n '))
    def test_reject_module_startup(self):
        with self.assertRaises(Unsupported):compile_source('do_something()\ndef f():\n return True')
    def test_decision_not_forced_to_bool(self):
        self.assertEqual(run('def f(x):\n return x',{'x':{'$record':{'allowed':True}}})['result']['type'],'record')
    def test_decorators_not_called(self):
        f,_=compile_source('@dangerous()\ndef f(x):\n return x')
        self.assertEqual(f.decorator_list,[])

if __name__=='__main__':unittest.main()
