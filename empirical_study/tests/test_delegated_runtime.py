import ast,builtins,contextlib,unittest
from types import SimpleNamespace
from delegated_runtime import install,finish,Unknown,Machine,capture_unknowns
from predicate_runtime import body_identity

class World:
    def __init__(self):
        self.globals={'fail':lambda:(_ for _ in ()).throw(Unknown('unresolved')),'lock':contextlib.nullcontext}
        self.builtins={n:getattr(builtins,n) for n in ('set','list','tuple','any','len','bool','str','Exception','ValueError','AssertionError')}
        self.allowed_imports={};self.native_environments=[]
    def native_builtins(self):return self.builtins
    def bind_source_methods(self,mode):pass

def row(s):
    f=ast.parse(s).body[0]
    return dict(source=s,portable_body_sha256=body_identity(f.body),binding='f')
def compare(s,*args,**kwargs):
    results=[]
    for mode in ('native','model'):
        w=World();g=install([row(s)],w,mode);results.append(finish(g['f'](*args,**kwargs)))
    return results

class DelegationControls(unittest.TestCase):
    def test_unresolved_cleanup_cannot_certify_a_value(self):
        for code in ('def f():\n try:\n  fail()\n finally:\n  return True',
                     'def f():\n try:\n  fail()\n except:\n  return True'):
            for mode in ('native','model'):
                w=World();g=install([row(code)],w,mode)
                with capture_unknowns() as unresolved:
                    try:g['f']()
                    except Unknown:pass
                self.assertEqual(unresolved,['unresolved'])
    def test_padding_arithmetic(self):
        self.assertEqual(compare('def f(s):\n rem=len(s)%4\n if rem>0:\n  s += "="*(4-rem)\n return s','abc'),['abc=','abc='])
    def test_related_object_exception_is_not_unknown(self):
        class Missing(AttributeError,LookupError):pass
        class User:
            @property
            def settings(self):raise Missing('absent related row')
        for mode in ('native','model'):
            w=World();w.globals['LookupError']=LookupError
            g=install([row('def f(user):\n try:\n  return user.settings\n except LookupError:\n  return False')],w,mode)
            self.assertIs(g['f'](User()),False)
    def test_rich_comparison_not_forced_to_bool(self):
        class Query:
            def __bool__(self):raise AssertionError('query expression truth-tested')
        class Column:
            def __eq__(self,other):return query
        query=Query()
        for result in compare('def f(column):\n return column == 1',Column()):self.assertIs(result,query)
    def test_comparison_chain_preserves_last_operand(self):
        class Query:
            def __bool__(self):raise AssertionError('final expression truth-tested')
        class Column:
            def __lt__(self,other):return query
            def __gt__(self,other):return True
        query=Query()
        for result in compare('def f(column):\n return 0 < 1 < column < 3',Column()):self.assertIs(result,query)
    def test_duplicate_expanded_keyword_rejected(self):
        for mode in ('native','model'):
            w=World();w.globals.update(callee=lambda **kw:kw,dict=dict)
            g=install([row('def f():\n return callee(x=1, **dict(x=2))')],w,mode)
            with self.assertRaises(TypeError):g['f']()
    def test_reviewed_finite_loop(self):
        r=row('def f(xs):\n while xs:\n  xs.pop()\n else:\n  return len(xs)');r['reviewed_bounded_loop']=True
        for mode in ('native','model'):
            w=World();g=install([r],w,mode);self.assertEqual(g['f']([1,2]),0)
    def test_async_result(self):self.assertEqual(compare('async def f(x):\n return x',3),[3,3])
    def test_closure(self):
        self.assertEqual(compare('def f(x):\n def g(y):\n  return x+y\n return g(2)',3),[5,5])
    def test_async_closure_await(self):
        self.assertEqual(compare('async def f(x):\n async def g(y):\n  return x+y\n return await g(2)',3),[5,5])
    def test_lazy_any_comprehension(self):
        self.assertEqual(compare('def f(xs):\n return any(x.ok for x in xs)',[SimpleNamespace(ok=True),None]),[True,True])
    def test_nested_comprehension(self):self.assertEqual(compare('def f(xs):\n return {y for x in xs for y in x if y>0}',[[0,1],[2]]),[{1,2},{1,2}])
    def test_loop_unpack(self):self.assertEqual(compare('def f(xs):\n for a,b in xs:\n  if a:\n   return b\n return None',[(False,1),(True,2)]),[2,2])
    def test_keywords(self):self.assertEqual(compare('def f(x,*,y):\n return x+y',1,y=2),[3,3])
    def test_named_self_keyword_is_program_data(self):
        self.assertEqual(compare('def f(self):\n return self.ok',self=SimpleNamespace(ok=True)),[True,True])
    def test_keyword_default_used_by_helper(self):
        self.assertEqual(compare('def f(x):\n def g(*,value,other=None):\n  return value if other is None else other\n return g(value=x)',True),[True,True])
    def test_global_helper_default_is_preserved(self):
        first=row('def helper(*,value,other=None):\n return value if other is None else other');first['binding']='helper'
        second=row('def f(x):\n return helper(value=x)')
        for mode in ('native','model'):
            w=World();g=install([first,second],w,mode);self.assertIs(g['f'](True),True)
    def test_real_exception_handling(self):self.assertEqual(compare('def f(x):\n try:\n  raise ValueError(x)\n except ValueError as e:\n  return str(e)','normal'),['normal','normal'])
    def test_return_not_swallowed_by_except(self):self.assertEqual(compare('def f(x):\n try:\n  return x\n except Exception:\n  return False',True),[True,True])
    def test_unknown_not_swallowed_by_source_except(self):
        for mode in ('native','model'):
            w=World();g=install([row('def f():\n try:\n  return fail()\n except Exception:\n  return False')],w,mode)
            with self.assertRaises(Unknown):g['f']()
    def test_with_return(self):self.assertEqual(compare('def f():\n with lock():\n  return True'),[True,True])
    def test_augmented_set_updates(self):self.assertEqual(compare('def f():\n x={1}\n y=x\n x|={2}\n return y'),[{1,2},{1,2}])
    def test_short_circuit_none(self):self.assertEqual(compare('def f(x):\n return x and x.ok',None),[None,None])
    def test_slice(self):self.assertEqual(compare('def f(x):\n return x[1:-1]','abcd'),['bc','bc'])
    def test_not_admitted_effects(self):
        for s in ['def f():\n import os\n return os.getcwd()','def f():\n while True:\n  pass','def f(x):\n return x.__class__']:
            for mode in ('native','model'):
                with self.assertRaises(Unknown):install([row(s)],World(),mode)

if __name__=='__main__':unittest.main()
