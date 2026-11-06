"""Benign owned language examples for the received final method findings."""
import ast,builtins,contextlib,json,unittest
from types import SimpleNamespace
from unittest.mock import patch
import predicate_runtime as pure
from delegated_runtime import install,finish,Unknown
from remaining_worker import observe
from remaining_worlds import World as ProviderWorld

class World:
    def __init__(self,extra=None):
        self.globals=dict(extra or {});self.builtins={n:getattr(builtins,n) for n in ('Exception','ValueError','TypeError','RuntimeError','UnboundLocalError','NameError','str','list','dict','set','tuple','len','bool','any','all')};self.allowed_imports={};self.native_environments=[]
    def native_builtins(self):return self.builtins
    def bind_source_methods(self,mode):pass
def capsule(s):
    f=ast.parse(s).body[0];return dict(source=s,binding='f',portable_body_sha256=pure.body_identity(f.body))
def function(s,mode,extra=None):return install([capsule(s)],World(extra),mode)['f']
def outcome(fn):
    try:return ('value',finish(fn()))
    except Unknown as ex:return ('unsupported',str(ex))
    except Exception as ex:return ('source_exception',type(ex).__name__)

class FinalReviewSemantics(unittest.TestCase):
    def test_positional_only_and_same_name_extra_keyword(self):
        s='def f(x, /, y=2, **extras):\n return x,y,extras'
        self.assertEqual([function(s,m)(1,x=3) for m in ('native','model')],[(1,2,{'x':3})]*2)
    def test_positional_only_simple_argument(self):
        self.assertEqual([function('def f(x, /):\n return x',m)(1) for m in ('native','model')],[1,1])
    def test_missing_async_argument_is_rejected_at_call(self):
        for mode in ('native','model'):
            with self.subTest(mode=mode),self.assertRaises(TypeError):function('async def f(x):\n return x',mode)()
    def test_local_read_before_assignment_does_not_read_global(self):
        s='def f():\n y=x\n x=1\n return y'
        self.assertEqual([outcome(lambda m=m:function(s,m,{'x':7})()) for m in ('native','model')],[('source_exception','UnboundLocalError')]*2)
    def test_pure_local_read_before_assignment(self):
        f,ir=pure.compile_source('def f():\n y=x\n x=1\n return y')
        self.assertEqual(pure.observation(lambda:pure.execute(ir,{'x':7})[1]),dict(status='source_exception',exception='UnboundLocalError'))
    def test_pure_assigned_parameter_is_not_uninitialized(self):
        f,ir=pure.compile_source('def f(x):\n x=x\n return x')
        self.assertEqual(pure.execute(ir,{'x':3})[1],3)
    def test_free_cell_uninitialized_is_name_error(self):
        s='def f():\n def g():\n  return x\n y=g()\n x=1\n return y'
        self.assertEqual([outcome(lambda m=m:function(s,m,{'x':7})()) for m in ('native','model')],[('source_exception','NameError')]*2)
    def test_late_bound_closure_cell(self):
        s='def f():\n def g():\n  return x\n x=2\n return g()'
        self.assertEqual([function(s,m)() for m in ('native','model')],[2,2])
    def test_await_requires_awaitable(self):
        s='async def f():\n return await 1'
        self.assertEqual([outcome(lambda m=m:function(s,m)()) for m in ('native','model')],[('source_exception','TypeError')]*2)
    def test_coroutine_cannot_be_reused(self):
        s='async def f():\n async def g():\n  return 1\n c=g()\n await c\n return await c'
        self.assertEqual([outcome(lambda m=m:function(s,m)()) for m in ('native','model')],[('source_exception','RuntimeError')]*2)
    def test_dict_key_precedes_value(self):
        for mode in ('native','model'):
            seen=[]
            def key():seen.append('key');return 'x'
            def value():seen.append('value');return 1
            self.assertEqual(function('def f():\n return {key():value()}',mode,dict(key=key,value=value))(),{'x':1})
            self.assertEqual(seen,['key','value'])
    def test_dict_expansion_requires_mapping(self):
        for mode in ('native','model'):
            self.assertEqual(outcome(lambda m=mode:function('def f(x):\n return {**x}',m)([['x',1]])),('source_exception','TypeError'))
    def test_generator_outer_expression_is_eager(self):
        for mode in ('native','model'):
            seen=[]
            def values():seen.append('iterable');return [1,2]
            def mark():seen.append('created')
            self.assertEqual(function('def f():\n g=(x for x in values())\n mark()\n return list(g)',mode,dict(values=values,mark=mark))(),[1,2])
            self.assertEqual(seen,['iterable','created'])
    def test_generator_obtains_outer_iterator_at_creation(self):
        for mode in ('native','model'):
            seen=[]
            class Values:
                def __iter__(self):seen.append('iter');return iter([1])
            def mark():seen.append('created')
            self.assertEqual(function('def f(xs):\n g=(x for x in xs)\n mark()\n return list(g)',mode,dict(mark=mark))(Values()),[1])
            self.assertEqual(seen,['iter','created'])
    def test_exception_binding_is_cleared(self):
        s='def f():\n try:\n  raise ValueError("x")\n except ValueError as error:\n  pass\n return str(error)'
        self.assertEqual([outcome(lambda m=m:function(s,m)()) for m in ('native','model')],[('source_exception','UnboundLocalError')]*2)
    def test_augmented_assignment_target_evaluated_once(self):
        for mode in ('native','model'):
            seen=[];record=SimpleNamespace(x=2)
            def obj():seen.append('target');return record
            def rhs():seen.append('rhs');return 3
            function('def f():\n obj().x += rhs()\n return True',mode,dict(obj=obj,rhs=rhs))()
            self.assertEqual((record.x,seen),(5,['target','rhs']))
    def test_pure_encoder_error_is_not_source_exception(self):
        with patch.object(pure,'pack',side_effect=TypeError('owned encoder failure')):
            self.assertEqual(pure.observation(lambda:1)['status'],'harness_error')
    def test_delegated_encoder_error_is_not_source_exception(self):
        w=SimpleNamespace(pack=lambda value:(_ for _ in ()).throw(TypeError('owned encoder failure')))
        self.assertEqual(observe(w,lambda:1)['status'],'harness_error')
    def test_pure_mixed_dictionary_keys_are_typed(self):
        result=pure.observation(lambda:{1:'a','1':'b'})
        self.assertEqual(result['status'],'value');self.assertEqual(len(result['result']['value']),2)
    def test_delegated_dictionary_keys_are_not_stringified(self):
        w=object.__new__(ProviderWorld);w.refs={}
        self.assertEqual(len(w.pack({1:'a','1':'b'})['mapping']),2)
    def test_set_and_frozenset_are_distinct_projections(self):
        w=object.__new__(ProviderWorld);w.refs={}
        self.assertNotEqual(w.pack({1}),w.pack(frozenset({1})))
    def test_registered_return_identity_is_preserved(self):
        w=object.__new__(ProviderWorld);value=SimpleNamespace(x=1);w.refs={id(value):'user'}
        self.assertEqual(w.pack(value),{'ref':'user'})
        self.assertNotEqual(w.pack(value),w.pack(SimpleNamespace(x=1)))
if __name__=='__main__':unittest.main()
