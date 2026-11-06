"""Owned normal-language follow-ups for cleanup and keyword forwarding."""
import unittest
from test_review_semantics import function,outcome

class FollowupSemantics(unittest.TestCase):
    def cleanup(self,mode,suppress):
        seen=[]
        class Manager:
            def __enter__(self):seen.append('enter');return [1]
            def __exit__(self,kind,value,tb):seen.append(('exit',kind.__name__ if kind else None));return suppress
        source='def f():\n with cm() as (x,y):\n  return x\n return "after"'
        return outcome(lambda:function(source,mode,dict(cm=Manager))()),seen
    def test_context_binding_error_still_calls_exit(self):
        for mode in ('native','model'):
            result,seen=self.cleanup(mode,False)
            self.assertEqual(result,('source_exception','ValueError'))
            self.assertEqual(seen,['enter',('exit','ValueError')])
    def test_context_binding_error_can_be_suppressed(self):
        for mode in ('native','model'):
            self.assertEqual(self.cleanup(mode,True),(('value','after'),['enter',('exit','ValueError')]))
    def test_keyword_expansion_rejects_nonmapping(self):
        for mode in ('native','model'):
            self.assertEqual(outcome(lambda:function('def f(m):\n return sink(**m)',mode,dict(sink=lambda **kw:kw))([])),('source_exception','TypeError'))
    def test_keyword_expansion_accepts_keys_only_mapping(self):
        for mode in ('native','model'):
            seen=[]
            class Mapping:
                def keys(self):seen.append('keys');return ['x','y']
                def __getitem__(self,key):seen.append(key);return {'x':1,'y':2}[key]
            value=function('def f(m):\n return sink(**m)',mode,dict(sink=lambda **kw:kw))(Mapping())
            self.assertEqual((value,seen),({'x':1,'y':2},['keys','x','y']))
    def test_duplicate_keyword_does_not_fetch_duplicate_value(self):
        for mode in ('native','model'):
            seen=[]
            class Mapping:
                def keys(self):seen.append('keys');return ['x','y']
                def __getitem__(self,key):seen.append(key);return 1
            self.assertEqual(outcome(lambda:function('def f(m):\n return sink(x=0,**m)',mode,dict(sink=lambda **kw:kw))(Mapping())),('source_exception','TypeError'))
            self.assertEqual(seen,['keys'])

if __name__=='__main__':unittest.main()
