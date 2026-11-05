"""Owned bounded source-data interpreter; never imports or executes application code."""
import ast
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
ART=HERE.parent if (HERE.parent/'src').is_dir() else next(p/'workspace/artifact' for p in HERE.parents if (p/'workspace/artifact/src').is_dir())
sys.path[:0]=[str(ART/'src')]
from effect_slice import (Capability,Closure,DataRecord,Deferred,EffectInterpreter,ErrorType,
    Generator,LoopBreak,RecordType,Return,SerialContext,SliceFault)
from native_casbin import AdmissionError

def body_dump(node):
    tree=ast.Module(body=node.body,type_ignores=[])
    return ast.dump(tree,show_empty=True) if sys.version_info>=(3,13) else ast.dump(tree)

@lru_cache(maxsize=32)
def source_syntax(text):
    # New runtimes may inherit -OO in ast.parse. Source identity includes
    # original docstrings; explicitly request the unoptimized syntax tree.
    return ast.parse(text,optimize=0) if sys.version_info>=(3,13) else ast.parse(text)

def declarations(text):
    tree=source_syntax(text)
    for n in tree.body:
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):yield n.name,n
        if isinstance(n,ast.ClassDef):
            for f in n.body:
                if isinstance(f,(ast.FunctionDef,ast.AsyncFunctionDef)):yield n.name+'.'+f.name,f

@lru_cache(maxsize=64)
def program_template(text,qualified,helpers):
    from source_bindings import require_static_definitions,require_static_class_members
    tree=source_syntax(text)
    selected=(qualified,*helpers)
    roots=set(name.split('.')[0] for name in selected)
    require_static_definitions(tree,roots)
    for cls in (n for n in tree.body if isinstance(n,ast.ClassDef) and n.name in roots):
        require_static_class_members(cls,[n.split('.')[1] for n in selected if n.startswith(cls.name+'.')])
    nodes=dict(declarations(text));program={}
    for name in (qualified,*helpers):
        node=deepcopy(nodes[name]);node._owner=name.rpartition('.')[0]
        node.name=name.replace('.','__')
        node.decorator_list=[] # Invocation begins at the explicitly supplied entry.
        walked=[n for stmt in node.body for n in ast.walk(stmt)]
        if len(walked)>6000:raise AdmissionError('selected complete body exceeds AST envelope','inconclusive')
        # All lookup/call execution is through the typed interpreter below.
        # Imports may occur in a dead configured branch; a reached import always
        # returns unknown. No bytecode,eval,exec or arbitrary host attributes exist.
        forbidden=(ast.While,ast.Delete,ast.Global,ast.Nonlocal,ast.ClassDef,ast.Lambda,ast.Yield,ast.YieldFrom)
        if any(isinstance(n,forbidden) for n in walked):raise AdmissionError('body requires an unadmitted semantic construct')
        program[node.name]=node
    return program,qualified.replace('.','__')

def program_for(text,qualified,helpers=()):
    # Admission may be shared for identical source/selection,execution AST and
    # all worlds remain fresh. This changes no semantic budget or observation.
    program,key=program_template(text,qualified,tuple(helpers))
    return deepcopy(program),key

class Interpreter(EffectInterpreter):
    def __init__(self,program,bindings,control=None):
        super().__init__(program,DataRecord('Unused',{}),bindings)
        self.frames=[];self.control=control
        self.bindings.update({n:ErrorType(n) for n in ('Exception','TypeError','ValueError','KeyError','UnicodeDecodeError','NotImplementedError','AttributeError')})
        self.bindings.update(len=Capability('bounded length',self.length),
            any=Capability('bounded existential',lambda x:any(self.truth(v) for v in self.sequence(x))),
            hasattr=Capability('declared field presence',lambda x,k:isinstance(x,DataRecord) and k in x.fields))
    def length(self,x):
        if isinstance(x,DataRecord) and x.kind=='Query':return len(x.fields['rows'])
        if type(x) in (tuple,list,dict,set,frozenset,str,bytes) and len(x)<=16384:return len(x)
        raise AdmissionError('length outside bounded data')
    def truth(self,x):
        if isinstance(x,DataRecord) and x.kind=='Query':return bool(x.fields['rows'])
        if type(x) is bytes:return bool(x)
        return super().truth(x)
    def invoke(self,fn,args,kwargs):
        if isinstance(fn,ErrorType) and fn.name=='HTTPException':
            if len(args)>1 or set(kwargs)-{'status_code','detail'}:raise AdmissionError('HTTP error signature outside profile')
            fault=SliceFault(fn.name,str(kwargs.get('detail','')))
            fault.status=kwargs.get('status_code',args[0] if args else None)
            return fault
        if isinstance(fn,Capability) and fn.asynchronous:
            self.charge()
            pending=Deferred(lambda:fn.callback(*args,**kwargs))
            pending.owned_call=(fn.name,tuple(args),dict(kwargs))
            return pending
        if not isinstance(fn,Closure):return super().invoke(fn,args,kwargs)
        self.charge();p=fn.function.args
        names=[a.arg for a in [*p.posonlyargs,*p.args]];kw_names=[a.arg for a in p.kwonlyargs]
        if len(args)>32 or len(kwargs)>32 or len(set(names+kw_names))!=len(names+kw_names):raise AdmissionError('source call outside argument envelope')
        if len(args)>len(names) and p.vararg is None:raise AdmissionError('too many positional arguments')
        bound=dict(zip(names,args));rest={}
        for k,v in kwargs.items():
            if k in bound:raise AdmissionError('duplicate source argument')
            if k in names+kw_names:bound[k]=v
            elif p.kwarg is not None:rest[k]=v
            else:raise AdmissionError('unknown source keyword')
        defaults=dict(zip(names[len(names)-len(p.defaults):],p.defaults))
        defaults.update(zip(kw_names,p.kw_defaults))
        for name in names+kw_names:
            if name not in bound:
                n=defaults.get(name)
                if not isinstance(n,ast.Constant):raise AdmissionError('entry default not explicitly supplied')
                bound[name]=n.value
        if p.vararg:bound[p.vararg.arg]=tuple(args[len(names):])
        if p.kwarg:bound[p.kwarg.arg]=rest
        local={**fn.environment,**bound}
        def execute():
            if self.depth>=16:raise AdmissionError('source depth exhausted','inconclusive')
            self.depth+=1;self.frames.append((fn.function._owner,bound.get('self')))
            self.function_calls[fn.function.name]=self.function_calls.get(fn.function.name,0)+1
            try:
                result=self.statements(fn.function.body,local)
                return result.value if isinstance(result,Return) else None
            finally:self.depth-=1;self.frames.pop()
        return Deferred(execute) if isinstance(fn.function,ast.AsyncFunctionDef) else execute()
    def sequence(self,x):
        if isinstance(x,DataRecord) and x.kind=='Query':return list(x.fields['rows'])
        return super().sequence(x)
    def equal(self,a,b):
        if isinstance(a,DataRecord) and isinstance(b,DataRecord):
            if a.kind!=b.kind:return False
            if a.kind not in ('User','Space','Project','Recipe','Actor','UserSource','Candidate'):
                return a is b
            ids=(a.fields.get('pk'),b.fields.get('pk'))
            if any(type(x) is not int or x<=0 for x in ids):raise AdmissionError('nominal equality requires persisted positive same-class keys')
            result=ids[0]==ids[1]
            return not result if self.control=='wrong_identity' else result
        if isinstance(a,DataRecord) or isinstance(b,DataRecord):return False
        if type(a) in (dict,list,tuple,set,frozenset) or type(b) in (dict,list,tuple,set,frozenset):
            if type(a)!=type(b):return False
            return a==b
        if a is None or b is None:return a is b
        if type(a) in (str,bool,int,bytes) and type(b) in (str,bool,int,bytes):return a==b
        raise AdmissionError('equality outside declared data domain')
    def value(self,n,env):
        self.charge()
        if isinstance(n,ast.JoinedStr):
            parts=[]
            for item in n.values:
                if isinstance(item,ast.FormattedValue):
                    if item.conversion!=-1 or item.format_spec is not None:raise AdmissionError('formatted conversion outside profile')
                    value=self.value(item.value,env)
                else:value=self.value(item,env)
                if isinstance(value,SliceFault):value=str(value)
                if value is not None and type(value) not in (str,bool,int):raise AdmissionError('interpolation needs bounded scalar or declared source fault')
                parts.append(str(value))
            result=''.join(parts)
            if len(result)>16384:raise AdmissionError('interpolation envelope','inconclusive')
            return result
        if isinstance(n,ast.Constant) and type(n.value) is bytes:return n.value
        if isinstance(n,ast.NamedExpr):
            if not isinstance(n.target,ast.Name):raise AdmissionError('named expression target not local')
            value=self.value(n.value,env);self.bind(n.target,value,env);return value
        if isinstance(n,ast.Attribute):
            x=self.value(n.value,env)
            if isinstance(x,DataRecord):
                if n.attr in x.fields:return x.fields[n.attr]
                raise AdmissionError('unbound source record field '+n.attr)
            if type(x) in (str,bytes) and n.attr in ('strip','lower','upper','split','startswith','partition','decode'):
                return Capability('bounded text '+n.attr,lambda *a,**k:self.text(x,n.attr,a,k))
            if type(x) is dict and n.attr in ('get','keys','pop'):
                return Capability('bounded mapping '+n.attr,lambda *a,**k:self.mapping(x,n.attr,a,k))
            if type(x) in (str,bytes,int,bool) or x is None:raise SliceFault('AttributeError','plain source value has no '+n.attr)
            raise AdmissionError('attribute outside declared data '+n.attr)
        if isinstance(n,ast.Subscript):
            x,k=self.value(n.value,env),self.value(n.slice,env)
            if type(x) is dict:
                if k not in x:raise SliceFault('KeyError',str(k))
                return x[k]
            if type(x) in (list,tuple,str,bytes) and type(k) is int and -len(x)<=k<len(x):return x[k]
            if x is None or type(x) in (int,bool):raise SliceFault('TypeError','plain value is not subscriptable')
            if type(x) in (list,tuple,str,bytes) and type(k) is int:raise SliceFault('IndexError','index outside sequence')
            raise AdmissionError('subscript outside bounded data')
        if isinstance(n,ast.BinOp) and isinstance(n.op,(ast.Add,ast.Sub,ast.Mult)):
            a,b=self.value(n.left,env),self.value(n.right,env)
            if isinstance(n.op,ast.Sub) and type(a) in (set,frozenset) and type(b) in (set,frozenset):return a-b
            if isinstance(n.op,ast.Add) and type(a)==type(b) and type(a) in (str,tuple,list):
                if len(a)+len(b)>16384:raise AdmissionError('concatenation envelope','inconclusive')
                return a+b
            if type(a) is int and type(b) is int:
                result=a+b if isinstance(n.op,ast.Add) else a-b if isinstance(n.op,ast.Sub) else a*b
                if result.bit_length()>64:raise AdmissionError('integer envelope','inconclusive')
                return result
            raise AdmissionError('binary operation outside typed profile')
        if isinstance(n,ast.Compare):
            left=self.value(n.left,env)
            for op,right_node in zip(n.ops,n.comparators):
                right=self.value(right_node,env)
                if isinstance(op,(ast.Eq,ast.NotEq)):ok=self.equal(left,right);ok=not ok if isinstance(op,ast.NotEq) else ok
                elif isinstance(op,(ast.Is,ast.IsNot)):ok=left is right;ok=not ok if isinstance(op,ast.IsNot) else ok
                elif isinstance(op,(ast.In,ast.NotIn)):
                    if type(right) not in (tuple,list,set,frozenset,dict,str,bytes):raise AdmissionError('membership domain unresolved')
                    ok=any(self.equal(left,r) for r in right) if type(right) in (tuple,list) else left in right
                    if isinstance(op,ast.NotIn):ok=not ok
                elif type(left)==type(right) and type(left) in (int,str,bytes):
                    ok={ast.Lt:lambda:left<right,ast.LtE:lambda:left<=right,ast.Gt:lambda:left>right,ast.GtE:lambda:left>=right}[type(op)]()
                else:raise AdmissionError('ordered comparison domain unresolved')
                if not ok:return False
                left=right
            return True
        if isinstance(n,ast.Call):
            fn=self.value(n.func,env);args=[];kwargs={}
            for v in n.args:args.extend(self.sequence(self.value(v.value,env))) if isinstance(v,ast.Starred) else args.append(self.value(v,env))
            for v in n.keywords:
                pairs=self.value(v.value,env) if v.arg is None else {v.arg:self.value(v.value,env)}
                if type(pairs) is not dict or any(type(k) is not str or k in kwargs for k in pairs):raise AdmissionError('expanded keyword domain unresolved')
                kwargs.update(pairs)
            from policy_slice import Call
            return self.call(fn,args,kwargs,env) if isinstance(fn,Call) else self.invoke(fn,args,kwargs)
        return super().value(n,env)
    def mapping(self,x,name,args,kwargs):
        if len(x)>128:raise AdmissionError('mapping envelope','inconclusive')
        if name=='keys' and not args and not kwargs:return list(x)
        if name in ('get','pop') and 1<=len(args)<=2:
            if kwargs and not(name=='get' and len(args)==1 and set(kwargs)=={'default'}):raise AdmissionError('mapping keyword unresolved')
            default=args[1] if len(args)==2 else kwargs.get('default')
            if name=='get':return x.get(args[0],default)
            return x.pop(args[0],default)
        raise AdmissionError('mapping method unresolved')
    def text(self,x,name,args,kwargs):
        if kwargs or len(x)>16384 or len(args)>2:raise AdmissionError('text method envelope')
        if name in ('strip','lower','upper') and not args:return getattr(x,name)()
        if name in ('split','startswith','partition') and len(args)<=1:return getattr(x,name)(*args)
        if name=='decode' and type(x) is bytes and args in ((),('utf-8',)):
            try:return x.decode('utf-8')
            except UnicodeDecodeError:raise SliceFault('UnicodeDecodeError')
        raise AdmissionError('text method unresolved')
    def error_matches(self,node,fault,env):
        if node is None:return True # only SliceFault reaches here,never AdmissionError
        if isinstance(node,ast.Tuple):return any(self.error_matches(t,fault,env) for t in node.elts)
        value=self.value(node,env)
        if not isinstance(value,ErrorType):raise AdmissionError('exception type has no declared binding')
        return value.name in (fault.name,'Exception')
    def statements(self,body,env):
        for n in body:
            self.charge()
            if isinstance(n,ast.Try):
                result=None
                try:result=self.statements(n.body,env)
                except SliceFault as fault:
                    handler=next((h for h in n.handlers if self.error_matches(h.type,fault,env)),None)
                    if handler is None:raise
                    if handler.name:env[handler.name]=fault
                    self.fault_stack.append(fault)
                    try:result=self.statements(handler.body,env)
                    finally:
                        self.fault_stack.pop()
                        if handler.name:env.pop(handler.name,None)
                else:
                    if not isinstance(result,Return):result=self.statements(n.orelse,env)
                if n.finalbody:raise AdmissionError('finally interface not admitted')
                if isinstance(result,Return):return result
            elif isinstance(n,ast.Raise):
                fault=self.value(n.exc,env) if n.exc is not None else self.fault_stack[-1] if self.fault_stack else None
                if isinstance(fault,ErrorType):fault=SliceFault(fault.name)
                if not isinstance(fault,SliceFault):raise AdmissionError('raise needs an explicit source error')
                if n.cause is not None:
                    cause=self.value(n.cause,env)
                    if cause is not None and not isinstance(cause,SliceFault):raise AdmissionError('source cause unresolved')
                raise fault
            elif isinstance(n,ast.AugAssign) and isinstance(n.op,ast.Add):
                if not isinstance(n.target,ast.Attribute):raise AdmissionError('addition target not a declared record field')
                x=self.value(n.target,env);y=self.value(n.value,env)
                if type(x) is not int or type(y) is not int or abs(x+y)>100000:raise AdmissionError('counter outside bounded profile')
                self.bind(n.target,x+y,env)
            elif isinstance(n,ast.Expr) and isinstance(n.value,ast.Call):
                value=self.value(n.value,env)
                if isinstance(value,Deferred):raise AdmissionError('discarded coroutine outside scheduler interface')
            elif isinstance(n,ast.With):
                if len(n.items)!=1 or n.items[0].optional_vars is not None:raise AdmissionError('context binding outside profile')
                context=self.value(n.items[0].context_expr,env)
                if isinstance(context,DataRecord) and context.kind=='MappedContext':
                    context.fields['enter']()
                    try:
                        try:result=self.statements(n.body,env)
                        finally:context.fields['exit']()
                    except SliceFault as fault:raise context.fields['translate'](fault)
                    if isinstance(result,Return):return result
                else:
                    # Re-evaluate no expression: put the already-bound protocol
                    # into a fresh local for the inherited serial context rule.
                    local='_owned_context';env[local]=context
                    replacement=deepcopy(n);replacement.items[0].context_expr=ast.Name(id=local,ctx=ast.Load())
                    try:result=super().statements([replacement],env)
                    finally:env.pop(local,None)
                    if isinstance(result,Return):return result
            elif isinstance(n,ast.ImportFrom):
                # A declared interface binding,not a host-language import.
                # No module loader,import hook or module initialization runs.
                aliases=tuple((a.name,a.asname) for a in n.names)
                imports=self.bindings.get('_declared_imports',{})
                binding=imports.get((n.module,n.level,aliases))
                if binding is None:raise AdmissionError('reached import has no exact declared dependency binding')
                env.update(binding)
            elif isinstance(n,ast.Import):raise AdmissionError('reached import is not an admitted operation')
            else:
                result=super().statements([n],env)
                if isinstance(result,Return):return result
        return None

    def call(self,fn,args,kwargs,env):
        from policy_slice import Call
        if isinstance(fn,Call) and fn.kind=='effect-builtin' and fn.value=='int' and len(args)==1 and not kwargs:
            value=args[0]
            if value is None or type(value) not in (str,int,bool):raise SliceFault('TypeError')
            if type(value) is str and len(value)>128:raise AdmissionError('integer conversion text envelope','inconclusive')
            try:converted=int(value)
            except ValueError:raise SliceFault('ValueError')
            if converted.bit_length()>64:raise AdmissionError('integer conversion result envelope','inconclusive')
            return converted
        return super().call(fn,args,kwargs,env)
