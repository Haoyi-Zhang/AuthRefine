"""Closed operational interpreter for reviewed delegated authorization bodies.

Source functions are data in the model arm and original compiled bodies in the
native arm. Both arms use separately initialized declared providers. An unknown
provider/model operation is not a target exception and cannot be caught by a
target's broad `except Exception` to become a misleading negative/pass.
"""
import ast,asyncio,builtins,copy,inspect,json,operator,sys
from contextlib import contextmanager
from contextvars import ContextVar
from collections import ChainMap
from types import SimpleNamespace
from predicate_runtime import body_identity

_unknowns=ContextVar('authrefine_unresolved_operations',default=None)
class Unknown(BaseException):
    def __init__(self,message):
        super().__init__(message)
        active=_unknowns.get()
        if active is not None:active.append(str(message))

@contextmanager
def capture_unknowns():
    """Unresolved operations stay inconclusive even if source cleanup returns."""
    messages=[];token=_unknowns.set(messages)
    try:yield messages
    finally:_unknowns.reset(token)
class Returned(BaseException):
    def __init__(self,value):self.value=value
class Broken(BaseException):pass
class Continued(BaseException):pass
UNBOUND=object()

class Frame(ChainMap):
    """Lexical locals do not fall back to globals before assignment."""
    def __getitem__(self,key):
        if key in self.maps[0]:
            value=self.maps[0][key]
            if value is UNBOUND:raise UnboundLocalError('local variable referenced before assignment:'+key)
            return value
        outer=self.maps[1]
        return outer.free(key) if isinstance(outer,Frame) else outer[key]
    def free(self,key):
        if key in self.maps[0]:
            value=self.maps[0][key]
            if value is UNBOUND:raise NameError('free variable referenced before assignment:'+key)
            return value
        outer=self.maps[1]
        return outer.free(key) if isinstance(outer,Frame) else outer[key]

def local_names(node):
    names={a.arg for a in [*node.args.posonlyargs,*node.args.args,*node.args.kwonlyargs]}
    if node.args.vararg:names.add(node.args.vararg.arg)
    if node.args.kwarg:names.add(node.args.kwarg.arg)
    class Bindings(ast.NodeVisitor):
        def visit_Name(self,n):
            if isinstance(n.ctx,ast.Store):names.add(n.id)
        def visit_FunctionDef(self,n):names.add(n.name)
        visit_AsyncFunctionDef=visit_FunctionDef
        def visit_ExceptHandler(self,n):
            if n.name:names.add(n.name)
            for s in n.body:self.visit(s)
        def visit_Import(self,n):
            names.update(a.asname or a.name.split('.')[0] for a in n.names)
        def visit_ImportFrom(self,n):names.update(a.asname or a.name for a in n.names)
        def visit_GeneratorExp(self,n):pass
        visit_ListComp=visit_GeneratorExp
        visit_SetComp=visit_GeneratorExp
        visit_DictComp=visit_GeneratorExp
    visitor=Bindings()
    for n in node.body:visitor.visit(n)
    return names

class Deferred:
    def __init__(self,work):self.work=work;self.state='pending'
    def resolve(self):
        if self.state!='pending':raise RuntimeError('cannot reuse already awaited coroutine')
        self.state='running'
        try:return self.work()
        finally:self.state='done'

def finish(v):
    if isinstance(v,Deferred):return v.resolve()
    if inspect.isawaitable(v):
        async def completed():return await v
        return asyncio.run(completed())
    return v

def await_value(v):
    if not isinstance(v,Deferred) and not inspect.isawaitable(v):raise TypeError('object cannot be used in await expression')
    return finish(v)

def keyword_arguments(**values):
    """Use the host's mapping/duplicate-key primitive,not an items() shortcut."""
    return values

class ModelFunction:
    def __init__(self,node,closure,vm):
        self.node=node;self.closure=closure;self.vm=vm
        a=node.args;pos=[*a.posonlyargs,*a.args]
        self.defaults={x.arg:vm.expr(v,closure) for x,v in zip(pos[-len(a.defaults):],a.defaults)} if a.defaults else {}
        self.kwdefaults={x.arg:vm.expr(v,closure) for x,v in zip(a.kwonlyargs,a.kw_defaults) if v is not None}
        self.local_names=local_names(node)
    def __call__(self,/,*args,**kwargs):
        local=self.bind(args,kwargs)
        return Deferred(lambda:self.run(local)) if isinstance(self.node,ast.AsyncFunctionDef) else self.run(local)
    def bind(self,args,kwargs):
        a=self.node.args;names=[x.arg for x in [*a.posonlyargs,*a.args]];only={x.arg for x in a.posonlyargs};known=set(names)|{x.arg for x in a.kwonlyargs};bound={};extras={}
        if len(args)>len(names) and not a.vararg:raise TypeError('too many arguments')
        for name,value in zip(names,args):bound[name]=value
        for name,value in kwargs.items():
            if name in only or name not in known:
                if not a.kwarg:raise TypeError('unexpected or positional-only keyword:'+name)
                extras[name]=value
            else:
                if name in bound:raise TypeError('multiple argument values')
                bound[name]=value
        for name in names:
            if name not in bound:
                if name not in self.defaults:raise TypeError('missing argument:'+name)
                bound[name]=self.defaults[name]
        for item in a.kwonlyargs:
            if item.arg not in bound:
                if item.arg not in self.kwdefaults:raise TypeError('missing keyword:'+item.arg)
                bound[item.arg]=self.kwdefaults[item.arg]
        if a.vararg:bound[a.vararg.arg]=tuple(args[len(names):])
        if a.kwarg:bound[a.kwarg.arg]=extras
        return {**dict.fromkeys(self.local_names,UNBOUND),**bound}
    def run(self,local):
        self.vm.tick();env=Frame(local,self.closure)
        try:self.vm.block(self.node.body,env)
        except Returned as r:return r.value
        return None

class Machine:
    def __init__(self,globals,allowed_imports=None):self.globals=globals;self.steps=0;self.allowed_imports=allowed_imports or {};self.exceptions=[]
    def tick(self):
        self.steps+=1
        if self.steps>20000:raise Unknown('operational step bound')
    def expr(self,n,e):
        self.tick()
        if n is None:return None
        if isinstance(n,ast.Constant):return n.value
        if isinstance(n,ast.Name):
            try:return e[n.id]
            except KeyError:raise Unknown('unbound name:'+n.id)
        if isinstance(n,ast.Attribute):
            if n.attr.startswith('__'):raise Unknown('hidden runtime attribute')
            obj=self.expr(n.value,e)
            try:return getattr(obj,n.attr)
            except AttributeError as ex:
                # Django's absent related-object exception also subclasses
                # AttributeError. It is a real application exception,not an
                # unresolved provider,as is an exception from a known property.
                missing=object()
                if type(ex) is not AttributeError or inspect.getattr_static(obj,n.attr,missing) is not missing:raise
                raise Unknown('missing provider/field:'+n.attr)
        if isinstance(n,ast.Subscript):return self.expr(n.value,e)[self.expr(n.slice,e)]
        if isinstance(n,ast.Slice):return slice(self.expr(n.lower,e),self.expr(n.upper,e),self.expr(n.step,e))
        if isinstance(n,(ast.List,ast.Tuple,ast.Set)):
            values=[]
            for child in n.elts:
                if isinstance(child,ast.Starred):values.extend(self.expr(child.value,e))
                else:values.append(self.expr(child,e))
            return {ast.List:list,ast.Tuple:tuple,ast.Set:set}[type(n)](values)
        if isinstance(n,ast.Dict):
            result={}
            for k,v in zip(n.keys,n.values):
                if k is None:
                    mapping=self.expr(v,e)
                    if not hasattr(mapping,'keys'):raise TypeError('dictionary expansion requires a mapping')
                    for key in mapping.keys():result[key]=mapping[key]
                else:
                    key=self.expr(k,e);value=self.expr(v,e);result[key]=value
            return result
        if isinstance(n,ast.UnaryOp):
            ops={ast.Not:operator.not_,ast.USub:operator.neg,ast.UAdd:operator.pos}
            if type(n.op) not in ops:raise Unknown('unary operation')
            return ops[type(n.op)](self.expr(n.operand,e))
        if isinstance(n,ast.BoolOp):
            for child in n.values:
                value=self.expr(child,e)
                if isinstance(n.op,ast.And) and not value or isinstance(n.op,ast.Or) and value:return value
            return value
        if isinstance(n,ast.IfExp):return self.expr(n.body if self.expr(n.test,e) else n.orelse,e)
        if isinstance(n,ast.BinOp):
            ops={ast.Add:operator.add,ast.Sub:operator.sub,ast.Mult:operator.mul,ast.Mod:operator.mod,ast.BitOr:operator.or_,ast.BitAnd:operator.and_}
            if type(n.op) not in ops:raise Unknown('binary operation')
            return ops[type(n.op)](self.expr(n.left,e),self.expr(n.right,e))
        if isinstance(n,ast.Compare):
            ops={ast.Eq:operator.eq,ast.NotEq:operator.ne,ast.Lt:operator.lt,ast.LtE:operator.le,ast.Gt:operator.gt,ast.GtE:operator.ge,ast.Is:operator.is_,ast.IsNot:operator.is_not,ast.In:lambda a,b:a in b,ast.NotIn:lambda a,b:a not in b}
            left=self.expr(n.left,e)
            for index,(op,rightnode) in enumerate(zip(n.ops,n.comparators)):
                right=self.expr(rightnode,e)
                if type(op) not in ops:raise Unknown('comparison')
                result=ops[type(op)](left,right)
                # Python preserves a rich-comparison object for the final
                # comparison (e.g. an ORM WHERE expression). Only a chained
                # intermediate result is truth-tested.
                if index==len(n.ops)-1 or not result:return result
                left=right
        if isinstance(n,ast.JoinedStr):
            parts=[]
            for child in n.values:
                if isinstance(child,ast.Constant):parts.append(child.value)
                elif isinstance(child,ast.FormattedValue):
                    value=self.expr(child.value,e)
                    if child.conversion==114:value=repr(value)
                    elif child.conversion==97:value=ascii(value)
                    elif child.conversion==115:value=str(value)
                    elif child.conversion!=-1:raise Unknown('format conversion')
                    parts.append(format(value,self.expr(child.format_spec,e) if child.format_spec else ''))
                else:raise Unknown('format component')
            return ''.join(parts)
        if isinstance(n,ast.Call):
            fn=self.expr(n.func,e);args=[];kwargs={}
            for a in n.args:
                if isinstance(a,ast.Starred):args.extend(self.expr(a.value,e))
                else:args.append(self.expr(a,e))
            for k in n.keywords:
                value=self.expr(k.value,e)
                if k.arg is None:kwargs=keyword_arguments(**kwargs,**value)
                else:
                    if k.arg in kwargs:raise TypeError('multiple keyword argument values')
                    kwargs[k.arg]=value
            return fn(*args,**kwargs)
        if isinstance(n,ast.Await):return await_value(self.expr(n.value,e))
        if isinstance(n,(ast.GeneratorExp,ast.ListComp,ast.SetComp)):
            if any(g.is_async for g in n.generators):raise Unknown('async comprehension')
            first=iter(self.expr(n.generators[0].iter,e))
            names={x.id for g in n.generators for x in ast.walk(g.target) if isinstance(x,ast.Name) and isinstance(x.ctx,ast.Store)}
            scope=Frame(dict.fromkeys(names,UNBOUND),e)
            def generate(index,env):
                if index==len(n.generators):yield self.expr(n.elt,env);return
                g=n.generators[index]
                values=first if index==0 else iter(self.expr(g.iter,env))
                for value in values:
                    self.assign(g.target,value,env)
                    if all(self.expr(cond,env) for cond in g.ifs):yield from generate(index+1,env)
            gen=generate(0,scope)
            return gen if isinstance(n,ast.GeneratorExp) else list(gen) if isinstance(n,ast.ListComp) else set(gen)
        raise Unknown('expression:'+type(n).__name__)
    def assign(self,n,v,e):
        if isinstance(n,ast.Name):e[n.id]=v
        elif isinstance(n,ast.Attribute):
            if n.attr.startswith('__'):raise Unknown('runtime mutation')
            setattr(self.expr(n.value,e),n.attr,v)
        elif isinstance(n,ast.Subscript):self.expr(n.value,e)[self.expr(n.slice,e)]=v
        elif isinstance(n,(ast.List,ast.Tuple)):
            values=list(v)
            if len(values)!=len(n.elts):raise ValueError('unpack arity')
            for child,value in zip(n.elts,values):self.assign(child,value,e)
        else:raise Unknown('assignment')
    def block(self,body,e):
        for n in body:
            self.tick()
            if isinstance(n,ast.Expr):self.expr(n.value,e)
            elif isinstance(n,ast.Return):raise Returned(self.expr(n.value,e))
            elif isinstance(n,ast.Assign):
                v=self.expr(n.value,e)
                for target in n.targets:self.assign(target,v,e)
            elif isinstance(n,ast.AnnAssign):
                if n.value is not None:self.assign(n.target,self.expr(n.value,e),e)
            elif isinstance(n,ast.AugAssign):
                ops={ast.Add:operator.iadd,ast.BitOr:operator.ior,ast.BitAnd:operator.iand}
                if type(n.op) not in ops:raise Unknown('in-place operation')
                if isinstance(n.target,ast.Name):
                    before=self.expr(n.target,e);value=ops[type(n.op)](before,self.expr(n.value,e));e[n.target.id]=value
                elif isinstance(n.target,ast.Attribute):
                    obj=self.expr(n.target.value,e);before=getattr(obj,n.target.attr);value=ops[type(n.op)](before,self.expr(n.value,e));setattr(obj,n.target.attr,value)
                elif isinstance(n.target,ast.Subscript):
                    obj=self.expr(n.target.value,e);key=self.expr(n.target.slice,e);before=obj[key];obj[key]=ops[type(n.op)](before,self.expr(n.value,e))
                else:raise Unknown('in-place target')
            elif isinstance(n,ast.If):self.block(n.body if self.expr(n.test,e) else n.orelse,e)
            elif isinstance(n,ast.For):
                broke=False
                for value in self.expr(n.iter,e):
                    self.assign(n.target,value,e)
                    try:self.block(n.body,e)
                    except Continued:continue
                    except Broken:broke=True;break
                if not broke:self.block(n.orelse,e)
            elif isinstance(n,ast.While):
                broke=False
                while self.expr(n.test,e):
                    self.tick()
                    try:self.block(n.body,e)
                    except Continued:continue
                    except Broken:broke=True;break
                if not broke:self.block(n.orelse,e)
            elif isinstance(n,ast.Break):raise Broken()
            elif isinstance(n,ast.Continue):raise Continued()
            elif isinstance(n,ast.Raise):
                if n.exc is None:
                    if not self.exceptions:raise RuntimeError('no active source exception')
                    raise self.exceptions[-1]
                raise self.expr(n.exc,e)
            elif isinstance(n,ast.Try):
                try:
                    try:self.block(n.body,e)
                    except Exception as ex:
                        for h in n.handlers:
                            if h.type is None or isinstance(ex,self.expr(h.type,e)):
                                if h.name:e[h.name]=ex
                                self.exceptions.append(ex)
                                try:self.block(h.body,e)
                                finally:
                                    self.exceptions.pop()
                                    if h.name:e[h.name]=UNBOUND
                                break
                        else:raise
                    else:self.block(n.orelse,e)
                finally:self.block(n.finalbody,e)
            elif isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):e[n.name]=ModelFunction(n,e,self)
            elif isinstance(n,ast.With):
                if len(n.items)!=1:raise Unknown('multiple context managers')
                manager=self.expr(n.items[0].context_expr,e);value=manager.__enter__()
                try:
                    if n.items[0].optional_vars:self.assign(n.items[0].optional_vars,value,e)
                    self.block(n.body,e)
                except BaseException as ex:
                    # Return/break are operational control flow,not exceptions
                    # that a context manager may suppress.
                    if isinstance(ex,(Returned,Broken,Continued)):
                        manager.__exit__(None,None,None);raise
                    if not manager.__exit__(type(ex),ex,ex.__traceback__):raise
                else:manager.__exit__(None,None,None)
            elif isinstance(n,ast.Assert):
                if not self.expr(n.test,e):raise AssertionError(self.expr(n.msg,e) if n.msg else '')
            elif isinstance(n,ast.Import):
                for alias in n.names:
                    if alias.name not in self.allowed_imports:raise Unknown('unadmitted import')
                    e[alias.asname or alias.name]=self.allowed_imports[alias.name]
            elif isinstance(n,ast.ImportFrom):
                key=f'{n.level}:{n.module}'
                if key not in self.allowed_imports:raise Unknown('unadmitted from import')
                module=self.allowed_imports[key]
                for alias in n.names:
                    if alias.name=='*':raise Unknown('wildcard import')
                    e[alias.asname or alias.name]=getattr(module,alias.name)
            elif isinstance(n,ast.Pass):pass
            else:raise Unknown('statement:'+type(n).__name__)

class EraseAnnotations(ast.NodeTransformer):
    def visit_arg(self,n):n.annotation=None;return n
    def visit_FunctionDef(self,n):
        n=self.generic_visit(n);n.returns=None;n.decorator_list=[]
        if hasattr(n,'type_params'):n.type_params=[]
        return n
    visit_AsyncFunctionDef=visit_FunctionDef

def parse_source(source):
    wrapped=source[:1].isspace();t=ast.parse(('if True:\n' if wrapped else '')+source)
    body=t.body[0].body if wrapped else t.body
    if len(body)!=1 or not isinstance(body[0],(ast.FunctionDef,ast.AsyncFunctionDef)):raise Unknown('function capsule required')
    return body[0]

def admit(row,allowed_imports):
    f=parse_source(row['source'])
    if body_identity(f.body)!=row['portable_body_sha256']:raise Unknown('original source body mismatch')
    if sum(1 for _ in ast.walk(f))>1800:raise Unknown('syntax envelope')
    forbidden=(ast.Global,ast.Nonlocal,ast.ClassDef,ast.Lambda,ast.AsyncFor,ast.AsyncWith,ast.Yield,ast.YieldFrom,ast.Delete,ast.NamedExpr)
    for n in ast.walk(f):
        if isinstance(n,forbidden):raise Unknown('unadmitted syntax:'+type(n).__name__)
        if isinstance(n,ast.While) and not row.get('reviewed_bounded_loop'):raise Unknown('unadmitted syntax:While')
        if isinstance(n,ast.Attribute) and n.attr.startswith('__'):raise Unknown('runtime introspection')
        if isinstance(n,ast.Name) and n.id.startswith('__'):raise Unknown('runtime binding')
        if isinstance(n,ast.Import) and any(a.name not in allowed_imports for a in n.names):raise Unknown('unadmitted import')
        if isinstance(n,ast.ImportFrom) and (f'{n.level}:{n.module}' not in allowed_imports or any(a.name=='*' for a in n.names)):raise Unknown('unadmitted from import')
    return EraseAnnotations().visit(f)

def install(rows,world,mode):
    globals=world.globals;globals.update(world.builtins)
    for row in rows:
        f=admit(row,world.allowed_imports)
        # Preserve literal defaults used by source-to-source helper calls.
        # Nonliteral dependency descriptors are metadata at the declared entry
        # boundary and replaced by None;their source edges are retained in the
        # separately extracted dependency graph,not executed as service calls.
        def safe_default(n):
            if n is None:return None
            try:ast.literal_eval(n);return n
            except (ValueError,TypeError):return ast.Constant(value=None)
        f.args.defaults=[safe_default(n) for n in f.args.defaults]
        f.args.kw_defaults=[safe_default(n) for n in f.args.kw_defaults]
        if mode=='native':
            env={**globals,'__builtins__':world.native_builtins()}
            module=ast.fix_missing_locations(ast.Module(body=[f],type_ignores=[]))
            exec(compile(module,'<reviewed-authorization-capsule>','exec',dont_inherit=True,optimize=0),env)
            fn=env[f.name]
        else:
            vm=Machine(globals,world.allowed_imports);fn=ModelFunction(f,globals,vm)
        globals[row['binding']]=fn
        # Keep global source function references live after later helper binds.
        if mode=='native':world.native_environments.append(env)
    for env in world.native_environments:env.update(globals)
    world.bind_source_methods(mode)
    for env in world.native_environments:env.update(globals)
    return globals
