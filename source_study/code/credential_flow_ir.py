"""Bounded credential-flow interpreter;not a full-app verifier.

Bounded, non-eval data interpreter for selected credential-flow functions.

Only closed primitive dispatch may execute. Application AST is data, never
imported/compiled as Python. Native database and crypto operations are supplied
by an owned normal-data projection, not by the target application's modules.
"""
from dataclasses import dataclass


class Unsupported(Exception):
    """Analysis unknown,never a source-program ValueError/negative verdict."""
    pass
class QueryMiss(Exception):pass
class NotFound(Exception):pass


@dataclass
class Ref:
    name:str
    receiver:object=None


@dataclass
class Record:
    kind:str
    fields:dict


def expression(n):
    import ast
    if isinstance(n,ast.Constant) and type(n.value) in (str,int,bool,type(None)):return ['constant',n.value]
    if isinstance(n,ast.Name):return ['name',n.id]
    if isinstance(n,ast.Attribute):return ['attribute',expression(n.value),n.attr]
    if isinstance(n,ast.Dict):
        if any(k is None for k in n.keys):raise Unsupported('dictionary expansion')
        return ['dict',[[expression(k),expression(v)] for k,v in zip(n.keys,n.values)]]
    if isinstance(n,(ast.Tuple,ast.List)):return ['sequence',[expression(x) for x in n.elts]]
    if isinstance(n,ast.Subscript):
        if isinstance(n.slice,ast.Slice):
            if n.slice.step is not None:raise Unsupported('stepped slice')
            return ['slice',expression(n.value),expression(n.slice.lower) if n.slice.lower else ['constant',None],
                    expression(n.slice.upper) if n.slice.upper else ['constant',None]]
        return ['subscript',expression(n.value),expression(n.slice)]
    if isinstance(n,ast.UnaryOp) and isinstance(n.op,ast.Not):return ['not',expression(n.operand)]
    if isinstance(n,ast.BoolOp):return ['and' if isinstance(n.op,ast.And) else 'or',[expression(v) for v in n.values]]
    if isinstance(n,ast.Compare) and len(n.ops)==1 and type(n.ops[0]).__name__ in ('Eq','NotEq','In','NotIn','Is','IsNot'):
        return ['compare',type(n.ops[0]).__name__,expression(n.left),expression(n.comparators[0])]
    if isinstance(n,ast.BinOp) and isinstance(n.op,(ast.Add,ast.BitOr)):
        return ['add' if isinstance(n.op,ast.Add) else 'query_or',expression(n.left),expression(n.right)]
    if isinstance(n,ast.JoinedStr):
        pieces=[]
        for part in n.values:
            if isinstance(part,ast.Constant) and isinstance(part.value,str):pieces.append(['constant',part.value])
            elif isinstance(part,ast.FormattedValue) and part.conversion==-1 and part.format_spec is None:
                pieces.append(['string',expression(part.value)])
            else:raise Unsupported('unreviewed string format')
        return ['join',pieces]
    if isinstance(n,ast.Call):
        names={'len','str','isinstance','token_urlsafe','Q','error','_get_api_version','get_object_or_404','HttpResponseForbidden','JsonResponse','f'}
        methods={'startswith','split','encode','decode','hex','digest','compare_digest','loads','for_api_key','filter','get',
                 'compare_api_key','_make_api_key','to_dict'}
        if (isinstance(n.func,ast.Name) and n.func.id not in names or
                isinstance(n.func,ast.Attribute) and n.func.attr not in methods or
                not isinstance(n.func,(ast.Name,ast.Attribute))):raise Unsupported('unreviewed callable')
        args=[['expand',expression(a.value)] if isinstance(a,ast.Starred) else ['one',expression(a)] for a in n.args]
        return ['call',expression(n.func),args,[[k.arg,expression(k.value)] for k in n.keywords]]
    raise Unsupported('unreviewed expression: '+type(n).__name__)


def target(n):
    import ast
    if isinstance(n,ast.Name):return ['local',n.id]
    if isinstance(n,ast.Attribute):return ['field',expression(n.value),n.attr]
    if isinstance(n,(ast.Tuple,ast.List)) and all(isinstance(v,ast.Name) for v in n.elts):return ['unpack',[v.id for v in n.elts]]
    raise Unsupported('unreviewed assignment target')


def statements(nodes):
    import ast
    result=[]
    for n in nodes:
        if isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str):continue
        if isinstance(n,ast.Assign) and len(n.targets)==1:result.append(['assign',target(n.targets[0]),expression(n.value)])
        elif isinstance(n,ast.Return):result.append(['return',expression(n.value)])
        elif isinstance(n,ast.If):result.append(['if',expression(n.test),statements(n.body),statements(n.orelse)])
        elif isinstance(n,ast.For) and isinstance(n.target,ast.Name) and not n.orelse:
            result.append(['for',n.target.id,expression(n.iter),statements(n.body)])
        elif isinstance(n,ast.While) and isinstance(n.test,ast.Constant) and n.test.value is True and not n.orelse:
            result.append(['bounded_loop',statements(n.body)])
        elif isinstance(n,ast.Break):result.append(['break'])
        elif isinstance(n,ast.Pass):result.append(['pass'])
        elif isinstance(n,ast.Try) and not n.orelse and not n.finalbody:
            handlers=[]
            for h in n.handlers:
                if h.name or h.type is None:raise Unsupported('unbound exception handler')
                e=expression(h.type)
                if e not in (['name','ValueError'],['attribute',['name','Project'],'DoesNotExist']):raise Unsupported('unreviewed exception')
                handlers.append([e,statements(h.body)])
            result.append(['try',statements(n.body),handlers])
        else:raise Unsupported('unreviewed statement: '+type(n).__name__)
    return result


def compile_function(node):
    import ast
    if node.args.kwonlyargs or node.args.posonlyargs:raise Unsupported('unbound signature')
    parameters=[a.arg for a in node.args.args]
    defaults={a:expression(n) for a,n in zip(parameters[-len(node.args.defaults):],node.args.defaults)} if node.args.defaults else {}
    return dict(parameters=parameters,defaults=defaults,vararg=node.args.vararg.arg if node.args.vararg else None,
        kwarg=node.args.kwarg.arg if node.args.kwarg else None,body=statements(node.body),
        decorators_not_executed=True)


class Machine:
    def __init__(self,programs,globals,native):
        self.programs=programs;self.globals=globals;self.native=native;self.steps=0;self.depth=0

    def tick(self):
        self.steps+=1
        if self.steps>5000:raise Unsupported('finite step budget exceeded')

    def value(self,e,env):
        self.tick();tag=e[0]
        if tag=='constant':return e[1]
        if tag=='name':
            if e[1] in env:return env[e[1]]
            if e[1] not in self.globals:raise Unsupported('unbound name: '+e[1])
            return self.globals[e[1]]
        if tag=='attribute':
            obj=self.value(e[1],env);name=e[2]
            if isinstance(obj,Record):
                if name in obj.fields:return obj.fields[name]
                method=obj.kind+'.'+name
                if method in self.programs:return Ref(method,obj)
                return self.native.attribute(obj,name)
            if isinstance(obj,(str,bytes)) and name in ('startswith','split','encode','decode','hex'):
                return Ref('scalar.'+name,obj)
            raise Unsupported('unbound typed attribute')
        if tag=='dict':return {self.value(k,env):self.value(v,env) for k,v in e[1]}
        if tag=='sequence':return tuple(self.value(v,env) for v in e[1])
        if tag=='subscript':return self.value(e[1],env)[self.value(e[2],env)]
        if tag=='slice':return self.value(e[1],env)[self.value(e[2],env):self.value(e[3],env)]
        if tag=='not':return not self.value(e[1],env)
        if tag in ('and','or'):
            result=tag=='and'
            for child in e[1]:
                result=self.value(child,env)
                if (tag=='and' and not result) or (tag=='or' and result):return result
            return result
        if tag=='compare':
            a,b=self.value(e[2],env),self.value(e[3],env)
            if e[1]=='Eq':return a==b
            if e[1]=='NotEq':return a!=b
            if e[1]=='In':return a in b
            if e[1]=='NotIn':return a not in b
            if e[1]=='Is':return a is b
            if e[1]=='IsNot':return a is not b
        if tag=='add':return self.value(e[1],env)+self.value(e[2],env)
        if tag=='query_or':return self.native.query_or(self.value(e[1],env),self.value(e[2],env))
        if tag=='string':return str(self.value(e[1],env))
        if tag=='join':return ''.join(self.value(v,env) for v in e[1])
        if tag=='call':
            ref=self.value(e[1],env);args=[];kwargs={}
            for kind,child in e[2]:
                v=self.value(child,env)
                if kind=='expand':
                    if not isinstance(v,tuple):raise Unsupported('star argument is not supplied tuple')
                    args.extend(v)
                else:args.append(v)
            for name,child in e[3]:
                v=self.value(child,env)
                pairs=v if name is None else {name:v}
                if not isinstance(pairs,dict) or set(kwargs)&set(pairs):raise Unsupported('invalid keyword transfer')
                kwargs.update(pairs)
            return self.call(ref,args,kwargs)
        raise Unsupported('unknown expression data tag')

    def call(self,ref,args,kwargs=None):
        self.tick();kwargs=dict(kwargs or {})
        if not isinstance(ref,Ref):raise Unsupported('only closed function references callable')
        if ref.name not in self.programs:return self.native.call(ref,args,kwargs)
        if ref.receiver is not None:args=[ref.receiver]+list(args)
        p=self.programs[ref.name];env={};extra=args[len(p['parameters']):]
        if extra and p['vararg'] is None:raise Unsupported('extra positional arguments')
        for i,name in enumerate(p['parameters']):
            if i<len(args):
                if name in kwargs:raise Unsupported('duplicate parameter')
                env[name]=args[i]
            elif name in kwargs:env[name]=kwargs.pop(name)
            elif name in p['defaults']:env[name]=self.value(p['defaults'][name],{})
            else:raise Unsupported('missing parameter: '+name)
        if p['vararg']:env[p['vararg']]=tuple(extra)
        if kwargs and p['kwarg'] is None:raise Unsupported('extra keyword arguments')
        if p['kwarg']:env[p['kwarg']]=kwargs
        if self.depth>=12:raise Unsupported('finite call-depth budget exceeded')
        self.depth+=1
        try:
            state,value=self.block(p['body'],env)
            if state=='break':raise Unsupported('break escaped source loop')
            if hasattr(self.native,'on_source_return'):
                self.native.on_source_return(ref.name,value,env)
            return value
        finally:self.depth-=1

    def block(self,body,env):
        for n in body:
            self.tick();tag=n[0]
            if tag=='assign':
                t,v=n[1],self.value(n[2],env)
                if t[0]=='local':env[t[1]]=v
                elif t[0]=='unpack':
                    if len(v)!=len(t[1]):raise Unsupported('tuple transfer arity')
                    env.update(zip(t[1],v))
                else:
                    obj=self.value(t[1],env)
                    if not isinstance(obj,Record) or obj.kind not in ('Request','Project'):raise Unsupported('unreviewed mutation')
                    if t[2] not in ('json','project','readonly','v','api_key','api_key_readonly'):raise Unsupported('unreviewed field mutation')
                    obj.fields[t[2]]=v
            elif tag=='return':return 'return',self.value(n[1],env)
            elif tag=='break':return 'break',None
            elif tag=='if':
                state,v=self.block(n[2] if self.value(n[1],env) else n[3],env)
                if state:return state,v
            elif tag=='for':
                values=self.value(n[2],env)
                for i,v in enumerate(values):
                    if i>=32:raise Unsupported('finite database/iteration budget exceeded')
                    env[n[1]]=v;state,result=self.block(n[3],env)
                    if state=='return':return state,result
                    if state=='break':break
            elif tag=='bounded_loop':
                for _ in range(32):
                    state,v=self.block(n[1],env)
                    if state=='return':return state,v
                    if state=='break':break
                else:raise Unsupported('bounded producer loop not terminated')
            elif tag=='try':
                try:state,v=self.block(n[1],env)
                except (QueryMiss,ValueError) as error:
                    state=None;v=None;handled=False
                    for typ,body in n[2]:
                        if self.value(typ,env) is (QueryMiss if isinstance(error,QueryMiss) else ValueError):
                            state,v=self.block(body,env);handled=True;break
                    if not handled:raise
                if state:return state,v
            elif tag!='pass':raise Unsupported('unknown statement data tag')
        return None,None
