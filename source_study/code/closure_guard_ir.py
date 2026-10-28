"""Closed source-guard IR over supplied typed relationship observations.

AST is compiled to data,never eval/exec/imported as application code. Only
declared total field reads,finite comprehensions,builtins,403 denial/logging and
an explicitly supplied immutable native enforcer are modeled. This is not JWT,
ORM,DI,cache/deployment or a general Python soundness claim.
"""
import ast
import copy
import json


class Unsupported(ValueError):pass
class Unresolved(ValueError):pass
ENFORCER=object()


def expression(n):
    if isinstance(n,ast.Constant) and type(n.value) in (str,int,bool,type(None)):return ['constant',n.value]
    if isinstance(n,ast.Name):return ['name',n.id]
    if isinstance(n,ast.Attribute):return ['field',expression(n.value),n.attr]
    if isinstance(n,(ast.Tuple,ast.List,ast.Set)):return [type(n).__name__.lower(),[expression(v) for v in n.elts]]
    if isinstance(n,ast.UnaryOp) and isinstance(n.op,ast.Not):return ['not',expression(n.operand)]
    if isinstance(n,ast.BoolOp):return ['and' if isinstance(n.op,ast.And) else 'or',[expression(v) for v in n.values]]
    if isinstance(n,ast.Compare) and len(n.ops)==1 and isinstance(n.ops[0],(ast.In,ast.NotIn,ast.Eq,ast.NotEq)):
        return [type(n.ops[0]).__name__.lower(),expression(n.left),expression(n.comparators[0])]
    if isinstance(n,(ast.GeneratorExp,ast.SetComp,ast.ListComp)):
        generators=[]
        for g in n.generators:
            if g.is_async or not isinstance(g.target,ast.Name) or g.ifs:raise Unsupported('only finite unfiltered name comprehensions admitted')
            generators.append([g.target.id,expression(g.iter)])
        return ['generator' if isinstance(n,ast.GeneratorExp) else 'setcomp' if isinstance(n,ast.SetComp) else 'listcomp',expression(n.elt),generators]
    if isinstance(n,ast.JoinedStr):
        parts=[]
        for v in n.values:
            if isinstance(v,ast.Constant):parts.append(['constant',v.value])
            elif isinstance(v,ast.FormattedValue) and v.conversion==-1 and v.format_spec is None:parts.append(expression(v.value))
            else:raise Unsupported('format conversion or spec unmodeled')
        return ['format',parts]
    if isinstance(n,ast.Call):
        if n.keywords:raise Unsupported('expression call keywords unmodeled')
        if isinstance(n.func,ast.Name) and n.func.id in ('any','all') and len(n.args)==1:return [n.func.id,expression(n.args[0])]
        if isinstance(n.func,ast.Name) and n.func.id=='_get_enforcer' and not n.args:return ['enforcer']
        if isinstance(n.func,ast.Attribute) and n.func.attr=='enforce' and len(n.args)==4:
            return ['native_enforce',expression(n.func.value),[expression(a) for a in n.args]]
        if isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Constant) and type(n.func.value.value) is str and n.func.attr=='join' and len(n.args)==1:
            return ['join',n.func.value.value,expression(n.args[0])]
    raise Unsupported('expression outside closed source guard grammar: '+type(n).__name__)


def target(n):
    if isinstance(n,ast.Name):return n.id
    if isinstance(n,(ast.Tuple,ast.List)) and all(isinstance(v,ast.Name) for v in n.elts):return [v.id for v in n.elts]
    raise Unsupported('assignment target is not a local name/flat unpack')


def statements(nodes):
    out=[]
    for n in nodes:
        if isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and type(n.value.value) is str:continue
        if isinstance(n,ast.Assign) and len(n.targets)==1:out.append(['assign',target(n.targets[0]),expression(n.value)])
        elif isinstance(n,ast.Return) and n.value is not None:out.append(['return',expression(n.value)])
        elif isinstance(n,ast.If):out.append(['if',expression(n.test),statements(n.body),statements(n.orelse)])
        elif isinstance(n,ast.For) and isinstance(n.target,ast.Name) and not n.orelse:
            out.append(['for',n.target.id,expression(n.iter),statements(n.body)])
        elif isinstance(n,ast.Raise) and n.cause is None and isinstance(n.exc,ast.Call) and isinstance(n.exc.func,ast.Name) and n.exc.func.id=='HTTPException' and not n.exc.args:
            kwargs={k.arg:k.value for k in n.exc.keywords}
            if (set(kwargs)-{'status_code','detail'} or 'status_code' not in kwargs
                    or not isinstance(kwargs['status_code'],ast.Constant) or kwargs['status_code'].value!=403):raise Unsupported('only explicit403 denial admitted')
            out.append(['deny',expression(kwargs.get('detail',ast.Constant(value='')))])
        elif (isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute)
                and isinstance(n.value.func.value,ast.Name) and n.value.func.value.id=='logger' and n.value.func.attr=='warning'
                and not n.value.keywords and len(n.value.args)==1):out.append(['warning',expression(n.value.args[0])])
        else:raise Unsupported('statement outside closed source guard grammar: '+type(n).__name__)
    return out


def compile_guard(node,captures,constants=None):
    if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) or node.decorator_list:raise Unsupported('undecorated selected closure required')
    if sum(1 for _ in ast.walk(node))>1500:raise Unsupported('guard source envelope exceeded')
    a=node.args
    if a.vararg or a.kwarg or a.kwonlyargs or a.posonlyargs:raise Unsupported('selected supplied argument interface unmodeled')
    constants=constants or {}
    if constants:
        class Constants(ast.NodeTransformer):
            def visit_Attribute(self,n):
                key=ast.unparse(n)
                return ast.copy_location(ast.Constant(value=constants[key]),n) if key in constants else self.generic_visit(n)
        node=Constants().visit(copy.deepcopy(node))
    values={}
    for name,b in captures.items():
        try:value=ast.literal_eval(b['expression'])
        except (ValueError,SyntaxError):raise Unsupported('nonliteral captured value needs a separate producer contract')
        if not (type(value) is str or type(value) in (list,tuple) and all(type(v) is str for v in value)):raise Unsupported('bounded string captures only')
        if len(value)>256:raise Unsupported('capture bound exceeded')
        values[name]=value
    program=dict(arguments=[p.arg for p in a.args],captures=values,statements=statements(node.body),
        source_line=node.lineno,source_end_line=node.end_lineno,async_body_projection=isinstance(node,ast.AsyncFunctionDef),
        source_constant_substitutions=constants,
        assumptions=['complete immutable finite JSON principal/relationship observations','ordinary typed attribute reads with no ORM/lazy getters',
            'Python any/all and collection membership under source builtin bindings','source403 exception and source logger.warning are total declared effects',
            'optional supplied native enforcer equals bound source model/policy for this call','DI/current-user/token validation and concurrent mutation are outside this slice'])
    json.dumps(program);return program


class Machine:
    def __init__(self,native=None):self.native=native;self.work=0;self.native_calls=[];self.warnings=[]
    def tick(self):
        self.work+=1
        if self.work>20000:raise Unresolved('finite source guard budget exhausted')
    def values(self,e,env):
        def rec(i,scope):
            if i==len(e[2]):yield self.value(e[1],scope);return
            name,items=e[2][i];seq=self.value(items,scope)
            if type(seq) not in (list,tuple,frozenset):raise Unresolved('comprehension input is not a finite typed collection')
            for item in seq:
                self.tick();new=dict(scope);new[name]=item;yield from rec(i+1,new)
        return rec(0,env)
    def value(self,e,env):
        self.tick();op=e[0]
        if op=='constant':return e[1]
        if op=='name':
            if e[1] not in env:raise Unresolved('source name unbound: '+e[1])
            return env[e[1]]
        if op=='field':
            v=self.value(e[1],env)
            if type(v) is not dict or e[2] not in v:raise Unresolved('complete ordinary field observation required')
            return v[e[2]]
        if op in ('tuple','list','set'):return {'tuple':tuple,'list':list,'set':frozenset}[op](self.value(v,env) for v in e[1])
        if op=='not':return not bool(self.value(e[1],env))
        if op in ('and','or'):
            result=True if op=='and' else False
            for v in e[1]:
                result=self.value(v,env)
                if (op=='and' and not result) or (op=='or' and result):break
            return result
        if op in ('in','notin','eq','noteq'):
            a,b=self.value(e[1],env),self.value(e[2],env)
            return (a in b) if op=='in' else (a not in b) if op=='notin' else (a==b) if op=='eq' else (a!=b)
        if op=='generator':return self.values(e,env)
        if op in ('setcomp','listcomp'):return (frozenset if op=='setcomp' else list)(self.values(e,env))
        if op in ('any','all'):
            seq=self.value(e[1],env)
            return (any if op=='any' else all)(seq)
        if op=='format':return ''.join(str(self.value(v,env)) for v in e[1])
        if op=='join':
            items=self.value(e[2],env)
            if type(items) not in (list,tuple) or not all(type(v) is str for v in items):raise Unresolved('join requires supplied string sequence')
            return e[1].join(items)
        if op=='enforcer':
            if self.native is None:raise Unresolved('bound native enforcer absent')
            return ENFORCER
        if op=='native_enforce':
            if self.value(e[1],env) is not ENFORCER or self.native is None:raise Unresolved('native enforcer object identity unresolved')
            args=[self.value(v,env) for v in e[2]]
            if not all(type(v) is str for v in args):raise Unresolved('native request fields must be observed strings')
            try:result=self.native(*args)
            except Exception as error:raise Unresolved('bound native primitive failed: '+type(error).__name__) from error
            if type(result) is not bool:raise Unresolved('native decision is not Boolean')
            self.native_calls.append(dict(arguments=args,decision=result));return result
        raise Unresolved('unknown IR opcode')
    def run(self,code,env):
        for instruction in code:
            self.tick();op=instruction[0]
            if op=='assign':
                value=self.value(instruction[2],env);name=instruction[1]
                if type(name) is str:env[name]=value
                else:
                    if type(value) not in (list,tuple) or len(value)!=len(name):raise Unresolved('unpack shape differs')
                    env.update(zip(name,value))
            elif op=='if':
                result=self.run(instruction[2] if self.value(instruction[1],env) else instruction[3],env)
                if result is not None:return result
            elif op=='for':
                seq=self.value(instruction[2],env)
                if type(seq) not in (list,tuple,frozenset):raise Unresolved('loop requires finite observed collection')
                for item in seq:
                    self.tick();env[instruction[1]]=item;result=self.run(instruction[3],env)
                    if result is not None:return result
            elif op=='return':return dict(decision='allow',returned_value=self.value(instruction[1],env))
            elif op=='deny':self.value(instruction[1],env);return dict(decision='deny',status_code=403)
            elif op=='warning':self.warnings.append(self.value(instruction[1],env))
            else:raise Unresolved('unknown statement opcode')
        return None


def evaluate(program,arguments,native=None):
    m=Machine(native)
    try:
        if set(arguments)!=set(program['arguments']) or set(arguments)&set(program['captures']):raise Unresolved('argument/capture identity differs')
        # JSON round-trip forbids objects with overloaded getters/operators.
        supplied=json.loads(json.dumps(arguments,allow_nan=False));env={**program['captures'],**supplied}
        result=m.run(program['statements'],env)
        if result is None:raise Unresolved('fallthrough not a declared permission decision')
        result.update(work=m.work,native_calls=m.native_calls,total_warning_effects=len(m.warnings));return result
    except (Unresolved,TypeError,KeyError,ValueError,OverflowError) as e:
        return dict(decision='unknown',reason=str(e),work=m.work,native_calls=m.native_calls)
