"""Closed data model and isolated original-body executor for reviewed predicates.

Only the explicit pure syntax below is admitted. No target module, decorator,
constructor, descriptor, database or application startup is imported/executed.
Typed values, Python short circuit returns, and missing fields are preserved.
"""
import ast,copy,hashlib,json,sys,textwrap,time
from types import SimpleNamespace

class Unsupported(Exception):pass
UNBOUND=object()
class Program(list):pass

def digest(data):return hashlib.sha256(data).hexdigest()

def body_identity(body):
    # ast.dump changed omission of empty optional fields between Python3.12
    # and3.14. Serialize fields explicitly; source bytes remain separately bound.
    def normalize(n):
        if isinstance(n,ast.AST):return [type(n).__name__,[[k,normalize(v)] for k,v in ast.iter_fields(n)]]
        if isinstance(n,list):return [normalize(v) for v in n]
        return n
    return digest(json.dumps(normalize(body),sort_keys=True,separators=(',',':')).encode())

def unpack(x):
    if isinstance(x,list):return [unpack(v) for v in x]
    if isinstance(x,dict):
        if set(x)=={'$record'}:
            if not all(k.isidentifier() and not k.startswith('_') for k in x['$record']):raise Unsupported('unsafe field')
            return SimpleNamespace(**{k:unpack(v) for k,v in x['$record'].items()})
        if set(x)=={'$tuple'}:return tuple(unpack(v) for v in x['$tuple'])
        if set(x)=={'$set'}:return set(unpack(v) for v in x['$set'])
        return {k:unpack(v) for k,v in x.items()}
    if type(x) in (str,int,bool,type(None)):return x
    raise Unsupported('fixture value')

def pack(x):
    if type(x) in (str,int,bool,type(None)):return {'type':type(x).__name__,'value':x}
    if type(x) in (list,tuple,set,frozenset):
        vals=[pack(v) for v in x]
        if type(x) in (set,frozenset):vals.sort(key=lambda v:json.dumps(v,sort_keys=True))
        return {'type':type(x).__name__,'value':vals}
    if type(x) is dict:
        if all(type(k) is str for k in x):return {'type':'dict','value':{k:pack(v) for k,v in sorted(x.items())}}
        entries=[[pack(k),pack(v)] for k,v in x.items()];entries.sort(key=lambda p:json.dumps(p[0],sort_keys=True))
        return {'type':'dict-items','value':entries}
    if type(x) is SimpleNamespace:return {'type':'record','value':{k:pack(v) for k,v in sorted(vars(x).items())}}
    raise Unsupported('unknown result type')

def expression(n):
    if isinstance(n,ast.Constant) and type(n.value) in (str,int,bool,type(None)):return ['literal',n.value]
    if isinstance(n,ast.Name) and not n.id.startswith('__'):return ['name',n.id]
    if isinstance(n,ast.Attribute) and not n.attr.startswith('_'):return ['field',expression(n.value),n.attr]
    if isinstance(n,ast.Subscript):return ['item',expression(n.value),expression(n.slice)]
    if isinstance(n,(ast.Tuple,ast.List,ast.Set)):return [type(n).__name__.lower(),[expression(v) for v in n.elts]]
    if isinstance(n,ast.Dict):
        if any(k is None for k in n.keys):raise Unsupported('dictionary expansion')
        return ['dict',[[expression(k),expression(v)] for k,v in zip(n.keys,n.values)]]
    if isinstance(n,ast.UnaryOp) and isinstance(n.op,ast.Not):return ['not',expression(n.operand)]
    if isinstance(n,ast.BoolOp) and isinstance(n.op,(ast.And,ast.Or)):return [type(n.op).__name__.lower(),[expression(v) for v in n.values]]
    if isinstance(n,ast.IfExp):return ['conditional',expression(n.test),expression(n.body),expression(n.orelse)]
    if isinstance(n,ast.Compare) and all(type(o).__name__ in ('Eq','NotEq','In','NotIn','Is','IsNot','Gt','GtE','Lt','LtE') for o in n.ops):
        return ['compare',[type(o).__name__ for o in n.ops],[expression(n.left),*[expression(v) for v in n.comparators]]]
    raise Unsupported('expression:'+type(n).__name__)

def statements(body):
    result=[]
    for n in body:
        if isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str):continue
        if isinstance(n,ast.Return):result.append(['return',expression(n.value) if n.value else ['literal',None]])
        elif isinstance(n,ast.If):result.append(['if',expression(n.test),statements(n.body),statements(n.orelse)])
        elif isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and not n.targets[0].id.startswith('__'):
            result.append(['assign',n.targets[0].id,expression(n.value)])
        elif isinstance(n,ast.Pass):result.append(['pass'])
        else:raise Unsupported('statement:'+type(n).__name__)
    return result

def parse_definition(source):
    # Preserve indentation inside multiline docstrings. textwrap.dedent would
    # change literal source content in an extracted class method.
    wrapped=source[:1].isspace()
    t=ast.parse(('if True:\n' if wrapped else '')+source)
    body=t.body[0].body if wrapped and len(t.body)==1 and isinstance(t.body[0],ast.If) else t.body
    if len(body)!=1 or not isinstance(body[0],ast.FunctionDef):raise Unsupported('single sync definition required')
    return body[0]

def compile_source(source):
    f=parse_definition(source)
    if f.args.vararg or f.args.kwarg or f.args.posonlyargs:raise Unsupported('signature')
    if sum(1 for _ in ast.walk(f))>300:raise Unsupported('syntax envelope')
    ir=Program(statements(f.body))
    ir.parameters={a.arg for a in [*f.args.args,*f.args.kwonlyargs]}
    ir.locals={n.id for s in f.body for n in ast.walk(s) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store)}
    # Defaults and annotations are outside the reviewed invocation body. Every
    # argument is explicit; nonliteral defaults are not evaluated or imported.
    for arg in [*f.args.args,*f.args.kwonlyargs]:arg.annotation=None
    f.returns=None;f.decorator_list=[];f.args.defaults=[]
    f.args.kw_defaults=[None for _ in f.args.kwonlyargs]
    if hasattr(f,'type_params'):f.type_params=[]
    return f,ir

def evaluate(e,env):
    tag=e[0]
    if tag=='literal':return e[1]
    if tag=='name':
        if e[1] not in env:raise Unsupported('unbound name:'+e[1])
        if env[e[1]] is UNBOUND:raise UnboundLocalError('local variable referenced before assignment:'+e[1])
        return env[e[1]]
    if tag=='field':
        obj=evaluate(e[1],env)
        if type(obj) is not SimpleNamespace:raise Unsupported('field receiver outside owned record')
        if e[2] not in vars(obj):raise Unsupported('missing field:'+e[2])
        return vars(obj)[e[2]]
    if tag=='item':return evaluate(e[1],env)[evaluate(e[2],env)]
    if tag in ('tuple','list','set'):
        vals=[evaluate(v,env) for v in e[1]]
        return {'tuple':tuple,'list':list,'set':set}[tag](vals)
    if tag=='dict':return {evaluate(k,env):evaluate(v,env) for k,v in e[1]}
    if tag=='not':return not evaluate(e[1],env)
    if tag=='conditional':return evaluate(e[2] if evaluate(e[1],env) else e[3],env)
    if tag in ('and','or'):
        for child in e[1]:
            value=evaluate(child,env)
            if (tag=='and' and not value) or (tag=='or' and value):return value
        return value
    if tag=='compare':
        left=evaluate(e[2][0],env)
        for op,node in zip(e[1],e[2][1:]):
            right=evaluate(node,env)
            if op=='Eq':ok=left==right
            elif op=='NotEq':ok=left!=right
            elif op=='In':ok=left in right
            elif op=='NotIn':ok=left not in right
            elif op=='Is':ok=left is right
            elif op=='IsNot':ok=left is not right
            elif op=='Gt':ok=left>right
            elif op=='GtE':ok=left>=right
            elif op=='Lt':ok=left<right
            elif op=='LtE':ok=left<=right
            if not ok:return False
            left=right
        return True
    raise Unsupported('unknown IR')

def execute(ir,env,initialize=True):
    if initialize and isinstance(ir,Program):
        for name in ir.locals-ir.parameters:env[name]=UNBOUND
    for s in ir:
        if s[0]=='return':return True,evaluate(s[1],env)
        if s[0]=='assign':env[s[1]]=evaluate(s[2],env)
        if s[0]=='if':
            returned,value=execute(s[2] if evaluate(s[1],env) else s[3],env,initialize=False)
            if returned:return True,value
    return False,None

def observation(call):
    try:value=call()
    except Unsupported as ex:return dict(status='unsupported',reason=str(ex))
    except Exception as ex:return dict(status='source_exception',exception=type(ex).__name__)
    try:return dict(status='value',result=pack(value))
    except Unsupported as ex:return dict(status='unsupported',reason=str(ex),phase='result_projection')
    except Exception as ex:return dict(status='harness_error',exception=type(ex).__name__,phase='result_projection')

def measure(payload):
    if len(payload['cases'])>80:raise ValueError('case envelope')
    rows=[]
    for case in payload['cases']:
        start=time.perf_counter_ns();f,ir=compile_source(case['source']);parse_ns=time.perf_counter_ns()-start
        actual_body=body_identity(f.body)
        if actual_body!=case['portable_body_sha256']:raise ValueError('original body changed')
        g={'__builtins__':{}}
        g.update(unpack(case.get('globals',{})))
        t=ast.fix_missing_locations(ast.Module(body=[f],type_ignores=[]))
        code=compile(t,'<source-bound-normal-predicate>','exec',dont_inherit=True)
        exec(code,g)
        names=[a.arg for a in [*f.args.args,*f.args.kwonlyargs]]
        observations=[];native_ns=0;model_ns=0
        for sample in case['inputs']:
            if set(sample['arguments'])!=set(names):raise ValueError('all original parameters must be explicit')
            native_args=unpack(sample['arguments']);model_args=unpack(sample['arguments'])
            before=pack(native_args);env={**unpack(case.get('globals',{})),**model_args}
            start=time.perf_counter_ns();native=observation(lambda:g[f.name](**native_args));native_ns+=time.perf_counter_ns()-start
            if pack(native_args)!=before:raise ValueError('unexpected input mutation')
            start=time.perf_counter_ns();model=observation(lambda:execute(ir,env)[1]);model_ns+=time.perf_counter_ns()-start
            observations.append(dict(id=sample['id'],native=native,model=model,expected=sample['expected'],
                native_model_agree=native==model,native_reference_agree=native==sample['expected']))
        rows.append(dict(id=case['id'],project=case['project'],function=case['function'],
            member=case['member'],line=case['line'],portable_body_sha256=actual_body,
            contexts=len(observations),observations=observations,
            shared_parse_ir_ns=parse_ns,native_observation_ns=native_ns,model_observation_ns=model_ns,
            entry_scope=case['entry_scope']))
    return dict(rows=rows,python=sys.version,uid=__import__('os').getuid(),
        application_imports=0,source_function_bodies_executed=True,
        decorators_constructors_frameworks_not_executed=True)

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('one readonly payload required')
    with open(sys.argv[1],encoding='utf-8') as h:payload=json.load(h)
    print(json.dumps(measure(payload),separators=(',',':')))
