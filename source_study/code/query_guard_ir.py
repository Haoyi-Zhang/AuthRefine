"""Closed source-query data IR, with explicit effect/identity boundaries.

No eval/exec or application import. Only complete straight-line query functions
are lowered; opaque helpers, conditionals, writes and unresolved calls abstain.
Authorization/token verification is an input obligation, not inferred here.
"""
import ast


class Unsupported(ValueError):
    pass


def dotted(n):
    if isinstance(n,ast.Name):return n.id
    if isinstance(n,ast.Attribute):return dotted(n.value)+'.'+n.attr
    raise Unsupported('nonliteral reference')


def compile_function(node, models, lookups=()):
    env={a.arg:['input',a.arg] for a in node.args.args}
    if node.args.vararg or node.args.kwarg or node.args.kwonlyargs or node.args.posonlyargs:
        raise Unsupported('unbound signature')
    def value(n):
        if isinstance(n,ast.Name) and n.id in env:return env[n.id]
        if isinstance(n,ast.Constant) and type(n.value) in (str,int,bool):return ['constant',n.value]
        if isinstance(n,ast.Attribute):
            if n.attr.startswith('_') and n.attr!='pk':raise Unsupported('private attribute')
            return ['attribute',value(n.value),n.attr]
        raise Unsupported('opaque scalar or effect')
    def query(n):
        if isinstance(n,ast.Name) and n.id in env and env[n.id][0] in ('all','filter','order','input_query'):
            return env[n.id]
        if not isinstance(n,ast.Call):raise Unsupported('query operation required')
        try:name=dotted(n.func)
        except Unsupported:name=None
        if name in lookups:
            if len(n.args)!=1 or not n.keywords:raise Unsupported('unbound lookup')
            return ['lookup',query(n.args[0]),keywords(n)]
        if not isinstance(n.func,ast.Attribute):raise Unsupported('opaque helper call')
        if n.func.attr not in ('all','filter','order_by'):raise Unsupported('unreviewed query primitive')
        try:base=dotted(n.func.value)
        except Unsupported:base=None
        if base in models:receiver=['all',models[base]]
        else:receiver=query(n.func.value)
        if n.func.attr=='all':
            if n.args or n.keywords:raise Unsupported('all arguments')
            return receiver
        if n.func.attr=='filter':
            if n.args or not n.keywords:raise Unsupported('nonliteral filter')
            return ['filter',receiver,keywords(n)]
        if n.keywords or not n.args or any(not isinstance(a,ast.Constant) or not isinstance(a.value,str) for a in n.args):
            raise Unsupported('nonliteral ordering')
        return ['order',receiver,[a.value for a in n.args]]
    def keywords(n):
        if any(k.arg is None or not all(p.isidentifier() for p in k.arg.split('__')) for k in n.keywords):
            raise Unsupported('unbound query keyword')
        return [[k.arg,value(k.value)] for k in n.keywords]
    for arg in node.args.args:
        if arg.arg=='queryset':env[arg.arg]=['input_query',arg.arg]
    statements=[n for n in node.body if not (isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str))]
    returned=None
    for i,n in enumerate(statements):
        if isinstance(n,(ast.Assign,ast.AnnAssign)):
            target=n.target if isinstance(n,ast.AnnAssign) else n.targets[0] if len(n.targets)==1 else None
            if not isinstance(target,ast.Name) or target.id in env:raise Unsupported('assignment aliases or rebinding')
            try:env[target.id]=query(n.value)
            except Unsupported:env[target.id]=value(n.value)
        elif isinstance(n,ast.Return) and i==len(statements)-1:
            returned=query(n.value)
        else:raise Unsupported('control flow or opaque side effect requires a separate contract')
    if returned is None:raise Unsupported('complete terminal query required')
    return dict(parameters=[a.arg for a in node.args.args],query=returned,
        decorator_and_default_dependency_execution='external binding obligation;not executed by IR')


def scalar(expr, env):
    tag=expr[0]
    if tag=='input':return env[expr[1]]
    if tag=='constant':return expr[1]
    if tag=='attribute':
        obj=scalar(expr[1],env)
        if not isinstance(obj,dict) or expr[2] not in obj:raise Unsupported('missing typed scalar field')
        return obj[expr[2]]
    raise Unsupported('unbound scalar IR')


def run_query(expr, env, relations):
    """Interpret using supplied primitive contracts (e.g. actual owned ORM).

    No source string controls an executable object/call. Primitive names in the
    finite IR are the only dispatch. ORM relation completeness is an obligation.
    """
    tag=expr[0]
    if tag=='all':return relations[expr[1]].all()
    if tag=='input_query':return env[expr[1]]
    if tag=='filter':return run_query(expr[1],env,relations).filter(**{k:scalar(v,env) for k,v in expr[2]})
    if tag=='order':return run_query(expr[1],env,relations).order_by(*expr[2])
    if tag=='lookup':return run_query(expr[1],env,relations).get(**{k:scalar(v,env) for k,v in expr[2]})
    raise Unsupported('unbound query IR')
