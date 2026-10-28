"""Closed data interpreter for source DRF permission slices, not Python exec.

Only selected AST functions, inherited literal class attributes, pure boolean
operators, optional mapping reads and source-bound relational EXISTS are
admitted. It does not load Django, target modules, HTTP, credentials or services.
"""
import ast
from dataclasses import dataclass
import sqlite3


class Unsupported(ValueError):pass
class Unknown(ValueError):pass


def expression(n):
    if isinstance(n,ast.Constant) and type(n.value) in (str,int,bool,type(None)):return ['literal',n.value]
    if isinstance(n,ast.Name):return ['name',n.id]
    if isinstance(n,ast.Attribute):return ['field',expression(n.value),n.attr]
    if isinstance(n,(ast.Tuple,ast.List,ast.Set)):return ['sequence',[expression(v) for v in n.elts]]
    if isinstance(n,ast.BoolOp):return ['and' if isinstance(n.op,ast.And) else 'or',[expression(v) for v in n.values]]
    if isinstance(n,ast.UnaryOp) and isinstance(n.op,ast.Not):return ['not',expression(n.operand)]
    if isinstance(n,ast.Compare) and len(n.ops)==1 and isinstance(n.ops[0],(ast.Eq,ast.NotEq,ast.In,ast.NotIn)):
        return [type(n.ops[0]).__name__.lower(),expression(n.left),expression(n.comparators[0])]
    if isinstance(n,ast.Call):
        if isinstance(n.func,ast.Name) and n.func.id in ('bool','getattr','frozenset') and not n.keywords:
            arity={'bool':(1,),'getattr':(3,),'frozenset':(1,)}[n.func.id]
            if len(n.args) not in arity:raise Unsupported('bounded builtin signature differs')
            return [n.func.id,[expression(v) for v in n.args]]
        if isinstance(n.func,ast.Attribute) and n.func.attr=='get' and len(n.args) in (1,2) and not n.keywords:
            return ['get',expression(n.func.value),[expression(v) for v in n.args]]
        if isinstance(n.func,ast.Attribute) and n.func.attr=='exists' and not n.args and not n.keywords:
            query=n.func.value
            if not (isinstance(query,ast.Call) and isinstance(query.func,ast.Attribute) and query.func.attr=='filter' and not query.args
                    and query.keywords and all(k.arg is not None for k in query.keywords)):
                raise Unsupported('only a single source filter(...).exists() admitted')
            keys=[k.arg for k in query.keywords]
            if len(keys)!=len(set(keys)):raise Unsupported('duplicate relational filter key')
            return ['exists',expression(query.func.value),[[k.arg,expression(k.value)] for k in query.keywords]]
        if isinstance(n.func,ast.Attribute) and n.func.attr in ('get_project_id','has_role','has_permission','has_object_permission') and not n.keywords:
            return ['call',expression(n.func.value),n.func.attr,[expression(v) for v in n.args]]
    raise Unsupported('expression is outside declared permission grammar: '+ast.dump(n,include_attributes=False)[:180])


def statements(nodes):
    result=[]
    for n in nodes:
        if isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str):continue
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
            result.append(['assign',n.targets[0].id,expression(n.value)])
        elif isinstance(n,ast.Return) and n.value is not None:result.append(['return',expression(n.value)])
        elif isinstance(n,ast.If):result.append(['if',expression(n.test),statements(n.body),statements(n.orelse)])
        else:raise Unsupported('effectful/unmodeled statement: '+type(n).__name__)
    return result


def method(n):
    if not isinstance(n,ast.FunctionDef) or any(not isinstance(d,ast.Name) or d.id!='classmethod' for d in n.decorator_list):
        raise Unsupported('only ordinary methods or classmethod projections')
    if n.args.vararg or n.args.kwarg or n.args.kwonlyargs or n.args.posonlyargs or n.args.defaults:
        raise Unsupported('method argument binding outside finite interface')
    return dict(arguments=[a.arg for a in n.args.args],body=statements(n.body),line=n.lineno,end_line=n.end_lineno)


def compile_class(node,selected_methods=None):
    if node.decorator_list:raise Unsupported('decorated class not admitted')
    bases=[ast.unparse(n) for n in node.bases]
    if len(bases)>1:raise Unsupported('multiple inheritance unmodeled')
    result=dict(base=bases[0].rsplit('.',1)[-1] if bases else None,attributes={},methods={},line=node.lineno,end_line=node.end_lineno)
    for n in node.body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
            if n.targets[0].id in result['attributes']:raise Unsupported('duplicate class attribute')
            result['attributes'][n.targets[0].id]=expression(n.value)
        elif isinstance(n,ast.FunctionDef) and (selected_methods is None or n.name in selected_methods):
            if n.name in result['methods']:raise Unsupported('duplicate method definition')
            result['methods'][n.name]=method(n)
        elif isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str) or isinstance(n,ast.Pass):continue
        elif isinstance(n,ast.FunctionDef) and selected_methods is not None:continue
        else:raise Unsupported('unmodeled class declaration')
    return result


@dataclass(frozen=True)
class User:
    id:int
    authenticated:bool
    superuser:bool
    # Django persisted-user equality is projected onto the supplied same-model
    # primary key. Attribute changes do not create a different user identity.
    def __eq__(self,other):return isinstance(other,User) and self.id==other.id


@dataclass
class Handle:
    name:str
    fields:dict


class Machine:
    def __init__(self,program,rows,labels=()):
        self.p=program;self.work=0;self.queries=[];self.calls=[]
        self.db=sqlite3.connect(':memory:')
        self.db.execute('CREATE TABLE member(project INTEGER,user INTEGER,role TEXT,UNIQUE(project,user))')
        self.db.execute('CREATE TABLE label(id INTEGER,user INTEGER,UNIQUE(id,user))')
        self.db.executemany('INSERT INTO member VALUES(?,?,?)',rows)
        self.db.executemany('INSERT INTO label VALUES(?,?)',labels)
        self.globals=dict(SAFE_METHODS=program['safe_methods'],permissions={'SAFE_METHODS':program['safe_methods']},
            settings=program['settings'],Member={'objects':Handle('MemberManager',{'query_kind':'member'})})
    def close(self):self.db.close()
    def tick(self):
        self.work+=1
        if self.work>10000:raise Unknown('finite permission evaluation budget exceeded')
    def attr(self,obj,key,default=...):
        if isinstance(obj,User):
            fields={'id':obj.id,'is_authenticated':obj.authenticated,'is_superuser':obj.superuser}
        elif isinstance(obj,Handle):
            if key in obj.fields:return obj.fields[key]
            name=obj.name;seen=set()
            while name is not None:
                if name in seen or name not in self.p['classes']:raise Unknown('class inheritance unresolved')
                seen.add(name);c=self.p['classes'][name]
                if key in c['attributes']:return self.value(c['attributes'][key],self.globals)
                name=c['base']
            fields={}
        elif type(obj) is dict:fields=obj
        else:raise Unknown('typed field read unavailable')
        if key in fields:return fields[key]
        if default is not ...:return default
        raise Unknown('required supplied field missing: '+key)
    def value(self,e,env):
        self.tick();op=e[0]
        if op=='literal':return e[1]
        if op=='name':
            if e[1] not in env:raise Unknown('source name not bound: '+e[1])
            return env[e[1]]
        if op=='field':return self.attr(self.value(e[1],env),e[2])
        if op=='sequence':return tuple(self.value(v,env) for v in e[1])
        if op in ('and','or'):
            answer=None
            for v in e[1]:
                answer=self.value(v,env)
                if op=='and' and not answer or op=='or' and answer:return answer
            return answer
        if op=='not':return not self.value(e[1],env)
        if op in ('eq','noteq','in','notin'):
            a=self.value(e[1],env);b=self.value(e[2],env)
            return a==b if op=='eq' else a!=b if op=='noteq' else a in b if op=='in' else a not in b
        if op in ('bool','getattr','frozenset'):
            args=[self.value(v,env) for v in e[1]]
            return bool(args[0]) if op=='bool' else frozenset(args[0]) if op=='frozenset' else self.attr(*args)
        if op=='get':
            value=self.value(e[1],env);args=[self.value(v,env) for v in e[2]]
            if type(value) is not dict:raise Unknown('optional lookup requires supplied mapping')
            return value.get(*args)
        if op=='call':return self.call(self.value(e[1],env),e[2],[self.value(v,env) for v in e[3]])
        if op=='exists':
            holder=self.value(e[1],env);kind=self.attr(holder,'query_kind')
            predicates={k:self.value(v,env) for k,v in e[2]}
            allowed={'member':{'project':'project','user':'user','role__name':'role'},'label':{'id':'id','user':'user'}}
            if kind not in allowed or set(predicates)!=set(allowed[kind]):raise Unknown('complete bound relation key set required')
            params=[];columns=[]
            for key,value in predicates.items():
                if key=='user':
                    if not isinstance(value,User):raise Unknown('supplied persisted user identity required')
                    value=value.id
                if type(value) not in (str,int,type(None)):raise Unknown('typed relation scalar required')
                params.append(value);columns.append(allowed[kind][key]+' = ?')
            query='SELECT EXISTS(SELECT 1 FROM '+kind+' WHERE '+' AND '.join(columns)+')'
            result=bool(self.db.execute(query,params).fetchone()[0]);self.queries.append(dict(relation=kind,predicates=dict(zip(predicates,params)),result=result))
            return result
        raise Unknown('unknown data instruction')
    def block(self,items,env):
        for op in items:
            if op[0]=='assign':env[op[1]]=self.value(op[2],env)
            elif op[0]=='return':return True,self.value(op[1],env)
            elif op[0]=='if':
                done,value=self.block(op[2] if self.value(op[1],env) else op[3],env)
                if done:return True,value
            else:raise Unknown('unmodeled statement')
        return False,None
    def call(self,holder,name,args):
        self.tick()
        if not isinstance(holder,Handle):raise Unknown('source method receiver not bound')
        cls=holder.name;seen=set()
        while cls is not None:
            if cls in seen or cls not in self.p['classes']:raise Unknown('method class unknown')
            seen.add(cls);definition=self.p['classes'][cls]
            if name in definition['methods']:
                m=definition['methods'][name]
                if len(m['arguments'])!=len(args)+1:raise Unknown('method argument count differs')
                self.calls.append([holder.name,cls,name]);env={**self.globals,**dict(zip(m['arguments'],[holder,*args]))}
                done,value=self.block(m['body'],env)
                if not done:raise Unknown('missing explicit permission return')
                return value
            cls=definition['base']
        raise Unknown('permission method unavailable')
    def permission(self,tree,request,view,obj=None,phase='has_permission'):
        if isinstance(tree,str):holder=Handle(tree,{})
        else:holder=Handle(tree[0],{'op1':self.handle(tree[1]),'op2':self.handle(tree[2])})
        args=[request,view] if phase=='has_permission' else [request,view,obj]
        return bool(self.call(holder,phase,args))
    def handle(self,tree):
        return Handle(tree,{}) if isinstance(tree,str) else Handle(tree[0],dict(op1=self.handle(tree[1]),op2=self.handle(tree[2])))


def supplied_case(value):
    def user(v):return None if v is None else User(v['id'],v['is_authenticated'],v['is_superuser'])
    request=dict(value['request']);request['user']=user(request['user'])
    obj=dict(value.get('object',{}))
    if 'user' in obj:obj['user']=user(obj['user'])
    return request,dict(value['view']),obj


def evaluate(program,tree,case,object_stage=False):
    machine=None
    try:
        request,view,obj=supplied_case(case);machine=Machine(program,case.get('members',()),case.get('labels',()))
        granted=machine.permission(tree,request,view)
        if granted and object_stage:granted=machine.permission(tree,request,view,obj,'has_object_permission')
        return dict(decision='allow' if granted else 'deny',query_calls=machine.queries,source_method_calls=machine.calls)
    except (Unknown,KeyError,TypeError,sqlite3.Error) as error:
        return dict(decision='unknown',reason=type(error).__name__+': '+str(error),query_calls=[] if machine is None else machine.queries)
    finally:
        if machine is not None:machine.close()
