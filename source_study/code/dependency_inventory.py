"""Bounded static FastAPI dependency graph without importing foreign modules.

This discovers source interfaces, not Boolean authorization decisions. Runtime
DI, constructors, method bodies, middleware and data/identity validity are never
certified. Unknown and dynamic bindings remain explicit, never unrestricted.
"""
import ast
from collections import Counter
import hashlib
from pathlib import PurePosixPath
import zipfile


class Inventory:
    def __init__(self,archive_path):
        self.modules={};self.errors=[];self.omitted=[];self.nodes={};self.sources={};self.ambiguous_modules={}
        self.archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest();total=0
        with zipfile.ZipFile(archive_path) as z:
            self.snapshot=z.comment.decode('ascii')
            for info in sorted(z.infolist(),key=lambda i:i.filename):
                path=info.filename.partition('/')[2]
                if not path.endswith('.py'):continue
                if any(p.casefold() in ('test','tests','migrations','vendor','third_party','.venv','venv','node_modules') for p in PurePosixPath(path).parts):continue
                if (info.file_size>500000 or total+info.file_size>24000000 or len(self.sources)>=2000
                        or (info.external_attr>>16)&0o170000==0o120000 or info.flag_bits&1):
                    self.omitted.append(path);continue
                data=z.read(info);total+=len(data);self.sources[path]=hashlib.sha256(data).hexdigest()
                try:tree=ast.parse(data)
                except (SyntaxError,ValueError,RecursionError):self.errors.append(path);continue
                module=path[:-3].replace('/','.')
                if module.endswith('.__init__'):module=module[:-9]
                if module in self.ambiguous_modules:
                    self.ambiguous_modules[module].append(path);continue
                if module in self.modules:
                    self.ambiguous_modules[module]=[self.modules.pop(module)['path'],path];continue
                bindings={};writes=Counter();definitions={}
                for n in tree.body:
                    if isinstance(n,ast.ImportFrom):
                        package=module if path.endswith('/__init__.py') else module.rpartition('.')[0]
                        parent=package.split('.')
                        base='.'.join(parent[:len(parent)-n.level+1]) if n.level else ''
                        base='.'.join(x for x in (base,n.module or '') if x)
                        for a in n.names:
                            name=a.asname or a.name;writes[name]+=1;bindings[name]=base+'.'+a.name
                    elif isinstance(n,ast.Import):
                        for a in n.names:
                            name=a.asname or a.name.split('.')[0];writes[name]+=1
                            bindings[name]=a.name if a.asname else a.name.split('.')[0]
                    elif isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                        writes[n.name]+=1;definitions[n.name]=n
                    elif isinstance(n,(ast.Assign,ast.AnnAssign)):
                        for t in (n.targets if isinstance(n,ast.Assign) else [n.target]):
                            for sub in ast.walk(t):
                                if isinstance(sub,ast.Name):writes[sub.id]+=1
                # A conditional/loop/try module binding is still a possible
                # rebinding. Never ignore it merely because it is not top-level.
                def indirect_writes(statements):
                    for statement in statements:
                        if isinstance(statement,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                            yield statement.name;continue
                        if isinstance(statement,ast.Lambda):continue
                        if isinstance(statement,ast.ImportFrom):
                            for a in statement.names:
                                if a.name=='*':
                                    for bound in list(writes):yield bound
                                else:yield a.asname or a.name
                            continue
                        if isinstance(statement,ast.Import):
                            for a in statement.names:yield a.asname or a.name.split('.')[0]
                            continue
                        if isinstance(statement,ast.Name) and isinstance(statement.ctx,(ast.Store,ast.Del)):
                            yield statement.id
                        for child in ast.iter_child_nodes(statement):yield from indirect_writes([child])
                for statement in tree.body:
                    if isinstance(statement,(ast.If,ast.For,ast.AsyncFor,ast.While,ast.Try,ast.With,ast.AsyncWith,ast.Match)):
                        for name in indirect_writes([statement]):writes[name]+=1
                if any(isinstance(n,ast.ImportFrom) and any(a.name=='*' for a in n.names) for n in tree.body):
                    # Unknown star-import names can shadow all candidates.
                    for name in list(writes):writes[name]+=1
                self.modules[module]=dict(path=path,tree=tree,bindings=bindings,writes=writes,definitions=definitions)

    def module(self,name):
        if name in self.ambiguous_modules:return None
        if name in self.modules:return name
        choices=[m for m in set(self.modules)|set(self.ambiguous_modules) if m.endswith('.'+name)]
        return choices[0] if len(choices)==1 and choices[0] in self.modules else None

    def expression(self,node,module):
        if isinstance(node,ast.Name):
            m=self.modules[module]
            if m['writes'][node.id]!=1:return None
            if node.id in m['bindings']:return m['bindings'][node.id]
            if node.id in m['definitions']:return module+'.'+node.id
            return None
        if isinstance(node,ast.Attribute):
            parent=self.expression(node.value,module)
            return parent+'.'+node.attr if parent else None
        return None

    def locate(self,qualified):
        if not qualified:return None
        prefix,_,name=qualified.rpartition('.');module=self.module(prefix)
        if module is None:return None
        item=self.modules[module];node=item['definitions'].get(name)
        if node is None or item['writes'][name]!=1:return None
        constructor=None
        if isinstance(node,ast.ClassDef):
            constructor=node.name
            found=[n for n in node.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=='__call__']
            if len(found)!=1:return None
            node=found[0];name=name+'.__call__'
        return module,name,node,constructor

    def injected(self,node,module):
        """Only parameter defaults/Annotated metadata, never arbitrary body calls."""
        defaults=list(node.args.defaults)+[x for x in node.args.kw_defaults if x is not None]
        expressions=defaults+[a.annotation for a in node.args.posonlyargs+node.args.args+node.args.kwonlyargs if a.annotation is not None]
        seen=set();items=[]
        for expression in expressions:
            for call in ast.walk(expression):
                if not isinstance(call,ast.Call) or self.expression(call.func,module) not in ('fastapi.Depends','fastapi.Security'):continue
                if id(call) in seen:continue
                seen.add(id(call))
                target=call.args[0] if len(call.args)==1 else None
                constructed=isinstance(target,ast.Call)
                qualified=self.expression(target.func if constructed else target,module) if target else None
                items.append(dict(line=call.lineno,expression=ast.unparse(call),qualified=qualified,
                    constructor_expression=ast.unparse(target) if constructed else None,
                    reason=None if qualified else 'dynamic/implicit/ambiguous dependency is unresolved',
                    dependency_call_keywords=[k.arg for k in call.keywords]))
        return items

    def expand(self,qualified,stack=()):
        located=self.locate(qualified)
        if located is None:return None
        module,name,node,constructor=located;key=module+'.'+name
        if key in stack or len(stack)>=24:return dict(key=key,unresolved='cycle or depth boundary')
        if key not in self.nodes:
            value=dict(key=key,member=self.modules[module]['path'],line=node.lineno,end_line=node.end_lineno,
                constructor=constructor,constructor_and_body_semantics_verified=False,
                decorators_require_runtime_binding=bool(node.decorator_list),dependencies=[])
            self.nodes[key]=value
            for edge in self.injected(node,module):
                child=self.expand(edge['qualified'],stack+(key,))
                edge['resolved_source_node']=child['key'] if child and 'unresolved' not in child else None
                if child and 'unresolved' in child:edge['reason']=child['unresolved']
                if not child and edge['qualified']:edge['reason']='source callable unavailable/ambiguous or lacks unique __call__'
                value['dependencies'].append(edge)
        return self.nodes[key]

    def scan(self):
        routes=[]
        for module,m in sorted(self.modules.items()):
            routers={}
            for n in m['tree'].body:
                if (isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)
                        and isinstance(n.value,ast.Call) and self.expression(n.value.func,module)=='fastapi.APIRouter'
                        and m['writes'][n.targets[0].id]==1):routers[n.targets[0].id]=n.value
            for f in m['tree'].body:
                if not isinstance(f,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
                for d in f.decorator_list:
                    if not (isinstance(d,ast.Call) and isinstance(d.func,ast.Attribute) and isinstance(d.func.value,ast.Name)
                            and d.func.value.id in routers and d.func.attr in ('get','post','put','patch','delete','head','options')):continue
                    dependencies=self.injected(f,module)
                    # Preserve extra router/route dependencies as unresolved rather than omit them.
                    for owner in (routers[d.func.value.id],d):
                        for k in owner.keywords:
                            if k.arg=='dependencies':dependencies.append(dict(line=k.value.lineno,expression=ast.unparse(k.value),
                                qualified=None,constructor_expression=None,reason='router/decorator dependency list needs a separate binding',dependency_call_keywords=[]))
                    for edge in dependencies:
                        child=self.expand(edge['qualified']);edge['resolved_source_node']=child['key'] if child else None
                        if not child and edge['qualified']:edge['reason']='source callable unavailable/ambiguous or lacks unique __call__'
                    routes.append(dict(member=m['path'],module=module,function=f.name,line=f.lineno,
                        method=d.func.attr.upper(),local_route_expression=ast.unparse(d),dependencies=dependencies,
                        app_mount_startup_middleware_and_endpoint_semantics_verified=False,
                        additional_decorators_unresolved=len(f.decorator_list)!=1))
        return dict(snapshot=self.snapshot,archive_sha256=self.archive_sha256,source_bindings=self.sources,
            parsed_modules=len(self.modules),syntax_errors=self.errors,omitted=self.omitted,ambiguous_modules=self.ambiguous_modules,
            routes=routes,dependency_nodes=list(self.nodes.values()),
            scope='static declared route/DI source links only; not a general call graph, access decision, absence-of-check, unrestricted endpoint, or application proof',
            source_modules_or_tests_executed=False,whole_application_verified=False)
