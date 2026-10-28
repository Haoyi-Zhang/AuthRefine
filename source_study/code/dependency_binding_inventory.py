"""Static re-export/instance/list DI bindings, not runtime authorization proof.

The original inventory and its frozen consumers are unchanged. Source names
may be linked without evaluating imports, constructors, factories or bodies.
"""
import ast
import copy
from dependency_inventory import Inventory as OriginalInventory


class Inventory(OriginalInventory):
    def __init__(self,path):
        super().__init__(path)
        self.binding_traces={}

    def assignment(self,module,name):
        item=self.modules[module]
        if item['writes'][name]!=1:return None
        found=[]
        for node in item['tree'].body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id==name:
                found.append(node)
            elif isinstance(node,ast.AnnAssign) and isinstance(node.target,ast.Name) and node.target.id==name:
                found.append(node)
            elif isinstance(node,ast.AugAssign) and isinstance(node.target,ast.Name) and node.target.id==name:return None
        return found[0] if len(found)==1 else None

    def expression(self,node,module):
        value=super().expression(node,module)
        if value:return value
        if isinstance(node,ast.Name) and self.assignment(module,node.id) is not None:
            return module+'.'+node.id
        if isinstance(node,ast.Attribute):
            parent=self.expression(node.value,module)
            return parent+'.'+node.attr if parent else None
        return None

    def resolve(self,qualified,stack=()):
        if not qualified or qualified in stack or len(stack)>=24:return None,[]
        prefix,_,name=qualified.rpartition('.');module=self.module(prefix)
        if module is None:return None,[]
        item=self.modules[module]
        if item['writes'][name]!=1:return None,[]
        direct=super().locate(module+'.'+name)
        if direct:return direct,[]
        if name in item['bindings']:
            target=item['bindings'][name]
            result,trace=self.resolve(target,stack+(qualified,))
            return result,[dict(kind='import_reexport',member=item['path'],name=name,target=target)]+trace
        assignment=self.assignment(module,name)
        if assignment is None or assignment.value is None:return None,[]
        value=assignment.value;constructed=isinstance(value,ast.Call)
        target=self.expression(value.func if constructed else value,module)
        if target is None:return None,[]
        result,trace=self.resolve(target,stack+(qualified,))
        if result is None or constructed and result[3] is None:return None,[]
        # A factory returning a callable is not the factory's body. Only a
        # statically declared class __call__ template is linked for instances.
        entry=dict(kind='constructed_class_alias' if constructed else 'name_alias',member=item['path'],
            line=assignment.lineno,name=name,expression=ast.unparse(value),target=target,
            runtime_object_constructor_and_mutation_verified=False)
        return result,[entry]+trace

    def locate(self,qualified):
        result,trace=self.resolve(qualified)
        if result:self.binding_traces[qualified]=trace
        return result

    def dependency_call(self,call,module):
        kwargs=[k for k in call.keywords if k.arg=='dependency']
        target=call.args[0] if len(call.args)==1 and not kwargs else kwargs[0].value if not call.args and len(kwargs)==1 else None
        if any(k.arg is None for k in call.keywords):target=None
        constructed=isinstance(target,ast.Call)
        qualified=self.expression(target.func if constructed else target,module) if target is not None else None
        if constructed and qualified:
            result,_=self.resolve(qualified)
            if result is None or result[3] is None:qualified=None
        return dict(line=call.lineno,expression=ast.unparse(call),qualified=qualified,
            constructor_expression=ast.unparse(target) if constructed else None,
            reason=None if qualified else 'dynamic/implicit/ambiguous dependency is unresolved',
            dependency_call_keywords=[k.arg for k in call.keywords])

    def injected(self,node,module):
        defaults=list(node.args.defaults)+[x for x in node.args.kw_defaults if x is not None]
        expressions=defaults+[a.annotation for a in node.args.posonlyargs+node.args.args+node.args.kwonlyargs if a.annotation is not None]
        seen=set();edges=[]
        for expression in expressions:
            for call in ast.walk(expression):
                if (not isinstance(call,ast.Call) or id(call) in seen
                        or self.expression(call.func,module) not in ('fastapi.Depends','fastapi.Security')):continue
                seen.add(id(call));edges.append(self.dependency_call(call,module))
        return edges

    def list_value(self,value,module,stack=()):
        if len(stack)>=24:return None
        if isinstance(value,(ast.List,ast.Tuple)):
            if any(not isinstance(v,ast.Call) or self.expression(v.func,module) not in ('fastapi.Depends','fastapi.Security') for v in value.elts):return None
            return [self.dependency_call(v,module) for v in value.elts]
        if isinstance(value,ast.BinOp) and isinstance(value.op,ast.Add):
            left=self.list_value(value.left,module,stack+('left',));right=self.list_value(value.right,module,stack+('right',))
            return None if left is None or right is None else left+right
        qualified=self.expression(value,module)
        if not qualified and isinstance(value,ast.Name):qualified=module+'.'+value.id
        if not qualified or qualified in stack:return None
        prefix,_,name=qualified.rpartition('.');owner=self.module(prefix)
        if owner is None:return None
        item=self.modules[owner]
        if item['writes'][name]!=1:return None
        if name in item['bindings']:
            target=item['bindings'][name];prefix,_,symbol=target.rpartition('.');target_module=self.module(prefix)
            if target_module is None:return None
            return self.list_value(ast.Name(id=symbol,ctx=ast.Load()),target_module,stack+(qualified,))
        assignment=self.assignment(owner,name)
        if assignment is None:return None
        for node in ast.walk(item['tree']):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id==name:return None
            if isinstance(node,(ast.Assign,ast.AnnAssign,ast.AugAssign,ast.Delete)):
                targets=node.targets if isinstance(node,(ast.Assign,ast.Delete)) else [node.target]
                for target in targets:
                    if isinstance(target,(ast.Subscript,ast.Attribute)) and any(isinstance(n,ast.Name) and n.id==name for n in ast.walk(target)):return None
        values=self.list_value(assignment.value,owner,stack+(qualified,))
        if values is not None:
            for edge in values:edge.setdefault('static_dependency_list_bindings',[]).append(dict(member=item['path'],line=assignment.lineno,name=name))
        return values

    def finish_edge(self,edge):
        child=self.expand(edge['qualified']);edge['resolved_source_node']=child['key'] if child and 'unresolved' not in child else None
        if child and 'unresolved' in child:edge['reason']=child['unresolved']
        elif not child and edge['qualified']:edge['reason']='source callable unavailable/ambiguous or lacks unique __call__'
        if child:
            edge['static_binding_trace']=copy.deepcopy(self.binding_traces.get(edge['qualified'],[]))
            edge['runtime_binding_and_permission_semantics_verified']=False
        return edge

    def scan(self):
        result=super().scan()
        for route in result['routes']:
            module=route['module'];edges=[]
            for edge in route['dependencies']:
                if edge['reason']!='router/decorator dependency list needs a separate binding':
                    edges.append(self.finish_edge(edge));continue
                candidates=[n for n in ast.walk(self.modules[module]['tree']) if isinstance(n,ast.expr)
                    and getattr(n,'lineno',None)==edge['line'] and ast.unparse(n)==edge['expression']]
                parsed=self.list_value(candidates[0],module) if len(candidates)==1 else None
                if parsed is None:
                    edge['reason']='dynamic/ambiguous/mutable router or decorator dependency sequence remains unresolved';edges.append(edge)
                else:
                    for index,child in enumerate(parsed):
                        child['router_or_decorator_dependency_list_expression']=edge['expression'];child['sequence_position']=index
                        edges.append(self.finish_edge(child))
            route['dependencies']=edges
        # super.scan serializes a snapshot of nodes before newly bound list
        # dependencies are expanded, so refresh it, preserving nested edges.
        for node in self.nodes.values():
            for edge in node['dependencies']:
                if edge.get('resolved_source_node'):
                    edge['static_binding_trace']=copy.deepcopy(self.binding_traces.get(edge['qualified'],[]))
                    edge['runtime_binding_and_permission_semantics_verified']=False
        result['dependency_nodes']=list(self.nodes.values())
        result['source_link_scope_extension']='reexports, pure name aliases, declared class-instance callable templates and literal unmutated dependency sequences; no imports/constructor/factory/body execution'
        return result
