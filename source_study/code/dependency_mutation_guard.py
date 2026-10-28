"""Conservative cross-module visible mutation guard for static DI sequences.

The earlier development graph remains reproducible; this profile closes the
additional visible-alias mutation gap before using sequence links as evidence.
Runtime DI, hidden mutation and dynamic attribute manipulation remain unknown.
"""
import ast
from dependency_binding_inventory import Inventory as BindingInventory


class Inventory(BindingInventory):
    def __init__(self,path):
        super().__init__(path)
        self._reference_cache={};self._mutated=set()
        for module,item in self.modules.items():
            for node in ast.walk(item['tree']):
                values=[]
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):values.append(node.func.value)
                if isinstance(node,(ast.Assign,ast.AnnAssign,ast.AugAssign,ast.Delete)):
                    targets=node.targets if isinstance(node,(ast.Assign,ast.Delete)) else [node.target]
                    for target in targets:
                        if isinstance(target,(ast.Subscript,ast.Attribute)):
                            while isinstance(target,(ast.Subscript,ast.Attribute)):target=target.value
                            values.append(target)
                for value in values:
                    name=self.reference(value,module)
                    if name:self._mutated.add(name)

    def reference(self,value,module,stack=()):
        qualified=self.expression(value,module)
        # A subscript target may make the original parser's conservative
        # write count exceed1. For a negative mutation guard only, still trace
        # a unique visible top-level alias; never use this to admit a binding.
        if not qualified and isinstance(value,ast.Name):qualified=module+'.'+value.id
        if not qualified or qualified in stack or len(stack)>=24:return None
        if qualified in self._reference_cache:return self._reference_cache[qualified]
        prefix,_,name=qualified.rpartition('.');owner=self.module(prefix)
        if owner is None:return None
        item=self.modules[owner]
        if name in item['bindings']:
            target=item['bindings'][name];prefix,_,symbol=target.rpartition('.');target_module=self.module(prefix)
            result=self.reference(ast.Name(id=symbol,ctx=ast.Load()),target_module,stack+(qualified,)) if target_module else None
        else:
            assignments=[n for n in item['tree'].body if
                isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name
                or isinstance(n,ast.AnnAssign) and isinstance(n.target,ast.Name) and n.target.id==name]
            assignment=assignments[0] if len(assignments)==1 else None
            if assignment is None:return None
            if isinstance(assignment.value,(ast.Name,ast.Attribute)):
                result=self.reference(assignment.value,owner,stack+(qualified,))
            else:result=owner+'.'+name
        self._reference_cache[qualified]=result
        return result

    def list_value(self,value,module,stack=()):
        if isinstance(value,(ast.Name,ast.Attribute)):
            name=self.reference(value,module)
            if name in self._mutated:return None
        return super().list_value(value,module,stack)

    def scan(self):
        report=super().scan()
        report['visible_cross_module_mutation_guard']=True
        report['hidden_dynamic_mutation_or_runtime_order_certified']=False
        return report
