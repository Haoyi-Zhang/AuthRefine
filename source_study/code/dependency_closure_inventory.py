"""Pure source-factory closure bindings; never execute or verify the closure.

Development amendment after the first48-source transfer. That transfer and its
unknowns stay immutable; later results are explicitly exposed-source repair.
"""
import ast
import hashlib
import json
from dependency_mutation_guard import Inventory as Guarded


def capture_arguments(factory,call):
    """Bind expression syntax,not runtime values; reject Python call ambiguities."""
    a=factory.args
    if a.vararg or a.kwarg or any(k.arg is None for k in call.keywords) or any(isinstance(v,ast.Starred) for v in call.args):return None
    positions=a.posonlyargs+a.args;values={}
    if len(call.args)>len(positions):return None
    for name,value in zip(positions,call.args):values[name.arg]=value
    named={n.arg for n in a.args+a.kwonlyargs};allargs=positions+a.kwonlyargs
    for key in call.keywords:
        if key.arg not in named or key.arg in values:return None
        values[key.arg]=key.value
    defaults={p.arg:v for p,v in zip(positions[len(positions)-len(a.defaults):],a.defaults)}
    defaults.update({p.arg:v for p,v in zip(a.kwonlyargs,a.kw_defaults) if v is not None})
    result={}
    for parameter in allargs:
        value=values.get(parameter.arg,defaults.get(parameter.arg))
        if value is None:return None
        # A source reference is not evaluated. Calls,comprehensions,subscript
        # effects,*args and executable defaults are outside this pure profile.
        if any(not isinstance(n,(ast.Constant,ast.Name,ast.Attribute,ast.List,ast.Tuple,ast.Set,ast.Dict,ast.Load,ast.UnaryOp,ast.USub,ast.UAdd)) for n in ast.walk(value)):
            return None
        if isinstance(value,ast.Dict) and any(k is None for k in value.keys):return None
        result[parameter.arg]=dict(expression=ast.unparse(value),origin='supplied_source_expression' if parameter.arg in values else 'factory_default_source_expression',runtime_value_verified=False)
    return result


class Inventory(Guarded):
    def __init__(self,path):
        self.closures={};super().__init__(path)

    def locate(self,qualified):
        return self.closures[qualified]['located'] if qualified in self.closures else super().locate(qualified)

    def closure_binding(self,call,module):
        qualified=self.expression(call.func,module)
        located,_=self.resolve(qualified)
        if located is None:return None
        owner,name,factory,constructor=located
        if constructor is not None or not isinstance(factory,ast.FunctionDef) or factory.decorator_list:return None
        body=list(factory.body)
        if body and isinstance(body[0],ast.Expr) and isinstance(body[0].value,ast.Constant) and type(body[0].value.value) is str:body=body[1:]
        if (len(body)!=2 or not isinstance(body[0],(ast.FunctionDef,ast.AsyncFunctionDef)) or body[0].decorator_list
                or not isinstance(body[1],ast.Return) or not isinstance(body[1].value,ast.Name) or body[1].value.id!=body[0].name):return None
        # Default/annotation names are resolved in the factory scope. Do not
        # accidentally bind an outer parameter shadow to a module import.
        parameters=factory.args.posonlyargs+factory.args.args+factory.args.kwonlyargs
        if any(p.arg in self.modules[owner]['bindings'] or p.arg in self.modules[owner]['definitions'] for p in parameters):return None
        captures=capture_arguments(factory,call)
        if captures is None:return None
        closure=body[0];description=dict(kind='pure_returned_closure_source_template',factory_member=self.modules[owner]['path'],
            factory_name=name,factory_line=factory.lineno,factory_end_line=factory.end_lineno,
            closure_name=closure.name,closure_line=closure.lineno,closure_end_line=closure.end_lineno,
            call_member=self.modules[module]['path'],call_line=call.lineno,call_expression=ast.unparse(call),captures=captures,
            runtime_values_defaults_constructor_identity_and_body_semantics_verified=False)
        token=hashlib.sha256(json.dumps(description,sort_keys=True).encode()).hexdigest()[:24]
        selector=name+'.'+closure.name+'.__source_call_'+token;key=owner+'.'+selector
        self.closures[key]=dict(located=(owner,selector,closure,None),description=description)
        self.binding_traces[key]=[description]
        return key,description

    def dependency_call(self,call,module):
        edge=super().dependency_call(call,module)
        if edge['qualified'] is not None:return edge
        kwargs=[k for k in call.keywords if k.arg=='dependency']
        target=call.args[0] if len(call.args)==1 and not kwargs else kwargs[0].value if not call.args and len(kwargs)==1 else None
        if any(k.arg is None for k in call.keywords) or not isinstance(target,ast.Call):return edge
        binding=self.closure_binding(target,module)
        if binding is not None:
            edge.update(qualified=binding[0],reason=None,source_closure_capture=binding[1],closure_semantics_verified=False)
        return edge

    def scan(self):
        result=super().scan()
        result['pure_returned_closure_source_bindings']=[v['description'] for v in self.closures.values()]
        result['post_first_transfer_development_amendment']=True
        return result
