"""Lower a fully checked explicit-save candidate to the frozen native kernel.

The kernel's existing save switch is derived solely from the complete candidate
body, not supplied by the caller. Historical measurements of that unchanged
kernel remain measurements of the original kernel, not of this adapter.
"""
import ast
import copy

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from persistent_store import extract_store, compare_store, strip_docstring, body_shape
from source_bindings import require_static_class_members


def extract_repaired_store(source):
    if type(source) is not bytes or len(source)>MAX_TEXT_BYTES:
        raise AdmissionError('explicit-save source is outside the admitted envelope')
    try:tree=ast.parse(source)
    except (SyntaxError,ValueError,RecursionError) as error:
        raise AdmissionError('explicit-save candidate does not parse') from error
    classes=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='PolicyEngine']
    if len(classes)!=1:raise AdmissionError('explicit-save class is missing or ambiguous')
    cls=classes[0]
    require_static_class_members(cls,['__init__','authorize','add_policy_rule','remove_policy_rule'])
    effects={}
    for operation,name in (('add','add_policy_rule'),('remove','remove_policy_rule')):
        methods=[n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name==name]
        if len(methods)!=1:raise AdmissionError('explicit-save mutation method changed')
        node=methods[0];body=strip_docstring(node.body)
        if len(body)!=3:raise AdmissionError('complete save-on-success candidate required')
        assignment,condition,returned=body
        if (not isinstance(assignment,ast.Assign) or len(assignment.targets)!=1
                or not isinstance(assignment.targets[0],ast.Name)
                or assignment.targets[0].id in [a.arg for a in node.args.args]):
            raise AdmissionError('mutation result binding is not fresh')
        variable=assignment.targets[0].id
        tail=ast.parse(f'''if {variable} is True:
    self._enforcer.save_policy()
return {variable}
''').body
        if body_shape([condition,returned])!=body_shape(tail):
            raise AdmissionError('explicit-save condition/call/return order differs')
        effects[operation]=dict(method=name,line=node.lineno,end_line=node.end_lineno,
            persist_after_success=True,return_value_preserved=True)
        node.body=node.body[:len(node.body)-3]+[ast.Return(value=copy.deepcopy(assignment.value))]
    lowered=ast.unparse(ast.fix_missing_locations(tree)).encode()
    descriptor=extract_store(lowered)
    return lowered,dict(base_interface=descriptor,source_mutation_effects=effects,
        complete_selected_bodies_checked=True,original_source_bytecode_executed=False)


def compare_repaired_store(source,model_text,rows,*,initial=0):
    lowered,descriptor=extract_repaired_store(source)
    result=compare_store(lowered,model_text,rows,initial=initial,owned_explicit_save=True)
    return dict(result,source_candidate_descriptor=descriptor,save_effect_from_candidate_source=True,
        external_save_toggle_supplied=False,
        lowering='Complete native-return/save-if-True/return bodies select the unchanged native kernel save effect.',
        historical_kernel_timings_not_claimed_as_current_adapter_timings=True)
