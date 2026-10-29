"""Explicit owned repair candidates for three admitted interface defects.

Source is parsed and transported as data, never imported or executed. These
operators do not turn the original program into a passing measurement. Every
candidate must be compared separately against the unchanged supplied contract.
"""
import ast
import copy

from native_casbin import AdmissionError, MAX_TEXT_BYTES
from persistent_store import extract_store, strip_docstring
from source_save_store import extract_repaired_store
from source_bindings import require_static_definitions


def tree_of(source):
    if type(source) is not bytes or len(source)>MAX_TEXT_BYTES:
        raise AdmissionError('repair candidate source is outside the source envelope')
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise AdmissionError('repair candidate source does not parse') from error


def repair_sync_guard(source, *, native_result_protocol):
    if native_result_protocol!='synchronous_boolean':
        raise AdmissionError('removing await requires a separately established synchronous Boolean protocol')
    tree=tree_of(source)
    require_static_definitions(tree,['_check_permission'])
    function=next(n for n in tree.body if isinstance(n,ast.AsyncFunctionDef) and n.name=='_check_permission')
    selected=[n for n in ast.walk(function) if isinstance(n,ast.Await) and isinstance(n.value,ast.Call)
        and ast.dump(n.value.func,include_attributes=False)==ast.dump(ast.parse('enforcer.enforce',mode='eval').body,include_attributes=False)]
    if len(selected)!=1 or len(selected[0].value.args)!=4 or selected[0].value.keywords:
        raise AdmissionError('expected exactly one declared native enforcement await')
    target=selected[0]
    class Replace(ast.NodeTransformer):
        def visit_Await(self,node):
            return copy.deepcopy(node.value) if node is target else self.generic_visit(node)
    return ('# Changed 2026-10-29: consume the declared synchronous Boolean result.\n'
        '# Derived source candidate retains its original included license.\n'+
        ast.unparse(ast.fix_missing_locations(Replace().visit(tree)))).encode()


def repair_file_store(source):
    descriptor=extract_store(source)
    if any(row.get('persist_after_success') for row in descriptor['methods'].values()):
        raise AdmissionError('store candidate already contains a persistence repair')
    tree=tree_of(source)
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==descriptor['class'])
    for operation in ('add','remove'):
        name=descriptor['methods'][operation]['method']
        node=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name==name)
        body=strip_docstring(node.body)
        if len(body)!=1 or not isinstance(body[0],ast.Return):
            raise AdmissionError('store repair requires its admitted direct native return')
        replacement=ast.parse('''_saved_change = None
if _saved_change is True:
    self._enforcer.save_policy()
return _saved_change
''').body
        replacement[0].value=copy.deepcopy(body[0].value)
        node.body=node.body[:len(node.body)-len(body)]+replacement
    candidate=('# Changed 2026-10-29: persist successful native policy mutations.\n'
        '# Derived source candidate retains its original included license.\n'+
        ast.unparse(ast.fix_missing_locations(tree))).encode()
    _,admitted=extract_repaired_store(candidate)
    if not all(admitted['source_mutation_effects'][op].get('persist_after_success') for op in ('add','remove')):
        raise AdmissionError('candidate persistence effects were not admitted')
    return candidate


def repeated_string_values(value, field, *, limit=256):
    """Preserve source-indexed values/order/duplicates, never dictionary keys."""
    if type(field) is not str or not field.isidentifier() or type(limit) is not int or not 0<=limit<=256:
        raise AdmissionError('repeated-field boundary needs a bounded declared field')
    if type(value) is list:
        values=list(value)
    elif type(value) is dict:
        indices=[]
        for key in value:
            if type(key) is not str or not key.startswith(field+'_'):
                raise AdmissionError('repeated dictionary key does not bind its source field')
            index=key[len(field)+1:]
            if not index.isascii() or not index.isdecimal() or len(index)>6 or str(int(index))!=index:
                raise AdmissionError('repeated dictionary key is not a canonical source index')
            indices.append(int(index))
        if indices!=sorted(indices):
            raise AdmissionError('source-index order was lost at the repeated-field boundary')
        values=list(value.values())
    else:
        raise AdmissionError('repeated-field input is not a plain list or indexed dictionary')
    if len(values)>limit or any(type(v) is not str for v in values):
        raise AdmissionError('repeated-field string count/type is outside the boundary')
    return values
