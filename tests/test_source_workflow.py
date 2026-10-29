"""End-to-end source/contract controls, including wrong and missing semantics."""
import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'source_study'))
from workflow import analyze, main, read_json, validate_contract

SOURCE='''from fastapi import APIRouter, Depends, HTTPException
raise RuntimeError("must remain passive source")
router = APIRouter()
def get_user(): return None
def require_role(required):
    def guard(user=Depends(get_user)):
        if required not in user.roles:
            raise HTTPException(status_code=403)
        return user
    return guard
@router.get("/")
def endpoint(user=Depends(require_role("reader"))): return user
'''

def contract():
    return dict(profile='returned-guard',entry_contract='complete immutable role observations',cases=[dict(
        id='read',select=dict(factory='require_role',captures=dict(required='reader')),contexts=[
            dict(id='reader',arguments=dict(user=dict(roles=['reader'])),expected=dict(decision='allow',returned_value=dict(roles=['reader']))),
            dict(id='other',arguments=dict(user=dict(roles=['writer'])),expected=dict(decision='deny'))])])

class SourceWorkflow(unittest.TestCase):
    def archive(self,directory,source=SOURCE):
        path=Path(directory)/'input.zip'
        with zipfile.ZipFile(path,'w') as z:
            z.comment=b'owned-normal-source';z.writestr('renamed_source/permission.py',source)
        return path

    def test_actual_source_to_observations_models_and_replay(self):
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d),contract())
        self.assertEqual(result['status'],'contract_checked')
        case=result['semantics']['cases'][0]
        self.assertEqual(case['status'],'semantic_agreement')
        self.assertEqual(case['contexts'],2)
        self.assertEqual(case['diagnosis']['nonagreeing_properties'],0)
        self.assertEqual(case['diagnosis']['context_properties'],3)
        self.assertFalse(result['source_modules_or_tests_executed'])

    def test_source_mutation_is_measured_not_saved_answer_lookup(self):
        source=SOURCE.replace('required not in user.roles','required in user.roles')
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,source),contract())
        case=result['semantics']['cases'][0]
        self.assertEqual(case['status'],'contract_mismatch')
        self.assertEqual(sum(o['agrees'] is False for o in case['observations']),2)
        self.assertEqual(case['diagnosis']['nonagreeing_properties'],3)
        self.assertEqual(case['diagnosis']['batches'][0]['shortest_length'],1)
        self.assertTrue(case['diagnosis']['batches'][0]['shortest_witness'])

    def test_returned_identity_difference_is_not_hidden_by_allow(self):
        with tempfile.TemporaryDirectory() as d:
            result=analyze(self.archive(d,SOURCE.replace('return user\n','return False\n')),contract())
        case=result['semantics']['cases'][0]
        self.assertEqual(case['status'],'contract_mismatch')
        self.assertEqual(case['diagnosis']['nonagreeing_properties'],1)

    def test_missing_field_is_inconclusive_not_denial(self):
        value=contract();value['cases'][0]['contexts'][1]['arguments']={'user':{}}
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d),value)
        self.assertEqual(result['status'],'contract_incomplete')
        case=result['semantics']['cases'][0]
        self.assertEqual(case['status'],'inconclusive')
        self.assertIsNone(case['observations'][1]['agrees'])
        self.assertIsNone(case['diagnosis'])

    def test_absent_contract_is_not_semantic_success(self):
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d))
        self.assertEqual(result['status'],'needs_contract')
        self.assertIsNone(result['semantics'])

    def test_missing_source_selector_is_not_an_empty_success(self):
        value=contract();value['cases'][0]['select']['factory']='other'
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d),value)
        self.assertEqual(result['status'],'contract_incomplete')
        self.assertEqual(result['semantics']['cases'][0]['status'],'source_not_admitted')

    def test_source_primitive_rebinding_is_not_admitted(self):
        for source in (SOURCE.replace('router =','HTTPException = object\nrouter ='),
                       SOURCE.replace('def guard(user=', 'def guard(any, user='),
                       SOURCE.replace('if required not in user.roles:', 'any = False\n        if required not in user.roles:')):
            with self.subTest(source=source),tempfile.TemporaryDirectory() as d:
                result=analyze(self.archive(d,source),contract())
                self.assertEqual(result['status'],'contract_incomplete')
                self.assertEqual(result['compiled_closure_bindings'],0)

    def test_project_path_and_function_names_are_not_hardcoded(self):
        source=SOURCE.replace('require_role','ordinary_factory').replace('guard','ordinary_guard')
        value=contract();value['cases'][0]['select']['factory']='ordinary_factory'
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,source),value)
        self.assertEqual(result['semantics']['cases'][0]['status'],'semantic_agreement')

    def test_wrong_contract_is_retained_as_a_mismatch_not_corrected(self):
        value=contract();value['cases'][0]['contexts'][0]['expected']={'decision':'deny'}
        original=deepcopy(value)
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d),value)
        self.assertEqual(value,original)
        self.assertEqual(result['semantics']['cases'][0]['status'],'contract_mismatch')

    def test_no_routes_has_an_explicit_unsupported_result(self):
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,'def f(): return True\n'))
        self.assertEqual(result['status'],'unsupported_source_form')
        self.assertEqual(result['compiled_closure_bindings'],0)

    def test_invalid_contracts_do_not_enter_evaluation(self):
        values=[]
        value=contract();value['cases'][0]['contexts'].append(deepcopy(value['cases'][0]['contexts'][0]));values.append(value)
        value=contract();value['cases'][0]['contexts'][0]['expected']={'decision':'allow'};values.append(value)
        value=contract();value['cases'][0]['contexts'][0]['expected']={'decision':'unknown'};values.append(value)
        value=contract();value['cases'][0]['contexts']=[];values.append(value)
        for value in values:
            with self.subTest(value=value),self.assertRaises(ValueError):validate_contract(value)

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'input.json';path.write_text('{"cases": [], "cases": []}')
            with self.assertRaises(ValueError):read_json(path)

    def test_duplicate_selectors_do_not_inflate_context_counts(self):
        value=contract();second=deepcopy(value['cases'][0]);second['id']='different-label'
        value['cases'].append(second)
        with self.assertRaisesRegex(ValueError,'duplicate source selector'):validate_contract(value)

    def test_broad_and_narrow_overlapping_selectors_are_rejected(self):
        value=contract();second=deepcopy(value['cases'][0]);second['id']='member-label'
        second['select']['member']='permission.py';value['cases'].append(second)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'overlapping selectors'):
                analyze(self.archive(d),value)

    def test_cli_reports_actual_mismatch_and_preserves_output(self):
        with tempfile.TemporaryDirectory() as d:
            archive=self.archive(d,SOURCE.replace('required not in user.roles','required in user.roles'))
            path=Path(d)/'contract.json';path.write_text(json.dumps(contract()))
            out=Path(d)/'result.json';main(['source',str(archive),'--contract',str(path),'--output',str(out)])
            self.assertEqual(json.loads(out.read_text())['semantics']['cases'][0]['status'],'contract_mismatch')
            previous=out.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                main(['source',str(archive),'--contract',str(path),'--output',str(out)])
            self.assertEqual(out.read_bytes(),previous)

    def test_tuple_literal_is_selected_by_its_json_array(self):
        source=SOURCE.replace('require_role("reader")','require_role(("reader",))').replace('required not in user.roles','not any(role in required for role in user.roles)')
        value=contract();value['cases'][0]['select']['captures']['required']=['reader']
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,source),value)
        self.assertEqual(result['semantics']['cases'][0]['status'],'semantic_agreement')
        self.assertEqual(result['guards'][0]['program']['captures']['required'],('reader',))

    def test_json_selector_does_not_change_tuple_equality_semantics(self):
        source=SOURCE.replace('require_role("reader")','require_role(("reader",))').replace('required not in user.roles','required != user.roles')
        value=contract();value['cases'][0]['select']['captures']['required']=['reader']
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,source),value)
        case=result['semantics']['cases'][0]
        self.assertEqual(case['status'],'contract_mismatch')
        self.assertEqual(case['observations'][0]['observed']['decision'],'deny')

    def test_uninitialized_local_capture_never_inherits_outer_value(self):
        source=SOURCE.replace('if required not in user.roles:',"if user.active:\n            required = 'writer'\n        if required not in user.roles:")
        value=contract();value['cases'][0]['contexts']=[dict(id='normal',arguments={'user':{'active':False,'roles':['reader']}},expected={'decision':'allow','returned_value':{'active':False,'roles':['reader']}})]
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,source),value)
        case=result['semantics']['cases'][0]
        self.assertEqual(result['status'],'contract_incomplete')
        self.assertEqual(case['observations'][0]['observed']['decision'],'unknown')
        self.assertIn('unbound',case['observations'][0]['observed']['reason'])
        self.assertIsNone(case['diagnosis'])

    def test_initialized_shadow_uses_actual_local_value(self):
        source=SOURCE.replace('if required not in user.roles:',"if user.active:\n            required = 'writer'\n        if required not in user.roles:")
        user={'active':True,'roles':['writer']};value=contract()
        value['cases'][0]['contexts']=[dict(id='normal',arguments={'user':user},expected={'decision':'allow','returned_value':user})]
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,source),value)
        self.assertEqual(result['semantics']['cases'][0]['status'],'semantic_agreement')

    def test_zero_iteration_local_loop_target_remains_unbound(self):
        source=SOURCE.replace('if required not in user.roles:',"for required in user.choices:\n            seen = required\n        if required not in user.roles:")
        user={'choices':[],'roles':['reader']};value=contract()
        value['cases'][0]['contexts']=[dict(id='normal',arguments={'user':user},expected={'decision':'allow','returned_value':user})]
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,source),value)
        self.assertEqual(result['semantics']['cases'][0]['status'],'inconclusive')

    def test_conditional_unpack_target_is_also_function_local(self):
        source=SOURCE.replace('if required not in user.roles:',"if user.active:\n            required, other = user.pair\n        if required not in user.roles:")
        user={'active':False,'pair':['writer','other'],'roles':['reader']};value=contract()
        value['cases'][0]['contexts']=[dict(id='normal',arguments={'user':user},expected={'decision':'allow','returned_value':user})]
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,source),value)
        self.assertEqual(result['semantics']['cases'][0]['status'],'inconclusive')

    def test_formal_parameter_shadows_factory_parameter(self):
        source=SOURCE.replace('def guard(user=', 'def guard(required, user=')
        user={'roles':['writer']};value=contract()
        value['cases'][0]['contexts']=[dict(id='normal',arguments={'required':'writer','user':user},expected={'decision':'allow','returned_value':user})]
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,source),value)
        self.assertEqual(result['semantics']['cases'][0]['status'],'semantic_agreement')

    def test_comprehension_binding_does_not_shadow_enclosing_capture(self):
        source=SOURCE.replace('if required not in user.roles:',"seen = any(required in user.roles for required in user.choices)\n        if required not in user.roles:")
        user={'choices':['writer'],'roles':['reader']};value=contract()
        value['cases'][0]['contexts']=[dict(id='normal',arguments={'user':user},expected={'decision':'allow','returned_value':user})]
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,source),value)
        self.assertEqual(result['semantics']['cases'][0]['status'],'semantic_agreement')

    def test_shadowed_status_alias_cannot_be_folded_to_403(self):
        source=SOURCE.replace('HTTPException\n','HTTPException, status\n').replace('if required not in user.roles:','status = user.status\n        if required not in user.roles:').replace('status_code=403','status_code=status.HTTP_403_FORBIDDEN')
        value=contract()
        with tempfile.TemporaryDirectory() as d:result=analyze(self.archive(d,source),value)
        self.assertEqual(result['compiled_closure_bindings'],0)
        self.assertIn('shadowed',result['guards'][0]['reason'])
        self.assertEqual(result['status'],'contract_incomplete')

    def test_parameter_and_comprehension_cannot_shadow_source_constant(self):
        base=SOURCE.replace('HTTPException\n','HTTPException, status\n').replace('status_code=403','status_code=status.HTTP_403_FORBIDDEN')
        sources=[base.replace('def guard(user=', 'def guard(status, user='),
            base.replace('if required not in user.roles:','seen = any(status.HTTP_403_FORBIDDEN for status in user.choices)\n        if required not in user.roles:')]
        for source in sources:
            with self.subTest(source=source),tempfile.TemporaryDirectory() as d:
                result=analyze(self.archive(d,source),contract())
                self.assertEqual(result['compiled_closure_bindings'],0)
                self.assertIn('shadowed',result['guards'][0]['reason'])

    def test_non_json_returns_are_unknown_and_json_serializable(self):
        for returned in ('{required}','[user, {required}]','(role for role in user.roles)'):
            source=SOURCE.replace('return user\n','return '+returned+'\n')
            with self.subTest(returned=returned),tempfile.TemporaryDirectory() as d:
                result=analyze(self.archive(d,source),contract())
                case=result['semantics']['cases'][0]
                self.assertEqual(case['status'],'inconclusive')
                self.assertEqual(case['observations'][0]['observed']['decision'],'unknown')
                self.assertIn('JSON observation',case['observations'][0]['observed']['reason'])
                self.assertIsNone(case['diagnosis']);json.dumps(result,allow_nan=False)

    def test_cli_materializes_inconclusive_non_json_return(self):
        source=SOURCE.replace('return user\n','return {required}\n')
        with tempfile.TemporaryDirectory() as d:
            archive=self.archive(d,source);path=Path(d)/'contract.json';out=Path(d)/'result.json'
            path.write_text(json.dumps(contract()))
            main(['source',str(archive),'--contract',str(path),'--output',str(out)])
            self.assertEqual(json.loads(out.read_text())['status'],'contract_incomplete')

if __name__=='__main__':unittest.main()
