"""The completed paired review must not regress to missing or unbound labels."""
import copy
import gzip
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'empirical_study'
sys.path.insert(0, str(ROOT))
from review import verify_review


class ReviewCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.methods = json.loads((ROOT / 'methods.json').read_text(encoding='utf-8'))

    def changed(self, edit):
        value = copy.deepcopy(self.methods)
        edit(value['source_contract_review'])
        with self.assertRaises(ValueError):
            verify_review(ROOT, value)

    def test_complete_source_scoped_review(self):
        result = verify_review(ROOT, self.methods)
        self.assertEqual(result['completed_final_items'], 115)
        self.assertTrue(result['selected_source_review_complete'])
        self.assertFalse(result['independent_business_intent_oracle'])

    def test_no_missing_item(self):
        self.changed(lambda r: r['source_binding_crosswalk'].pop())

    def test_no_duplicate_item(self):
        self.changed(lambda r: r['source_binding_crosswalk'].__setitem__(1, copy.deepcopy(r['source_binding_crosswalk'][0])))

    def test_no_wrong_source_revision(self):
        self.changed(lambda r: r['source_binding_crosswalk'][0].__setitem__('snapshot', 'unbound'))

    def test_no_changed_context_denominator(self):
        self.changed(lambda r: r['source_binding_crosswalk'][59].__setitem__('existing_contexts', 999))

    def test_no_missing_adjudication(self):
        self.changed(lambda r: r['completed_workflow'].__setitem__('final_response_files', 0))

    def test_no_lost_method_disposition(self):
        self.changed(lambda r: r['method_and_design_dispositions'].pop())

    def test_no_business_intent_upgrade(self):
        self.changed(lambda r: r.__setitem__('independent_semantic_gold_claimed', True))

    def test_no_wrong_observed_agreement(self):
        for pair in range(3):
            with self.subTest(pair=pair):
                self.changed(lambda r: r['initial_judgment_agreement'][pair].__setitem__('observed_agreement', 0.0))

    def test_no_wrong_kappa(self):
        for pair in range(3):
            with self.subTest(pair=pair):
                self.changed(lambda r: r['initial_judgment_agreement'][pair].__setitem__('cohen_kappa', 1.0))

    def test_no_wrong_agreement_denominator(self):
        for pair in range(3):
            with self.subTest(pair=pair):
                self.changed(lambda r: r['initial_judgment_agreement'][pair].__setitem__('items', 1))

    def test_no_lost_disagreement_ids(self):
        for pair in range(3):
            with self.subTest(pair=pair):
                self.changed(lambda r: r['initial_judgment_agreement'][pair].__setitem__('disagreement_ids', []))

    def test_no_duplicate_agreement_pair(self):
        self.changed(lambda r: r['initial_judgment_agreement'].append(copy.deepcopy(r['initial_judgment_agreement'][0])))

    def test_no_missing_agreement_pair(self):
        self.changed(lambda r: r['initial_judgment_agreement'].pop())

    def test_no_false_text_completion(self):
        self.changed(lambda r: r['completed_workflow'].__setitem__('raw_responses_preserved_unchanged', 'false'))

    def test_no_fractional_file_count(self):
        self.changed(lambda r: r['completed_workflow'].__setitem__('initial_response_files', 6.0))

    def test_no_invalid_method_judgment(self):
        self.changed(lambda r: r['method_and_design_dispositions'][0].__setitem__('submitted_judgment', 'not-a-review-category'))

    def test_no_method_adoption_conflict(self):
        def edit(review):
            row=review['method_and_design_dispositions'][0]
            row.update(initial_left_judgment='未发现需修正问题',initial_right_judgment=row['submitted_judgment'],resolution='adopt_left')
        self.changed(edit)

    def source_metadata_change(self, field, value):
        # Only temporary copies change. Frozen source/inputs in the artifact
        # and original reviewer files are never edited by a regression test.
        with tempfile.TemporaryDirectory(prefix='authrefine-review-') as temporary:
            base=Path(temporary);empirical=base/'empirical_study';reference=base/'reference_completion'
            (empirical/'data').mkdir(parents=True);reference.mkdir()
            for name in ('inputs.json.gz','sources.json.gz'):
                shutil.copyfile(ROOT/'data'/name,empirical/'data'/name)
            payload=json.loads(gzip.decompress((ROOT.parent/'reference_completion/inputs.json.gz').read_bytes()))
            contract=next(c for c in payload['references']['contracts'] if c['source_distribution']=='included')
            contract[field]=value
            (reference/'inputs.json.gz').write_bytes(gzip.compress(json.dumps(payload).encode(),mtime=0))
            methods=copy.deepcopy(self.methods)
            methods['source_contract_review']['source_binding_crosswalk'][0]['source_anchors'][0][field]=value
            with self.assertRaises(ValueError):
                verify_review(empirical,methods)

    def test_source_function_name_is_not_self_asserted(self):
        self.source_metadata_change('function','WrongFunction')

    def test_source_function_line_is_not_self_asserted(self):
        self.source_metadata_change('line',50)


if __name__ == '__main__':
    unittest.main()
