"""The completed paired review must not regress to missing or unbound labels."""
import copy
import json
from pathlib import Path
import sys
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


if __name__ == '__main__':
    unittest.main()
