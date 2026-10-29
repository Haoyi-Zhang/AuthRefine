import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'source_study'))
from verify import read, verify_case_consumer, ROOT


class CaseResultIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        case=read(ROOT/'data/cases/1257410493.json')
        cls.original=case['existing_checker_consumer']

    def test_complete_original_case_has_a_recomputed_property_denominator(self):
        self.assertEqual(verify_case_consumer(self.original),1710)

    def test_changed_shortest_length_or_witness_is_not_hidden_by_same_classification(self):
        for key,value in (('shortest_length',1),('shortest_witness',[]),('matching_bindings',0),('matching_bindings',True),('algorithms_agree',False)):
            changed=copy.deepcopy(self.original);changed['batches'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):verify_case_consumer(changed)

    def test_ordinary_BFS_report_is_also_replayed(self):
        changed=copy.deepcopy(self.original);changed['batches'][0]['ordinary_BFS']['length']=1
        with self.assertRaises(ValueError):verify_case_consumer(changed)

    def test_aggregate_and_duplicate_property_identifiers_cannot_pass(self):
        changed=copy.deepcopy(self.original);changed['agreeing_properties']-=1
        with self.assertRaises(ValueError):verify_case_consumer(changed)
        changed=copy.deepcopy(self.original);changed['batches'][1]['source_context_ids'][0]=changed['batches'][0]['source_context_ids'][0]
        with self.assertRaises(ValueError):verify_case_consumer(changed)


if __name__=='__main__':unittest.main()
