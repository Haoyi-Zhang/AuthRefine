from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'source_study'))
from repair_profiles import verify


class ActualRepairProfileTests(unittest.TestCase):
    def test_all_three_fixed_source_consumers_replay_their_actual_candidates(self):
        value=verify()
        self.assertEqual(value['Conclave_contexts'],1176)
        self.assertEqual(value['Conclave_original_different_contexts'],168)
        self.assertEqual(value['Conclave_repaired_different_contexts'],0)
        self.assertEqual(value['IoT_original_different_records'],104)
        self.assertEqual(value['IoT_repaired_different_records'],0)
        self.assertEqual(value['Conet_table_cells'],768)
        self.assertTrue(value['Conet_repaired_accepted'])
        self.assertFalse(value['source_applications_executed'])


if __name__=='__main__':unittest.main()
