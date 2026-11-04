"""Owned regression controls for connected admission and stateful contracts."""
import gzip,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'adaptation_study'),str(ROOT/'src')]
from chained_profiles import expected_write,write_policy,header_cases,header_reference,BoundaryMismatch,Unsupported
import study
from checker import reference_step

class ChainedProfilesTests(unittest.TestCase):
    def test_wrong_owner_precedes_already_resumed_conflict(self):
        self.assertEqual(expected_write(1,'2w',1),(403,1))
        self.assertEqual(expected_write(1,'1w',1),(409,1))
    def test_readonly_and_absent_requests_preserve_state(self):
        self.assertEqual(expected_write(6,'1r',1),(401,6))
        self.assertEqual(expected_write(6,'1w',99),(404,6))
    def test_policy_carries_state_across_repeated_requests(self):
        p=write_policy();binding={f'owner-{i}':f'project-{i}' for i in (1,2,3)}
        self.assertEqual(reference_step(p,0,['1w','check-1','resume'],binding),('allow',1))
        self.assertEqual(reference_step(p,1,['1w','check-1','resume'],binding),('deny',1))
        self.assertEqual(reference_step(p,1,['2w','check-2','resume'],binding),('allow',3))
    def test_unattempted_authentication_is_not_a_rejection_or_success(self):
        self.assertEqual(header_reference('not_attempted','active',{}),('not_attempted',None))
        self.assertEqual(header_reference('malformed','active',{}),('rejected',None))
    def test_header_matrix_contains_bytes_text_and_explicit_failures(self):
        rows=header_cases();self.assertEqual(len(rows),14);self.assertEqual(len({r[0] for r in rows}),14)
        self.assertTrue(any(type(r[1]) is bytes for r in rows));self.assertTrue(any(type(r[1]) is str for r in rows))
        self.assertEqual(sum(r[2]=='key' for r in rows),6)
    def test_unknown_is_not_a_deliberate_counterexample_signal(self):
        self.assertFalse(issubclass(Unsupported,BoundaryMismatch))
        self.assertTrue(issubclass(BoundaryMismatch,ValueError))
        with self.assertRaises(Unsupported):header_reference('unresolved','active',{})
        with self.assertRaises(Unsupported):expected_write(True,'1w',1)
        with self.assertRaises(Unsupported):expected_write(0,'other',1)
    def test_all_case_axes_bind_to_actual_source_functions(self):
        r=study.audit_casebook();self.assertEqual((r['cases'],r['axis_assignments']),(8,40))
        self.assertTrue(all(sum(v.values())==8 for v in r['axis_counts'].values()))
    def test_saved_graph_is_stateful_and_not_reset_per_request(self):
        r=json.loads(gzip.decompress((ROOT/'adaptation_study/chained-health.json.gz').read_bytes()))
        self.assertFalse(r['complete_reset_per_request']);self.assertEqual(r['measured_edges'],448)
        for p in r['profiles']:
            self.assertEqual(p['machine']['transitions'][0][p['machine']['alphabet'].index(['1w','check-1','resume'])],['allow',1])
            self.assertEqual(p['machine']['transitions'][1][p['machine']['alphabet'].index(['1w','check-1','resume'])],['deny',1])
            self.assertEqual(len(p['native_witness_replays']),26)
if __name__=='__main__':unittest.main()
