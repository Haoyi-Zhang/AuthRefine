"""Rebuild the packaged selected-source workflow, including the native primitive."""
from pathlib import Path
import gzip
import hashlib
import json
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'source_study'))
from workflow import replay_profiles

class PackagedWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.result=replay_profiles()

    def test_exact_source_calls_and_normal_context_denominators(self):
        rows=self.result['projects']
        self.assertEqual(len(rows),2)
        self.assertEqual([r['result']['semantics']['actual_context_executions'] for r in rows],[1710,144])
        self.assertEqual([r['result']['compiled_closure_bindings'] for r in rows],[30,6])
        self.assertEqual(self.result['context_executions'],1854)
        self.assertFalse(self.result['source_modules_or_tests_executed'])

    def test_complete_models_witness_consumers_and_native_provenance(self):
        for row in self.result['projects']:
            self.assertEqual(row['result']['status'],'contract_checked')
            self.assertEqual(row['result']['semantics']['unselected_discovered_bindings'],0)
            for case in row['result']['semantics']['cases']:
                self.assertEqual(case['status'],'semantic_agreement')
                self.assertEqual(case['unknown_contexts'],0)
                self.assertEqual(case['diagnosis']['nonagreeing_properties'],0)
                self.assertTrue(all(b['algorithms_agree'] for b in case['diagnosis']['batches']))
        native=self.result['projects'][1]['result']['semantics']['cases']
        self.assertEqual(sum(c['native_calls'] for c in native),159)
        self.assertTrue(all(c['native_runtime']['profile']=='casbin-1.43.0' for c in native))

    def test_saved_workflow_matches_fresh_semantic_results(self):
        saved=json.loads(gzip.decompress((ROOT/'source_study/data/workflow-results.json.gz').read_bytes()))
        self.assertEqual(saved['summary']['current_workflow_sha256'],hashlib.sha256((ROOT/'source_study/workflow.py').read_bytes()).hexdigest())
        self.assertEqual(saved['summary']['original_population'],48)
        self.assertEqual(saved['summary']['status_counts'],{'unsupported_source_form':30,'structural_only':14,'unsupported_guard_form':2,'contract_checked':2})
        def scientific(value):
            if isinstance(value,dict):return {k:scientific(v) for k,v in value.items() if not k.endswith('_ns')}
            if isinstance(value,list):return [scientific(v) for v in value]
            return value
        previous={r['repository']:r['result']['semantics'] for r in saved['complete_source_reports']['rows'] if r['result'].get('semantics')}
        for row in self.result['projects']:
            self.assertEqual(scientific(row['result']['semantics']),scientific(previous[row['repository']]))

if __name__=='__main__':unittest.main()
