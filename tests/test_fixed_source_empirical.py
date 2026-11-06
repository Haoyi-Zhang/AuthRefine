"""Owned offline checks;no third-party application startup or network calls."""
import importlib.util,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class FixedSourceEmpiricalTests(unittest.TestCase):
    def test_frozen_source_and_observation_evidence(self):
        p=subprocess.run([sys.executable,'-B',str(ROOT/'empirical_study/verify.py')],capture_output=True,text=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
    def test_closed_runtime_controls(self):
        p=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','tests','-p','test_*runtime.py'],cwd=ROOT/'empirical_study',capture_output=True,text=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
    def test_portable_source_identity_controls(self):
        p=subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','tests','-p','test_portable_binding.py'],cwd=ROOT/'empirical_study',capture_output=True,text=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
    def test_received_review_semantic_repairs(self):
        p=subprocess.run([sys.executable,'-B','-W','error','-m','unittest','discover','-s','tests','-p','test_review_semantics.py'],cwd=ROOT/'empirical_study',capture_output=True,text=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
if __name__=='__main__':unittest.main()
