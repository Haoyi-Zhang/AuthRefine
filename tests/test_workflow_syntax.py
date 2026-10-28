"""Ensure every checked-in workflow is valid YAML before release."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml


class WorkflowSyntaxControls(unittest.TestCase):
    def test_every_workflow_parses_with_string_run_commands(self):
        paths = list((Path(__file__).resolve().parents[1] / '.github/workflows').glob('*.yml'))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path.name):
                value = yaml.safe_load(path.read_text(encoding='utf-8'))
                self.assertIsInstance(value['jobs'], dict)
                for job in value['jobs'].values():
                    for step in job['steps']:
                        if 'run' in step:
                            self.assertIsInstance(step['run'], str)

    def test_source_study_bytes_survive_windows_newline_conversion(self):
        root = Path(__file__).resolve().parents[1]
        attributes = (root / '.gitattributes').read_bytes()
        self.assertIn(b'source_study/** -text', attributes)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / '.gitattributes').write_bytes(attributes)
            (base / 'source_study').mkdir()
            samples = {'owned.py': b'first\nsecond\n', 'owned.txt': b'first\r\nsecond\r\n',
                       'owned.json.gz': b'\x1f\x8b\x00\r\n\x00'}
            for name, raw in samples.items():
                (base / 'source_study' / name).write_bytes(raw)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'core.autocrlf=true', '-C', str(base), *args], stderr=subprocess.PIPE)
            git('init', '-q')
            git('add', '.gitattributes', 'source_study')
            for name, raw in samples.items():
                self.assertEqual(git('cat-file', 'blob', ':source_study/' + name), raw)
                (base / 'source_study' / name).unlink()
            git('checkout-index', '-a')
            for name, raw in samples.items():
                self.assertEqual((base / 'source_study' / name).read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
