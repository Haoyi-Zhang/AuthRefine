"""Ensure every checked-in workflow is valid YAML before release."""
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
