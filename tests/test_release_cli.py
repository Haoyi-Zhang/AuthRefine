import json
from pathlib import Path
import tempfile
import unittest

import verify_release


class ReleaseCliContractTests(unittest.TestCase):
    def test_campaign_command_passes_fresh_output_and_frozen_baseline(self):
        output = Path("/temporary/run-output")
        baseline = Path("/artifact/results")
        command = verify_release.campaign_command(output, baseline)
        self.assertEqual(command[1], "reproduce.py")
        self.assertEqual(command[command.index("--output") + 1], str(output))
        self.assertEqual(command[command.index("--compare") + 1], str(baseline))

    def test_campaign_acceptance_requires_materialized_records_not_return_code_only(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            output = Path(temporary_name)
            (output / "summary.json").write_text(
                json.dumps({"primary_cases": 10000, "baseline_scientific_records_match": True})
            )
            (output / "reproduction.json").write_text(
                json.dumps(
                    {
                        "primary_cases": 10000,
                        "baseline_scientific_records_match": True,
                        "fresh_archive_extraction": True,
                        "resumed": False,
                        "documented_commands_succeeded": True,
                        "execution_environment": {
                            "platform": "Linux",
                            "peak_rss_unit": "KiB",
                            "python_hash_seed": "1729",
                            "timezone": "UTC",
                        },
                    }
                )
            )
            with self.assertRaises(ValueError):
                verify_release.inspect_campaign_output(
                    output,
                    expected_seed="1729",
                    expected_timezone="UTC",
                )


if __name__ == "__main__":
    unittest.main()
