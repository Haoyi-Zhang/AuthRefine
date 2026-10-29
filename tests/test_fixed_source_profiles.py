from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'source_study'))
from complete_profiles import verify


class FixedSourceProfiles(unittest.TestCase):
    def test_source_replay_and_complete_observation_consumer(self):
        result=verify()
        self.assertEqual(result['pretix_token_event_contexts'],288)
        self.assertEqual(result['pretix_differences'],0)
        self.assertTrue(result['H19_source_replay_and_checker_agree'])
    def test_negative_H19_result_is_not_turned_into_a_pass(self):
        result=verify()
        self.assertEqual(result['H19_nonagreeing_properties'],{'before':26,'after':18})
        self.assertTrue(result['historical_installed_version_not_inferred'])


if __name__=='__main__':unittest.main()
