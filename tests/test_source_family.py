from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from source_family import claim_reference_family, diagnose_source_family
from test_token_roles import USER, ENUM, MODEL, POLICY

RECORDS = [{"preferred_username": "reader", "resource_access": {"app": {"roles": ["viewer"]}}},
           {"preferred_username": "administrator", "resource_access": {"app": {"roles": ["admin"]}}},
           {"preferred_username": "outsider"}]
CANDIDATES = ["admin", "app:admin", "other-client:admin"]


class SourceFamilyTests(unittest.TestCase):
    def check(self, source=USER, records=RECORDS, candidates=CANDIDATES, bypass=True):
        return claim_reference_family(source, ENUM, MODEL, POLICY, records, "app:admin", candidates, bypass)

    def test_source_observations_select_the_qualified_setting_interpretation(self):
        result = self.check()
        self.assertEqual(result["classification"], "some")
        self.assertEqual(result["bindings"], 3)
        self.assertEqual(result["matching_bindings"], 1)
        tag = next(row["role_observation"] for row in result["reference_candidates"] if row["source_setting_value"] == "app:admin")
        self.assertEqual(result["matching_interpretations"], [{"configured-admin-role": tag}])
        self.assertEqual(result["strata"], {"1": 2, "infinity": 1})
        self.assertEqual(result["native_request_cells"], 18)
        self.assertTrue(result["algorithms_agree"])
        self.assertFalse(result["whole_application_verified"])

    def test_every_failing_interpretation_retains_one_fixed_replay(self):
        result = self.check()
        for row in result["profiles"]:
            if not row["equivalent"]:
                self.assertEqual(row["length"], len(row["indices"]))
                self.assertTrue(all(step["binding"] == row["binding"] for step in row["trace"]))
                self.assertTrue(all(step["compared_equal"] for step in row["trace"][:-1]))
                self.assertFalse(row["trace"][-1]["compared_equal"])

    def test_owned_producer_error_is_not_explained_away_by_a_setting_choice(self):
        result = self.check(source=USER.replace(b'f"{key}:{r}"', b'f"{key}-{r}"'))
        self.assertEqual(result["classification"], "none")
        self.assertEqual(result["matching_bindings"], 0)
        self.assertTrue(all(row["length"] == 1 for row in result["profiles"]))

    def test_unused_reference_is_observationally_uniform_not_a_false_alarm(self):
        result = self.check(bypass=False)
        self.assertEqual(result["classification"], "all")
        self.assertEqual(result["matching_bindings"], 3)
        self.assertEqual(result["strata"], {"infinity": 3})

    def test_missing_true_candidate_is_not_silently_added(self):
        result = self.check(candidates=["admin", "other-client:admin"])
        self.assertEqual(result["classification"], "none")
        self.assertEqual(result["bindings"], 2)

    def test_duplicate_principals_or_candidates_are_not_merged(self):
        for records, candidates in (([RECORDS[0], RECORDS[0]], CANDIDATES), (RECORDS, ["app:admin", "app:admin"])):
            with self.assertRaises(AdmissionError):
                self.check(records=records, candidates=candidates)

    def test_owned_inputs_are_unchanged(self):
        before = deepcopy((RECORDS, CANDIDATES))
        self.check()
        self.assertEqual((RECORDS, CANDIDATES), before)

    def test_zero_budget_or_narrow_family_cap_is_inconclusive(self):
        result = self.check()
        from checker import Rejected
        for kwargs in ({"work_budget": 0}, {"family_limit": 2}):
            with self.assertRaises((AdmissionError, Rejected)) as caught:
                diagnose_source_family(result["policy"], result["machine"], **kwargs)
            self.assertEqual(getattr(caught.exception, "status", getattr(caught.exception, "kind", None)), "inconclusive")


if __name__ == "__main__":
    unittest.main()
