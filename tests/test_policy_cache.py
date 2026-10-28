import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from checker import verify_reachable
from native_casbin import AdmissionError
from policy_cache import PolicySnapshot, cache_specification, export_policy_cache

ROOT = Path(__file__).resolve().parents[1]
MODEL = (ROOT / "external_inputs/casbin/basic_model.conf").read_text(encoding="utf-8")
RBAC = (ROOT / "external_inputs/casbin/rbac_model.conf").read_text(encoding="utf-8")
ROWS = [["alice", "records", "read"], ["bob", "reports", "write"]]


class PolicyCacheTests(unittest.TestCase):
    def test_complete_two_layer_observations_match_contract(self):
        result = export_policy_cache(MODEL, ROWS)
        self.assertTrue(result["accepted"])
        self.assertEqual(len(result["machine"]["observations"]), 16)
        self.assertEqual(result["native_enforce_calls"], 32)
        self.assertEqual(result["native_reload_calls"], 32)
        self.assertEqual(result["owned_producer_operations"], 64)

    def test_stale_grant_and_revoke_do_not_disappear_during_export(self):
        machine = export_policy_cache(MODEL, ROWS[:1])["machine"]
        state, decisions = 0, []
        for action in ("add", "authorize", "refresh", "authorize", "remove", "authorize", "refresh", "authorize"):
            decision, state = machine["transitions"][state][machine["alphabet"].index(["api", "permission_0", action])]
            decisions.append(decision)
        self.assertEqual(decisions, ["allow", "deny", "allow", "allow", "allow", "allow", "allow", "deny"])
        self.assertEqual(state, 0)

    def test_native_reload_rebuilds_role_links_after_removal(self):
        snapshot = PolicySnapshot(RBAC, [["p", "editor", "records", "read"], ["g", "alice", "editor"]])
        self.assertTrue(snapshot.enforce(["alice", "records", "read"]))
        self.assertTrue(snapshot.update("remove_policy", "g", "g", ["alice", "editor"]))
        self.assertTrue(snapshot.enforce(["alice", "records", "read"]))
        snapshot.reload()
        self.assertFalse(snapshot.enforce(["alice", "records", "read"]))

    def test_observed_nonempty_initial_store_and_cache_are_not_conflated(self):
        self.assertTrue(export_policy_cache(MODEL, ROWS, initial_store=2, initial_cache=1)["accepted"])

    def test_owned_lost_refresh_is_detected(self):
        result = export_policy_cache(MODEL, ROWS[:1])
        machine = copy.deepcopy(result["machine"])
        refresh = machine["alphabet"].index(["api", "permission_0", "refresh"])
        machine["transitions"][2][refresh] = ["allow", 2]
        outcome = verify_reachable(result["policy"], machine)
        self.assertFalse(outcome["accepted"])
        self.assertEqual(outcome["length"], 2)

    def test_claiming_immediate_visibility_without_reload_is_detected(self):
        result = export_policy_cache(MODEL, ROWS[:1])
        specification = copy.deepcopy(result["policy"])
        for rule in specification["rules"]:
            if any(atom.get("name") == "authorize" for atom in rule["guard"]):
                for atom in rule["guard"]:
                    if atom["field"] == "state":
                        atom["name"] = "store_0"
        outcome = verify_reachable(specification, result["machine"])
        self.assertFalse(outcome["accepted"])
        self.assertEqual(outcome["length"], 2)

    def test_aliases_duplicates_injection_and_envelopes_are_rejected(self):
        with self.assertRaises(AdmissionError):
            cache_specification(ROWS * 2)
        with self.assertRaises(AdmissionError):
            cache_specification([["a", "r" + str(i), "read"] for i in range(4)])
        with self.assertRaises(AdmissionError):
            PolicySnapshot(MODEL, [["p", *ROWS[0]], ["p", *ROWS[0]]])
        snapshot = PolicySnapshot(MODEL, [])
        with self.assertRaises(AdmissionError):
            snapshot.update("add_policy", "g", "p", ROWS[0])
        with self.assertRaises(AdmissionError):
            snapshot.update("add_policy", "p", "p", ["alice, admin", "records", "read"])

    def test_literal_database_fields_cannot_be_silently_trimmed_or_split(self):
        for user in (" alice ", "alice, admin", "alice\np, bob"):
            with self.assertRaises(AdmissionError):
                PolicySnapshot(MODEL, [["p", user, "records", "read"]])


if __name__ == "__main__":
    unittest.main()
