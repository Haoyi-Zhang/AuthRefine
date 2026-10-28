from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError, _schema
from threadpool_roles import compare_domain_updates, extract_domain_updates, native_domain_engine

MODEL = "\n".join("[" + section + "]\n" + "\n".join(key + " = " + value for key, value in row.items())
                  for section, row in _schema("rbac_with_domains").items()).replace("r.obj == p.obj", "keyMatch(r.obj, p.obj)")
SOURCE = b'''from fastapi.concurrency import run_in_threadpool
from app.core import casbin_enforcer as _casbin_mod
class PermissionService:
    async def add_role_for_user_in_domain(self, user_id, role, tenant_id):
        def _do():
            e = _casbin_mod.get_enforcer()
            with _casbin_mod.enforcer_lock():
                e.add_role_for_user_in_domain(user_id, role, tenant_id)
        await run_in_threadpool(_do)
    async def set_role_for_user_in_domain(self, user_id, role, tenant_id):
        def _do():
            e = _casbin_mod.get_enforcer()
            with _casbin_mod.enforcer_lock():
                for old in e.get_roles_for_user_in_domain(user_id, tenant_id):
                    e.delete_roles_for_user_in_domain(user_id, old, tenant_id)
                e.add_role_for_user_in_domain(user_id, role, tenant_id)
        await run_in_threadpool(_do)
    async def remove_user_from_tenant(self, user_id, tenant_id):
        def _do():
            e = _casbin_mod.get_enforcer()
            with _casbin_mod.enforcer_lock():
                for old in e.get_roles_for_user_in_domain(user_id, tenant_id):
                    e.delete_roles_for_user_in_domain(user_id, old, tenant_id)
        await run_in_threadpool(_do)
'''


class ThreadpoolRoleTests(unittest.TestCase):
    def compare(self, source=SOURCE):
        return compare_domain_updates(source, MODEL, engine_factory=native_domain_engine)

    def test_serial_grouping_and_native_consumer_match_independent_set_contract(self):
        result = self.compare()
        self.assertTrue(result["accepted"])
        self.assertEqual(len(result["cases"]), 40)
        self.assertEqual(result["native_operations"]["enforce"], 40)
        self.assertFalse(result["database_scd2_commit_adapter_or_threadpool_verified"])

    def test_replacement_drops_multiple_old_roles_and_preserves_other_scopes(self):
        result = self.compare()
        selected = [i for i, row in enumerate(result["cases"]) if row["initial_target_roles"] == ["reader", "writer"] and row["operation"] == "set" and row["requested_role"] == "reader"]
        self.assertEqual(len(selected), 2)
        for i in selected:
            self.assertFalse(result["observed"][i]["flags"]["writer_retained"])
            self.assertTrue(result["observed"][i]["flags"]["other_user_intact"])
            self.assertTrue(result["observed"][i]["flags"]["other_tenant_intact"])

    def test_owned_domain_role_swap_is_detected_not_a_configuration_change(self):
        source = SOURCE.replace(b"e.add_role_for_user_in_domain(user_id, role, tenant_id)", b"e.add_role_for_user_in_domain(user_id, tenant_id, role)")
        result = self.compare(source)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["comparison"]["first_counterexample"]["length"], 1)
        self.assertEqual(result["native_policy_rows"], self.compare()["native_policy_rows"])

    def test_owned_wrong_removal_scope_is_detected(self):
        source = SOURCE.replace(b"e.delete_roles_for_user_in_domain(user_id, old, tenant_id)", b"e.delete_roles_for_user_in_domain(user_id, tenant_id, old)")
        self.assertFalse(self.compare(source)["accepted"])

    def test_lost_await_lock_or_extra_statement_is_unsupported(self):
        for old, new in ((b"await run_in_threadpool(_do)", b"run_in_threadpool(_do)"),
                         (b"_casbin_mod.enforcer_lock()", b"other_lock()"),
                         (b"        await run_in_threadpool(_do)", b"        await run_in_threadpool(_do)\n        return True")):
            with self.subTest(old=old), self.assertRaises(AdmissionError):
                extract_domain_updates(SOURCE.replace(old, new))

    def test_native_argument_arity_and_import_shadowing_are_not_guessed(self):
        for old, new in ((b"user_id, old, tenant_id)", b"user_id, tenant_id)"),
                         (b"from app.core import casbin_enforcer as _casbin_mod", b"from other import casbin_enforcer as _casbin_mod")):
            with self.subTest(old=old), self.assertRaises(AdmissionError):
                extract_domain_updates(SOURCE.replace(old, new))

    def test_source_or_database_side_effects_are_not_run(self):
        descriptor = extract_domain_updates(b"raise RuntimeError('must never run')\n" + SOURCE)
        self.assertFalse(descriptor["source_module_executed"])
        self.assertFalse(descriptor["threadpool_or_real_lock_executed"])

    def test_conditional_method_rebinding_is_not_a_static_body(self):
        with self.assertRaises(AdmissionError):
            extract_domain_updates(SOURCE + b"\n    if True:\n        set_role_for_user_in_domain = None\n")

    def test_matcher_or_model_defaults_require_a_separate_contract(self):
        for model in (MODEL.replace("keyMatch(r.obj, p.obj)", "True"), "[DEFAULT]\nx=1\n" + MODEL):
            with self.subTest(model=model), self.assertRaises(AdmissionError):
                native_domain_engine(model, [], [])

    def test_parser_and_work_budget_failures_are_not_passes(self):
        for source in (b"def", b"x" * 1_048_577):
            with self.subTest(source=source[:10]), self.assertRaises(AdmissionError):
                extract_domain_updates(source)

    def test_native_exception_is_retained_not_normalized_to_plain_denial(self):
        def factory(model, policies, grouping):
            engine = native_domain_engine(model, policies, grouping)
            class NativeFailureControl:
                def __getattr__(self, name):
                    if name == "delete_roles_for_user_in_domain":
                        def fail(*args):
                            raise TypeError("owned incompatible API control")
                        return fail
                    return getattr(engine, name)
            return NativeFailureControl()
        result = compare_domain_updates(SOURCE, MODEL, engine_factory=factory)
        self.assertFalse(result["accepted"])
        self.assertTrue(any(row["flags"]["native_error"] for row in result["observed"]))


if __name__ == "__main__":
    unittest.main()
