from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from relational_policy import extract_relational_adapter, compile_relational_seed

ADAPTER = b'''
from casbin import persist
from ..models import Role, Rule
class Adapter:
    def __init__(self):
        self.adapter_models = [Role, Rule]
    def load_policy(self, model):
        for db in self.adapter_models:
            for qs in db.objects.all():
                for item in qs.adapter():
                    values = list(item.values())
                    persist.load_policy_line(", ".join(values), model)
'''
MODELS = b'''
from django.db import models
class Role:
    rule = models.ManyToManyField(to="Rule", related_name="role", blank=True)
    def adapter(self):
        return [{"ptype":"g", "user":user.username, "role":self.name} for user in self.user.all()]
    class Meta:
        db_table = "owned_role"
class Rule:
    def adapter(self):
        return [{"ptype":"p", "role":role.name, "path":self.path, "method":self.method} for role in self.role.all()]
    class Meta:
        db_table = "owned_rules"
'''
USERS = b'''
from django.db import models
from apps.pgo_permission.models import Role
class UserProfile:
    role = models.ManyToManyField(to=Role, related_name="user", blank=True)
    class Meta:
        db_table = "owned_users"
'''


def fixture():
    content = []
    tables = {"owned_role": (["id", "name"], [(1, "reader")]),
              "owned_rules": (["id", "name", "path", "method"], [(2, "read docs", "/docs/*", "GET")]),
              "owned_users": (["id", "username", "password"], [(3, "alice", "never-project")]),
              "owned_role_rule": (["id", "role_id", "rule_id"], [(4, 1, 2)]),
              "owned_users_role": (["id", "userprofile_id", "role_id"], [(5, 3, 1)])}
    for table, (fields, rows) in tables.items():
        content.append("CREATE TABLE `" + table + "` (\n" + ",\n".join(" `" + field + "` text" for field in fields) + "\n) ENGINE=InnoDB;")
        for row in rows:
            values = [str(x) if type(x) is int else "'" + x + "'" for x in row]
            content.append("INSERT INTO `" + table + "` VALUES (" + ", ".join(values) + ");")
    return "\n".join(content).encode()


class RelationalTests(unittest.TestCase):
    def compile(self, models=MODELS, seed=None):
        return compile_relational_seed(extract_relational_adapter(ADAPTER, models, USERS), fixture() if seed is None else seed)

    def test_source_projection_matches_independent_native_relational_joins(self):
        result = self.compile()
        self.assertTrue(result["accepted"])
        self.assertEqual(result["produced_rows"], [["g", "alice", "reader"], ["p", "reader", "/docs/*", "GET"]])
        self.assertNotIn("never-project", repr(result))
        self.assertFalse(result["application_or_django_orm_executed"])
        self.assertTrue(result["source_projection_type_contract"]["admitted"])

    def test_source_dictionary_order_is_observed_not_assumed(self):
        changed = MODELS.replace(b'"user":user.username, "role":self.name', b'"role":self.name, "user":user.username')
        result = self.compile(changed)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["produced_rows"][0], ["g", "reader", "alice"])
        self.assertFalse(result["source_projection_type_contract"]["admitted"])

    def test_source_field_substitution_is_detected(self):
        result = self.compile(MODELS.replace(b'"path":self.path', b'"path":self.name'))
        self.assertFalse(result["accepted"])

    def test_missing_foreign_endpoint_and_duplicate_key_rejected(self):
        source = fixture()
        bad = source.replace(b"VALUES (5, 3, 1)", b"VALUES (5, 3, 999)")
        with self.assertRaises(AdmissionError):
            self.compile(seed=bad)
        with self.assertRaises(AdmissionError):
            self.compile(seed=source + b"\nINSERT INTO `owned_role` VALUES (1, 'duplicate');")

    def test_custom_relation_or_loader_not_silently_admitted(self):
        for a, m in ((ADAPTER.replace(b'load_policy(self, model)', b'load_policy(self, other)'), MODELS),
                     (ADAPTER, MODELS.replace(b'related_name="role"', b'related_name="other"'))):
            with self.assertRaises(AdmissionError):
                extract_relational_adapter(a, m, USERS)

    def test_source_effects_are_not_executed(self):
        descriptor = extract_relational_adapter(b'raise RuntimeError("not run")\n' + ADAPTER, MODELS, USERS)
        self.assertTrue(compile_relational_seed(descriptor, fixture())["accepted"])

    def test_lossy_csv_transport_is_rejected(self):
        with self.assertRaises(AdmissionError):
            self.compile(seed=fixture().replace(b"'/docs/*'", b"'/docs,a/*'"))

    def test_model_class_rebinding_or_external_method_mutation_rejected(self):
        for suffix in (b'\nRole = Unreviewed\n', b'\nRule.adapter = other_function\n', b'\nif condition:\n Role = Other\n'):
            with self.assertRaises(AdmissionError):
                self.compile(MODELS + suffix)


if __name__ == "__main__":
    unittest.main()
