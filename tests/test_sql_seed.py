from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError
from sql_seed import project_seed


SEED = b"CREATE TABLE `owned` (\n `id` bigint,\n `name` text,\n `private` text\n) ENGINE=InnoDB;\nINSERT INTO `owned` VALUES (1, 'alpha', 'must-not-be-projected');\n"


class SeedTests(unittest.TestCase):
    def test_explicit_projection_discards_other_fields(self):
        result = project_seed(SEED, {"owned": ["id", "name"]})
        self.assertEqual(result["tables"]["owned"][0]["fields"], {"id": 1, "name": "alpha"})
        self.assertNotIn("must-not-be-projected", repr(result))
        self.assertFalse(result["sql_executed"])

    def test_mysql_quotes_escapes_null_and_integer(self):
        seed = SEED.replace(b"(1, 'alpha', 'must-not-be-projected')", b"(-2, 'a\\'b''c\\n', NULL)")
        result = project_seed(seed, {"owned": ["id", "name", "private"]})
        self.assertEqual(result["tables"]["owned"][0]["fields"], {"id": -2, "name": "a'b'c\n", "private": None})

    def test_sql_expression_is_not_executed_or_accepted(self):
        for changed in (SEED.replace(b"'alpha'", b"read_file('/not-run')"),
                        SEED.replace(b"VALUES (", b"(id,name,private) VALUES ("),
                        SEED.replace(b"'alpha'", b"'x' COLLATE unreviewed")):
            with self.assertRaises(AdmissionError):
                project_seed(changed, {"owned": ["id", "name"]})

    def test_multirow_and_multiline_inserts_are_not_silently_omitted(self):
        for changed in (SEED.replace(b"'must-not-be-projected');", b"'secret'), (2,'x','y');"),
                        SEED.replace(b"INSERT INTO", b" insert into"),
                        SEED.replace(b" VALUES (", b" VALUES\n(")):
            with self.assertRaises(AdmissionError):
                project_seed(changed, {"owned": ["id", "name"]})

    def test_missing_duplicate_or_unknown_schema_rejected(self):
        for changed, request in ((SEED, {"owned": ["missing"]}), (SEED + SEED, {"owned": ["id"]}),
                                 (SEED, {"absent": ["id"]})):
            with self.assertRaises(AdmissionError):
                project_seed(changed, request)

    def test_unselected_tables_are_not_inputs(self):
        source = SEED + b"INSERT INTO `unselected` VALUES (unreviewed_function());\n"
        self.assertEqual(project_seed(source, {"owned": ["id"]})["source_rows"], 1)

    def test_selected_mutation_is_not_silently_ignored(self):
        for command in (b"UPDATE `owned` SET name='other';", b"DELETE FROM owned;", b"REPLACE INTO `owned` VALUES (2,'x','y');"):
            with self.assertRaises(AdmissionError):
                project_seed(SEED + command + b"\n", {"owned": ["id", "name"]})

    def test_integer_transport_bound_is_explicit(self):
        with self.assertRaises(AdmissionError):
            project_seed(SEED.replace(b"VALUES (1,", b"VALUES (18446744073709551615,"), {"owned": ["id"]})

    def test_bad_projection_type_is_a_typed_rejection(self):
        for request in ({"owned": 3}, {"owned": "id"}, {1: ["id"]}):
            with self.assertRaises(AdmissionError):
                project_seed(SEED, request)


if __name__ == "__main__":
    unittest.main()
