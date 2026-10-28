import ast
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from source_bindings import require_import_bindings, require_static_class_members
from native_casbin import AdmissionError


class SourceBindingTests(unittest.TestCase):
    def check(self, source):
        return require_import_bindings(source, {"filtering": ("owned.scope", 0, "tenant_filtered")})

    def test_direct_renamed_import(self):
        self.assertIn("filtering", self.check(b'from owned.scope import tenant_filtered as filtering\n')["verified_direct_imports"])

    def test_wrong_import_or_missing_binding(self):
        for source in (b'from other.scope import tenant_filtered as filtering\n', b'pass\n'):
            with self.assertRaises(AdmissionError):
                self.check(source)

    def test_direct_and_tuple_rebinding(self):
        for suffix in (b'filtering = other\n', b'filtering, x = other, 1\n', b'del filtering\n'):
            with self.assertRaises(AdmissionError):
                self.check(b'from owned.scope import tenant_filtered as filtering\n' + suffix)

    def test_conditional_rebinding_and_import(self):
        for source in (b'if condition:\n from owned.scope import tenant_filtered as filtering\n',
                       b'from owned.scope import tenant_filtered as filtering\nif condition:\n filtering = other\n'):
            with self.assertRaises(AdmissionError):
                self.check(source)

    def test_attribute_mutation_and_wildcard(self):
        for suffix in (b'filtering.attribute = other\n', b'from unreviewed import *\n'):
            with self.assertRaises(AdmissionError):
                self.check(b'from owned.scope import tenant_filtered as filtering\n' + suffix)

    def test_function_local_names_do_not_rebind_module(self):
        source = b'from owned.scope import tenant_filtered as filtering\ndef f():\n filtering = other\n'
        self.assertIn("filtering", self.check(source)["verified_direct_imports"])

    def test_duplicate_function_export_is_not_a_clean_binding(self):
        with self.assertRaises(AdmissionError):
            self.check(b'from owned.scope import tenant_filtered as filtering\ndef filtering():\n pass\n')

    def test_class_method_locals_do_not_rebind_the_selected_member(self):
        cls = ast.parse('class C:\n def check(self):\n  check = 1\n  return check\n').body[0]
        require_static_class_members(cls, {"check"})

    def test_conditional_class_rebindings_and_duplicate_methods_are_rejected(self):
        for suffix in (' if choice:\n  check = other\n', ' if choice:\n  def check(self):\n   return False\n'):
            cls = ast.parse('class C:\n def check(self):\n  return True\n' + suffix).body[0]
            with self.assertRaises(AdmissionError):
                require_static_class_members(cls, {"check"})

    def test_custom_class_attribute_hooks_need_a_different_contract(self):
        cls = ast.parse('class C:\n def check(self):\n  return True\n def __getattr__(self, name):\n  return None\n').body[0]
        with self.assertRaises(AdmissionError):
            require_static_class_members(cls, {"check"})


if __name__ == "__main__":
    unittest.main()
