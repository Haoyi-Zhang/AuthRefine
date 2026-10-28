from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from entry_guard_prefix import compare_entry_prefixes, extract_entry_prefixes
from native_casbin import AdmissionError


SOURCE = b'''@unknown_class_decorator
class Service(UnknownBase):
 def guard(self, group, field_name, message):
  if group.defining_project_id is not None or group.defining_workspace_id is not None:
   raise ValidationError({field_name: message})
 @unknown_method_decorator
 def add(self, request, **kwargs):
  obj = self.get_object()
  self.perm_check(request, obj)
  self.guard(obj, "project_id", gettext("Scoped team"))
  if "project_id" not in request.data:
   dangerous_tail_not_executed()
  arbitrary_tail()
'''


class EntryPrefixTests(unittest.TestCase):
    def compare(self, source):
        return compare_entry_prefixes(source, "Service", {"add": "project_id"},
            {"add": frozenset({"project", "workspace"})})

    def test_guard_preserves_error_order_and_uninterpreted_tail(self):
        result = self.compare(SOURCE)
        self.assertTrue(result["comparison"]["accepted"])
        self.assertEqual(len(result["contexts"]), 12)
        self.assertFalse(result["descriptor"]["runtime_dispatch_or_inheritance_proved"])
        self.assertTrue(result["descriptor"]["reaches_tail_is_not_access_grant"])
        self.assertEqual(result["descriptor"]["class_decorators_not_executed"], ["unknown_class_decorator"])
        self.assertEqual(result["descriptor"]["entries"][0]["unexamined_tail_statements"], 2)

    def test_missing_helper_is_observable_not_unsupported(self):
        source = SOURCE.replace(b'  self.guard(obj, "project_id", gettext("Scoped team"))\n', b"")
        result = self.compare(source)
        self.assertFalse(result["comparison"]["accepted"])
        self.assertEqual(result["different_contexts"], 2)

    def test_wrong_predicate_is_not_hidden_by_same_exception_type(self):
        result = self.compare(SOURCE.replace(b" is not None or ", b" is not None and "))
        self.assertEqual(result["different_contexts"], 2)

    def test_changed_prefix_and_unknown_boundary_never_scan_past_changes(self):
        for source in (SOURCE.replace(b"  self.perm_check(request, obj)", b"  other()\n  self.perm_check(request, obj)"),
                       SOURCE.replace(b'  if "project_id" not in request.data:', b"  arbitrary()\n  if True:"),
                       SOURCE.replace(b'gettext("Scoped team")', b"dynamic_message()"),
                       SOURCE.replace(b'obj, "project_id", gettext', b'obj, "other_id", gettext')):
            with self.assertRaises(AdmissionError):
                self.compare(source)

    def test_rebindings_and_dynamic_attributes_need_separate_contract(self):
        for extra in (b"Service = other\n", b"bool = other\n", b"\n def __getattr__(self, name):\n  return True\n",
                      b"\n if flag:\n  guard = other\n"):
            with self.assertRaises(AdmissionError):
                self.compare(SOURCE + extra)

    def test_contract_must_cover_every_selected_entry(self):
        with self.assertRaises(ValueError):
            compare_entry_prefixes(SOURCE, "Service", {"add": "project_id"}, {})
        with self.assertRaises(AdmissionError):
            extract_entry_prefixes(SOURCE, "Service", {"missing": "project_id"})


if __name__ == "__main__":
    unittest.main()
