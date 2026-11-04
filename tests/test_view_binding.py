"""Owned declaration mutations and strict control-outcome separation."""
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'adaptation_study'))
from profiles import check_control, ProfileMismatch, Unsupported
import profiles
from view_binding import declarations, source_view_gate, native_base_facts

ITEM = b'''from rest_framework import viewsets
from pretix.api.views import ConditionalListView
class ItemViewSet(ConditionalListView, viewsets.ModelViewSet):
    permission = None
    write_permission = 'event.items:write'
    def get_queryset(self):
        return None
'''
BASE = b'class ConditionalListView:\n    def list(self, request):\n        return None\n'


class SourceViewBindingTests(unittest.TestCase):
    def test_current_original_nine_declarations_resolve_without_loading_application(self):
        path = ROOT / 'source_study/source/pretix/src/pretix/api/views/item.py'
        result = declarations(path.read_bytes(), (ROOT / 'adaptation_study/pretix-view-base.txt').read_bytes())
        self.assertEqual(len(result['views']), 9)
        self.assertTrue(all(row['fields'] == {'permission': None, 'write_permission': 'event.items:write'}
                            for row in result['views']))
        self.assertFalse(result['original_application_modules_executed'])

    def test_literal_slots_keep_their_actual_source_lines(self):
        row = declarations(ITEM, BASE)['views'][0]
        self.assertEqual(row['source_lines'], {'permission': 4, 'write_permission': 5})

    def test_conditional_and_repeated_rebinding_are_unknown(self):
        for extra in (b"    write_permission = None\n", b"    if True:\n        permission = None\n"):
            with self.assertRaises(Unsupported):
                declarations(ITEM + extra, BASE)

    def test_dynamic_hook_and_instance_mutation_are_unknown(self):
        for extra in (b'    def _get_permission_name(self, request):\n        return None\n',
                      b'    def change(self):\n        self.permission = None\n',
                      b'    def change(self):\n        setattr(self, "permission", None)\n'):
            with self.assertRaises(Unsupported):
                declarations(ITEM + extra, BASE)

    def test_unresolved_import_base_and_mixin_are_unknown(self):
        for item, base in ((ITEM + b'viewsets = None\n', BASE),
                           (ITEM.replace(b'viewsets.ModelViewSet', b'UnknownView'), BASE),
                           (ITEM, BASE + b'    permission = None\n')):
            with self.assertRaises(Unsupported):
                declarations(item, base)

    def test_unresolved_native_base_and_runtime_overrides_are_unknown(self):
        with self.assertRaises(Unsupported):
            native_base_facts(object, ROOT)
        with self.assertRaises(Unsupported):
            source_view_gate(object, ROOT, instance_overrides={'permission': None})

    def test_only_actual_contract_mismatch_counts_as_detected_control(self):
        def mismatch(control):
            raise ProfileMismatch('actual changed observation')
        self.assertTrue(check_control(mismatch, 'owned')['deliberate_fault_detected'])

    def test_setup_and_unknown_failures_never_count_as_detected_control(self):
        for exception in (ValueError('bad setup'), RuntimeError('missing runtime'), Unsupported('not admitted')):
            def fail(control):
                raise exception
            with self.assertRaises(type(exception)):
                check_control(fail, 'owned')
            # Exercise the actual CLI dispatcher, not only its helper.
            with patch.object(sys, 'argv', ['profiles.py', '--control', 'drop_save']), \
                    patch.object(profiles, 'healthchecks', side_effect=exception):
                with self.assertRaises(type(exception)):
                    profiles.main()
        with self.assertRaises(ValueError):
            check_control(lambda control: None, 'owned')


if __name__ == '__main__':
    unittest.main()
