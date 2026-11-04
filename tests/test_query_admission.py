"""Owned normal-data admission controls, not third-party application execution."""
import ast
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'source_study/code'))
from query_guard_ir import Unsupported,compile_function


def lower(text, models=None, lookups=()):
    return compile_function(ast.parse(text).body[0],
                            {'Model.objects':'record'} if models is None else models,lookups)


class QueryAdmissionTests(unittest.TestCase):
    def test_parameter_and_assignment_cannot_replace_model_origin(self):
        for text in ('def f(Model):\n return Model.objects.all()',
                     'def f(user):\n Model=user\n return Model.objects.all()'):
            with self.subTest(text=text),self.assertRaises(Unsupported):lower(text)

    def test_later_write_is_a_local_binding_for_the_whole_body(self):
        with self.assertRaises(Unsupported):
            lower('def f(user):\n rows=Model.objects.all()\n Model=user\n return rows')

    def test_dotted_model_namespace_cannot_be_a_parameter(self):
        with self.assertRaises(Unsupported):
            lower('def f(models):\n return models.Record.objects.all()',
                  {'models.Record.objects':'record'})

    def test_lookup_parameter_and_local_assignment_do_not_resolve_globally(self):
        for text in ('def f(lookup):\n return lookup(Model.objects.all(),id=1)',
                     'def f(user):\n lookup=user\n return lookup(Model.objects.all(),id=1)'):
            with self.subTest(text=text),self.assertRaises(Unsupported):
                lower(text,lookups=('lookup',))

    def test_duplicate_filter_and_lookup_keywords_are_not_last_write_wins(self):
        for text in ('def f():\n return Model.objects.filter(owner=1,owner=2)',
                     'def f():\n return lookup(Model.objects.all(),id=1,id=2)'):
            with self.subTest(text=text),self.assertRaises(Unsupported):
                lower(text,lookups=('lookup',))

    def test_duplicate_parameters_are_not_collapsed_to_one_input(self):
        with self.assertRaises(Unsupported):
            lower('def f(user,user):\n return Model.objects.filter(owner=user)')

    def test_supported_aliases_and_complete_query_output_are_preserved(self):
        report=lower('def f(user):\n u=user\n return Model.objects.all().filter(owner=u).order_by("id")')
        self.assertEqual(report['parameters'],['user'])
        self.assertEqual(report['query'],['order',
            ['filter',['all','record'],[['owner',['input','user']]]],['id']])
        lookup=lower('def f(queryset):\n return lookup(queryset,id=1)',lookups=('lookup',))
        self.assertEqual(lookup['query'],['lookup',['input_query','queryset'],[['id',['constant',1]]]])


if __name__=='__main__':unittest.main()
