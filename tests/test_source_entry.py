"""Exercise the real passive entry and prevent citation/scope drift."""
import contextlib
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
import warnings
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'source_study'))
from inspect_source import analyze_archive,main


class SourceEntryChecks(unittest.TestCase):
    def archive(self,directory,source,extra=()):
        path=Path(directory)/'source.zip'
        with zipfile.ZipFile(path,'w') as z:
            z.comment=b'owned-example';z.writestr('owned/app.py',source)
            for name,value in extra:
                info=zipfile.ZipInfo('fixture');info.filename=name
                z.writestr(info,value)
        return path

    def test_cli_reports_links_without_executing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=self.archive(tmp,'from fastapi import APIRouter, Depends\n'
                'raise RuntimeError("source must not execute")\n'
                'router=APIRouter()\ndef guard():return False\n'
                '@router.get("/")\ndef endpoint(user=Depends(guard)):return user\n')
            out=io.StringIO()
            with contextlib.redirect_stdout(out):main([str(path)])
        result=json.loads(out.getvalue())
        for method in ('baseline','guarded'):
            self.assertEqual(result['summary'][method]['declared_routes'],1)
            self.assertEqual(result['summary'][method]['routes_with_all_declared_direct_dependencies_linked'],1)
        self.assertFalse(result['source_modules_or_tests_executed'])
        self.assertIsNone(result['semantic_authorization_verdict'])

    def test_no_routes_is_unsupported_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=analyze_archive(self.archive(tmp,'def helper():return True\n'))
        self.assertEqual(result['summary']['guarded']['status'],'unsupported_framework_or_route_form')
        self.assertIsNone(result['semantic_authorization_verdict'])

    def test_missing_dependency_remains_unresolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=analyze_archive(self.archive(tmp,'from fastapi import APIRouter,Depends\n'
                'from unavailable import guard\nrouter=APIRouter()\n'
                '@router.get("/")\ndef endpoint(user=Depends(guard)):return user\n'))
        self.assertEqual(result['summary']['guarded']['routes_with_unresolved_declared_dependencies'],1)

    def test_reject_ambiguous_and_escaping_members(self):
        for member in ('owned/../escape.py','/absolute.py','other/app.py','root.py','owned\\bad.py'):
            with self.subTest(member=member),tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):analyze_archive(self.archive(tmp,'pass\n',[(member,'pass\n')]))
        with tempfile.TemporaryDirectory() as tmp,warnings.catch_warnings():
            warnings.simplefilter('ignore',UserWarning)
            with self.assertRaises(ValueError):analyze_archive(self.archive(tmp,'pass\n',[('owned/app.py','pass\n')]))

    def test_invalid_cli_has_no_success_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=self.archive(tmp,'pass\n',[('root.py','pass\n')]);out=io.StringIO();err=io.StringIO()
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                with self.assertRaises(SystemExit) as caught:main([str(path)])
        self.assertEqual(caught.exception.code,2);self.assertEqual(out.getvalue(),'')
        self.assertIn('source input not admitted',err.getvalue())

    def test_passive_non_python_document_names_do_not_exclude_a_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=analyze_archive(self.archive(tmp,'pass\n',[('owned/docs/note: title.md','passive text')]))
        self.assertEqual(result['guarded']['parsed_modules'],1)

    def test_citations_match_approved_author_order(self):
        text=(ROOT/'CITATION.cff').read_text(encoding='utf-8')
        first,preferred=text.split('preferred-citation:',1)
        names=lambda value:re.findall(r'family-names: "([^"]+)"\s+given-names: "([^"]+)"',value)
        expected=[('Zhang','Haoyi'),('Ran','Huaijin'),('Yu','Jiongchi'),('Sun','Yuqiang'),('Liu','Yang')]
        self.assertEqual(names(first),expected);self.assertEqual(names(preferred),expected)


if __name__=='__main__':unittest.main()
