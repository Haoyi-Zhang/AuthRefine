import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from native_casbin import AdmissionError, _engine
from tenant_dependency import extract_tenant_dependency
from tenant_lookup import extract_tenant_lookup, compare_tenant_lookup
from tenant_routes import SCHEMA, admit_tenant_routes
from test_tenant_dependency import SOURCE as DEPENDENCY

LOOKUP = b'''
import uuid
from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from dlw.authz.deps import require_perm
from dlw.db.tenant_scope import tenant_filtered
from dlw.db.models.task import DownloadTask
from dlw.schemas.task import TaskDetail
@router.get("/{task_id}")
async def get_task(task_id: uuid.UUID,
                   principal=Depends(require_perm("/api/v1/tasks*", "GET")),
                   session=Depends(_session)):
    row = (await session.execute(
        tenant_filtered(select(DownloadTask).where(DownloadTask.id == task_id), DownloadTask, principal)
        .options(selectinload(DownloadTask.subtasks))
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="task not found")
    return TaskDetail.model_validate(row)
'''
FILTER = b'def tenant_filtered(stmt, model, principal):\n return stmt.where(model.tenant_id == principal.tenant_id)\n'


class TenantLookupTests(unittest.TestCase):
    def setUp(self):
        model = "\n".join("[" + section + "]\n" + "\n".join(k + " = " + v for k, v in fields.items())
                          for section, fields in SCHEMA.items())
        policy = '\n'.join('p, role:' + role + ', /api/v1/tasks*, ^GET$, tenant_match' for role in ("tenant_operator", "tenant_viewer"))
        self.engine = _engine(admit_tenant_routes(model, policy))

    def compare(self, source=LOOKUP, filtering=FILTER):
        return compare_tenant_lookup(source, "get_task", extract_tenant_dependency(DEPENDENCY), self.engine, filtering)

    def test_native_composed_lookup(self):
        report = self.compare()
        self.assertTrue(report["accepted"])
        self.assertEqual(len(report["cases"]), 36)
        self.assertEqual(report["native_select_executions"], 24)
        self.assertFalse(report["application_endpoint_or_database_executed"])

    def test_missing_filter_is_not_hidden_by_native_policy_success(self):
        result = self.compare(filtering=b'def tenant_filtered(stmt, model, principal):\n return stmt\n')
        self.assertFalse(result["accepted"])
        self.assertTrue(any(row["observed_status"] == 200 and row["expected_status"] == 404 for row in result["cases"]))

    def test_changed_principal_or_model_rejected(self):
        for bad in (LOOKUP.replace(b'DownloadTask, principal)', b'DownloadTask, other_principal)'),
                    LOOKUP.replace(b'select(DownloadTask)', b'select(OtherTask)')):
            with self.assertRaises(AdmissionError):
                extract_tenant_lookup(bad, "get_task")

    def test_additional_endpoint_effect_rejected(self):
        bad = LOOKUP.replace(b'    return TaskDetail', b'    await perform_unreviewed_action()\n    return TaskDetail')
        with self.assertRaises(AdmissionError):
            extract_tenant_lookup(bad, "get_task")

    def test_untrusted_module_is_not_executed(self):
        self.assertTrue(self.compare(b'raise RuntimeError("never run")\n' + LOOKUP)["accepted"])

    def test_namespace_rebinding_cannot_retain_a_clean_result(self):
        for changed in (LOOKUP + b'\ntenant_filtered = unreviewed\n',
                        LOOKUP + b'\nif external_condition:\n tenant_filtered = unreviewed\n'):
            with self.assertRaises(AdmissionError):
                self.compare(changed)


if __name__ == "__main__":
    unittest.main()
