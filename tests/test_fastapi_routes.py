from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from fastapi_routes import extract_router, extract_mounts
from native_casbin import AdmissionError

SOURCE = b'''
from fastapi import APIRouter, Depends
from ..auth import require_permission, require_scope, require_role
router = APIRouter(prefix="/documents", dependencies=[Depends(require_scope("documents"))])
@router.get("/{identifier}", dependencies=[Depends(require_permission("read"))])
async def retrieve(identifier, context=Depends(require_role("viewer"))):
    unreviewed_endpoint_effect()
'''


class FastAPIRouteTests(unittest.TestCase):
    def test_router_decorator_and_parameter_dependencies_are_all_retained(self):
        result = extract_router(SOURCE, "api.routes.documents")
        self.assertEqual(len(result["routes"]), 1)
        route = result["routes"][0]
        self.assertEqual([g["factory"] for g in route["guards"]], ["require_scope", "require_permission", "require_role"])
        self.assertEqual(route["resource_contract"], "documents")
        self.assertFalse(route["endpoint_body_verified"])
        self.assertEqual(route["unresolved"], [])

    def test_unknown_dependencies_are_not_silently_skipped(self):
        route = extract_router(SOURCE.replace(b'require_permission("read")', b'custom_guard()'), "module")["routes"][0]
        self.assertEqual(len(route["unresolved"]), 1)

    def test_binding_redefinition_is_rejected(self):
        with self.assertRaises(AdmissionError):
            extract_router(SOURCE + b'\nrequire_permission = None\n', "module")

    def test_mounts_are_source_declarations_not_running_services(self):
        mounts = extract_mounts(b'def create_app():\n    app.include_router(documents.router, prefix="/api/v1")\n')
        self.assertEqual(mounts[0]["prefix"], "/api/v1")
        self.assertFalse(mounts[0]["registration_executed"])

    def test_extra_decorator_and_nonliteral_dependencies_stay_unresolved(self):
        altered = SOURCE.replace(b'@router.get', b'@another_decorator\n@router.get')
        self.assertTrue(extract_router(altered, "module")["routes"][0]["unresolved"])

    def test_annotated_dependency_is_not_omitted(self):
        altered = SOURCE.replace(b'context=Depends(require_role("viewer"))', b'context: Annotated[object, Depends(require_role("viewer"))]')
        route = extract_router(altered, "module")["routes"][0]
        self.assertEqual([g["factory"] for g in route["guards"]], ["require_scope", "require_permission", "require_role"])

    def test_aliased_security_and_dynamic_defaults_remain_unresolved(self):
        for header, parameter in ((b'from fastapi import Security as Gate\n', b'context=Gate(custom_guard)'),
                                  (b'', b'context=custom_dependency_factory()')):
            altered = header + SOURCE.replace(b'context=Depends(require_role("viewer"))', parameter)
            self.assertTrue(extract_router(altered, "module")["routes"][0]["unresolved"])
        altered = SOURCE.replace(b'dependencies=[Depends(require_permission("read"))]', b'dependencies=other_dependencies')
        self.assertTrue(extract_router(altered, "module")["routes"][0]["unresolved"])


if __name__ == "__main__":
    unittest.main()
