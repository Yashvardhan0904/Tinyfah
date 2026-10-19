from fastapi import APIRouter, Query
from app.loaders.asvs import get_all_chapters, get_test_suite
from app.loaders.tinyfah import get_chapter_requirements

router = APIRouter(prefix="/asvs", tags=["ASVS"])

@router.get("/chapters")
def list_asvs_chapters():
    """Returns all 17 OWASP ASVS chapters with section counts."""
    return {"chapters": get_all_chapters()}

@router.get("/tests")
def get_asvs_tests(suite: str = Query("chapter_sample", description="Test suite type")):
    """Returns the tests that will be run for the given suite type."""
    if suite in ["v1", "chapter_v1"]:
        v1_reqs = get_chapter_requirements("V1")
        return {
            "suite": suite,
            "chapter": "V1 Encoding and Sanitization",
            "count": len(v1_reqs),
            "tests": v1_reqs,
        }
    tests = get_test_suite(suite)
    return {
        "suite": suite,
        "count": len(tests),
        "tests": tests,
    }
