from fastapi import APIRouter, HTTPException
from app.loaders.tinyfah import (
    get_chapter_requirements,
    get_input_legend,
    get_mode_legend,
)
from harness.registry import (
    list_registered_tests,
    list_script_definitions,
    get_script_definition,
)
import harness.scripts.v1_encoding  # Ensures V1 script definitions and registered tests are loaded

router = APIRouter(prefix="/api/harness/v1", tags=["Harness"])

@router.get("/requirements")
def list_v1_requirements():
    """Returns all Chapter V1 requirements loaded directly from Tinyfah.json."""
    reqs = get_chapter_requirements("V1")
    return {
        "chapter": "V1 Encoding and Sanitization",
        "count": len(reqs),
        "requirements": reqs,
        "input_legend": get_input_legend(),
        "mode_legend": get_mode_legend(),
    }

@router.get("/tests")
def list_v1_registered_tests():
    """Returns all registered deterministic test scripts for Chapter V1."""
    tests = list_registered_tests()
    return {
        "registered_count": len(tests),
        "tests": [
            {"shortcode": t["shortcode"], "name": t["name"], "description": t["description"]}
            for t in tests.values()
        ],
    }

@router.get("/scripts")
def list_v1_scripts():
    """Returns the formal requirement-to-script definitions for Chapter V1."""
    defs = list_script_definitions()
    return {
        "chapter": "V1 Encoding and Sanitization",
        "script_count": len(defs),
        "scripts": [s.to_dict() for s in defs.values()],
    }

@router.get("/scripts/{requirement_id}")
def get_v1_script_detail(requirement_id: str):
    """Returns the complete script specification for an ASVS requirement (e.g. V1.3.7)."""
    script_def = get_script_definition(requirement_id)
    if not script_def:
        raise HTTPException(status_code=404, detail=f"No script definition found for requirement '{requirement_id}'")
    return script_def.to_dict()
