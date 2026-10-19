import os
from pathlib import Path
from dotenv import load_dotenv

# MUST run before importing scanner / agent_harness so env vars are loaded
load_dotenv(Path(__file__).resolve().parent / ".env")
load_dotenv()

from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from sqlmodel import Session, select
from sqlalchemy.orm.attributes import flag_modified
from database import init_db, get_session, Scan
from scanner import execute_scan_task, validate_target_scope
from asvs_loader import get_all_chapters, get_test_suite
from checks import deduplicate_findings

from tinyfah_loader import get_chapter_requirements, get_all_chapters_summary, get_input_legend, get_mode_legend
from harness.registry import list_registered_tests, list_script_definitions, get_script_definition

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="OWASP ASVS Web Security Verification Harness", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
from screenshots import SCREENSHOTS_DIR

app.mount("/screenshots", StaticFiles(directory=str(SCREENSHOTS_DIR)), name="screenshots")


class ScanRequest(BaseModel):
    url: HttpUrl
    suite: Optional[str] = "v1"  # "v1" | "chapter_v1" | "chapter_sample" | "first_five" | "full"
    test_id: Optional[str] = None           # e.g. "V1.2.1"
    focus_prompt: Optional[str] = None

@app.get("/asvs/chapters")
def list_asvs_chapters():
    """Returns all 17 OWASP ASVS chapters with section counts."""
    return {"chapters": get_all_chapters()}

@app.get("/asvs/tests")
def get_asvs_tests(suite: str = Query("chapter_sample", description="Test suite type")):
    """Returns the tests that will be run for the given suite type."""
    if suite in ["v1", "chapter_v1"]:
        v1_reqs = get_chapter_requirements("V1")
        return {
            "suite": suite,
            "chapter": "V1 Encoding and Sanitization",
            "count": len(v1_reqs),
            "tests": v1_reqs
        }
    tests = get_test_suite(suite)
    return {
        "suite": suite,
        "count": len(tests),
        "tests": tests
    }

@app.get("/api/harness/v1/requirements")
def list_v1_requirements():
    """Returns all 30 Chapter V1 requirements loaded directly from Tinyfah.json."""
    reqs = get_chapter_requirements("V1")
    return {
        "chapter": "V1 Encoding and Sanitization",
        "count": len(reqs),
        "requirements": reqs,
        "input_legend": get_input_legend(),
        "mode_legend": get_mode_legend(),
    }

@app.get("/api/harness/v1/tests")
def list_v1_registered_tests():
    """Returns all registered deterministic test scripts for Chapter V1."""
    tests = list_registered_tests()
    return {
        "registered_count": len(tests),
        "tests": [
            {"shortcode": t["shortcode"], "name": t["name"], "description": t["description"]}
            for t in tests.values()
        ]
    }

@app.get("/api/harness/v1/scripts")
def list_v1_scripts():
    """Returns the formal requirement-to-script definitions for Chapter V1."""
    defs = list_script_definitions()
    return {
        "chapter": "V1 Encoding and Sanitization",
        "script_count": len(defs),
        "scripts": [s.to_dict() for s in defs.values()],
    }

@app.get("/api/harness/v1/scripts/{requirement_id}")
def get_v1_script_detail(requirement_id: str):
    """Returns the complete script specification for an ASVS requirement (e.g. V1.3.7)."""
    script_def = get_script_definition(requirement_id)
    if not script_def:
        raise HTTPException(status_code=404, detail=f"No script definition found for requirement '{requirement_id}'")
    return script_def.to_dict()

@app.post("/scans", response_model=Scan)
async def start_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_session),
):
    url_str = str(payload.url)
    valid, scope_err = validate_target_scope(url_str)
    if not valid:
        raise HTTPException(
            status_code=400,
            detail=f"Target URL is out of scope or invalid: {scope_err}"
        )

    suite_type = payload.suite or "v1"
    # Initialize results with empty traces and findings
    scan = Scan(
        url=url_str,
        status="queued",
        results={"agent_trace": [], "findings": [], "asvs_results": []}
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(
        execute_scan_task,
        scan.id,
        scan.url,
        suite_type,
        payload.test_id
    )
    return scan

def _normalize_scan_record(scan: Scan, db: Session) -> Scan:
    if not scan or not scan.results or not isinstance(scan.results, dict):
        return scan

    modified = False
    results = dict(scan.results)
    asvs_results = results.get("asvs_results", [])
    evaluated = [
        r for r in asvs_results
        if isinstance(r, dict) and r.get("status") in ["PASS", "FAIL"]
    ]

    # 1. Normalize zero-evaluated scans
    if len(evaluated) == 0:
        if scan.score is not None or scan.grade != "NOT_ASSESSED" or (scan.status not in ["not_assessed", "failed", "running", "queued"]):
            scan.score = None
            scan.grade = "NOT_ASSESSED"
            if scan.status not in ["failed", "running", "queued"]:
                scan.status = "not_assessed"
            modified = True

        if results.get("score") is not None or results.get("grade") != "NOT_ASSESSED":
            results["score"] = None
            results["grade"] = "NOT_ASSESSED"
            if results.get("scan_status") not in ["failed", "running", "queued"]:
                results["scan_status"] = "not_assessed"
            results["coverage_percentage"] = 0.0
            results["pass_rate_percentage"] = None
            modified = True

    # 2. Deduplicate findings if present
    if "findings" in results and isinstance(results["findings"], list):
        deduped = deduplicate_findings(results["findings"])
        if len(deduped) != len(results["findings"]):
            results["findings"] = deduped
            modified = True

    if modified:
        scan.results = results
        flag_modified(scan, "results")
        db.add(scan)
        db.commit()
        db.refresh(scan)

    return scan

@app.get("/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: int, db: Session = Depends(get_session)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _normalize_scan_record(scan, db)

@app.get("/scans", response_model=list[Scan])
def list_scans(db: Session = Depends(get_session)):
    scans = db.exec(select(Scan).order_by(Scan.created_at.desc()).limit(20)).all()
    return [_normalize_scan_record(s, db) for s in scans]
