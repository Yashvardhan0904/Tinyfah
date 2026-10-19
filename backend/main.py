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
from database import init_db, get_session, Scan
from scanner import execute_scan_task
from asvs_loader import get_all_chapters, get_test_suite

from tinyfah_loader import get_chapter_requirements, get_all_chapters_summary, get_input_legend, get_mode_legend
from harness.registry import list_registered_tests

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

@app.post("/scans", response_model=Scan)
async def start_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_session),
):
    suite_type = payload.suite or "v1"
    # Initialize results with empty traces and findings
    scan = Scan(
        url=str(payload.url),
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

@app.get("/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: int, db: Session = Depends(get_session)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/scans", response_model=list[Scan])
def list_scans(db: Session = Depends(get_session)):
    return db.exec(select(Scan).order_by(Scan.created_at.desc()).limit(20)).all()
