from typing import List
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlmodel import Session, select
from sqlalchemy.orm.attributes import flag_modified

from app.core.database import get_session
from app.models.scan import Scan, ScanRequest
from app.core.scope import validate_target_scope
from app.services.scanner import execute_scan_task
from app.services.checks import deduplicate_findings

router = APIRouter(tags=["Scans"])

def normalize_scan_record(scan: Scan, db: Session) -> Scan:
    """Normalizes scan record scoring and findings on retrieval."""
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

@router.post("/scans", response_model=Scan)
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
        payload.test_id,
    )
    return scan

@router.get("/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: int, db: Session = Depends(get_session)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return normalize_scan_record(scan, db)

@router.get("/scans", response_model=List[Scan])
def list_scans(db: Session = Depends(get_session)):
    scans = db.exec(select(Scan).order_by(Scan.created_at.desc()).limit(20)).all()
    return [normalize_scan_record(s, db) for s in scans]
