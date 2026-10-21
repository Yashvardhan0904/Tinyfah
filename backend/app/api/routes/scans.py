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

@router.get("/scans/{scan_id}/stream")
async def stream_scan_progress(scan_id: int):
    """
    Server-Sent Events (SSE) stream yielding real-time browser session state,
    agent execution traces, and final report. Ideal for live UI progress indicators.
    """
    import json
    import asyncio
    from fastapi.responses import StreamingResponse
    from app.core.database import engine

    async def event_generator():
        last_step_count = -1
        last_status = None
        seen_browser_session = False
        iteration = 0
        max_idle_ticks = 800  # 800 * 0.25s = 200 seconds safety

        # Send initial connected comment to immediately flush headers to client
        yield ": connected\n\n"

        while iteration < max_idle_ticks:
            iteration += 1
            with Session(engine) as db:
                scan = db.get(Scan, scan_id)
                if not scan:
                    yield f"event: error\ndata: {json.dumps({'error': 'Scan not found'})}\n\n"
                    break

                normalized = normalize_scan_record(scan, db)
                status = normalized.status
                results = normalized.results or {}
                trace = results.get("agent_trace", [])
                browser_session = results.get("browser_session")

                has_new_session = bool(browser_session and not seen_browser_session)
                has_new_trace = len(trace) != last_step_count
                status_changed = status != last_status

                if has_new_trace or status_changed or has_new_session:
                    last_step_count = len(trace)
                    last_status = status
                    if browser_session:
                        seen_browser_session = True

                    payload = {
                        "id": normalized.id,
                        "url": normalized.url,
                        "status": status,
                        "grade": normalized.grade,
                        "score": normalized.score,
                        "browser_session": browser_session,
                        "trace_count": len(trace),
                        "agent_trace": trace,
                        "latest_step": trace[-1] if trace else None,
                        "error": normalized.error,
                    }
                    if status in ["completed", "failed", "not_assessed"]:
                        payload["results"] = results

                    yield f"event: message\ndata: {json.dumps(payload, default=str)}\n\n"

                if status in ["completed", "failed", "not_assessed"]:
                    yield f"event: done\ndata: {json.dumps({'status': status, 'grade': normalized.grade, 'score': normalized.score})}\n\n"
                    break

            await asyncio.sleep(0.25)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

@router.get("/scans", response_model=List[Scan])
def list_scans(db: Session = Depends(get_session)):
    scans = db.exec(select(Scan).order_by(Scan.created_at.desc()).limit(20)).all()
    return [normalize_scan_record(s, db) for s in scans]
