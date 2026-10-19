import os
import asyncio
from typing import Optional, List, Dict, Any
import httpx
from sqlmodel import Session
from sqlalchemy.orm.attributes import flag_modified
from playwright.async_api import async_playwright

from app.config import TINYFISH_URL, TINYFISH_API_KEY, MAX_CONCURRENT_SESSIONS
from app.core.database import engine
from app.models.scan import Scan
from app.core.scope import validate_target_scope
from app.services.agent import run_gemini_security_harness
from app.loaders.asvs import get_test_suite

tinyfish_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SESSIONS)

def update_scan_status(scan_id: int, status: str, error: Optional[str] = None) -> None:
    """Updates scan execution status and optional error message in SQLite."""
    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = status
            if error:
                scan.error = error
            db.add(scan)
            db.commit()

def save_live_trace(scan_id: int, trace: list) -> None:
    """Writes intermediate tool steps to SQLite so polling clients show live progress."""
    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        if scan:
            if not scan.results:
                scan.results = {}
            scan.results["agent_trace"] = list(trace)
            flag_modified(scan, "results")
            db.add(scan)
            db.commit()

def save_browser_session(scan_id: int, session_info: Dict[str, Any]) -> None:
    """Writes browser session details (provider, session_id, cdp_url, status) to SQLite."""
    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        if scan:
            if not scan.results:
                scan.results = {}
            scan.results["browser_session"] = dict(session_info)
            flag_modified(scan, "results")
            db.add(scan)
            db.commit()

def _save_scan_report(scan_id: int, report: Dict[str, Any]) -> None:
    """Persists finalized audit report to the database with consistent scoring safeguards."""
    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            return

        asvs_results = report.get("asvs_results", [])
        evaluated = [
            r for r in asvs_results
            if (isinstance(r, dict) and r.get("status") in ["PASS", "FAIL"])
            or (hasattr(r, "status") and getattr(r, "status") in ["PASS", "FAIL"])
        ]
        if len(evaluated) == 0:
            scan.status = "not_assessed"
            scan.score = None
            scan.grade = "NOT_ASSESSED"
        else:
            scan.status = report.get("scan_status", "completed")
            scan.score = report.get("score")
            scan.grade = report.get("grade", "NOT_ASSESSED")

        scan.results = report
        flag_modified(scan, "results")
        db.add(scan)
        db.commit()

async def execute_scan_task(
    scan_id: int,
    target_url: str,
    suite: str = "v1",
    test_id: Optional[str] = None,
) -> None:
    """Coordinates isolated browser scanning and execution for both Chapter V1 harness and ASVS ReAct agent."""
    headers = {"X-API-Key": TINYFISH_API_KEY, "Content-Type": "application/json"}
    session_id = None
    cdp_issues: List[str] = []
    doc_headers: Dict[str, str] = {}

    # 1. Target Scope Validation
    valid, scope_err = validate_target_scope(target_url)
    if not valid:
        update_scan_status(scan_id, "failed", f"Out-of-scope target rejected: {scope_err}")
        with Session(engine) as db:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.score = None
                scan.grade = "NOT_ASSESSED"
                scan.results = {
                    "error": f"Target URL out of scope: {scope_err}",
                    "findings": [],
                    "asvs_results": [],
                }
                flag_modified(scan, "results")
                db.add(scan)
                db.commit()
        return

    # 2. LangGraph Multi-Agent Security Audit Workflow (Full ASVS & Domain Agents)
    if suite in ["langgraph", "agent_graph", "multi_agent", "v1_langgraph", "all", "all_standards", "asvs_all", "full", "all_chapters"]:
        update_scan_status(scan_id, "running")
        try:
            from app.graph.runner import run_langgraph_security_audit
            report = await run_langgraph_security_audit(
                target_url=target_url,
                suite=suite,
                on_step_callback=lambda trace: save_live_trace(scan_id, trace),
                on_session_callback=lambda session_info: save_browser_session(scan_id, session_info),
            )
            _save_scan_report(scan_id, report)
        except Exception as exc:
            with Session(engine) as db:
                scan = db.get(Scan, scan_id)
                if scan:
                    scan.status = "failed"
                    scan.error = str(exc)
                    scan.score = None
                    scan.grade = "NOT_ASSESSED"
                    db.add(scan)
                    db.commit()
        return

    # 3. Chapter V1 Deterministic Harness Execution
    if suite in ["v1", "chapter_v1"] or test_id:
        update_scan_status(scan_id, "running")
        try:
            from harness.engine import HarnessEngine
            engine_instance = HarnessEngine(tinyfish_api_key=TINYFISH_API_KEY)
            report = await engine_instance.execute_harness(
                target_url=target_url,
                chapter="V1",
                single_test_id=test_id,
                on_step_callback=lambda trace: save_live_trace(scan_id, trace),
                on_session_callback=lambda session_info: save_browser_session(scan_id, session_info),
            )
            _save_scan_report(scan_id, report)
        except Exception as exc:
            with Session(engine) as db:
                scan = db.get(Scan, scan_id)
                if scan:
                    scan.status = "failed"
                    scan.error = str(exc)
                    scan.score = None
                    scan.grade = "NOT_ASSESSED"
                    db.add(scan)
                    db.commit()
        return

    # 4. Legacy General ASVS Suite Execution
    try:
        asvs_requirements = get_test_suite(suite)
    except Exception as e:
        update_scan_status(scan_id, "failed", f"Failed to load ASVS standards: {str(e)}")
        return

    update_scan_status(scan_id, "queued")

    async with tinyfish_semaphore:
        update_scan_status(scan_id, "running")
        try:
            async with httpx.AsyncClient(timeout=65.0) as http_client:
                resp = await http_client.post(TINYFISH_URL, headers=headers, json={"url": target_url})
                resp.raise_for_status()
                session_data = resp.json()
                session_id = session_data["session_id"]
                cdp_url = session_data["cdp_url"]
                live_view_url = session_data.get("live_view_url") or session_data.get("viewer_url")
                save_browser_session(scan_id, {
                    "provider": "tinyfish",
                    "session_id": session_id,
                    "cdp_url": cdp_url,
                    "live_view_url": live_view_url,
                    "status": "connected",
                    "target_url": target_url,
                })
                save_live_trace(scan_id, [
                    {
                        "step": 1,
                        "phase": "browser_provisioning",
                        "agent": "TinyFish Cloud Provisioner",
                        "tool": "tinyfish_browser_api",
                        "action": "cdp_connected",
                        "reason": "TinyFish browser session allocated and CDP WebSocket ready",
                        "observation_preview": f"Session ID: '{session_id}'. CDP WebSocket acquired. Connecting Playwright to browser over CDP...",
                        "status": "connected",
                        "session_id": session_id,
                        "cdp_url": cdp_url,
                    }
                ])

                async with async_playwright() as p:
                    browser = await p.chromium.connect_over_cdp(cdp_url)
                    context = browser.contexts[0]
                    while len(context.pages) > 1:
                        try:
                            await context.pages[-1].close()
                        except Exception:
                            break
                    page = context.pages[0] if context.pages else await context.new_page()
                    try:
                        await context.clear_cookies()
                    except Exception:
                        pass
                    cdp = await context.new_cdp_session(page)

                    await cdp.send("Page.enable")
                    await cdp.send("Audits.enable")
                    await cdp.send("Network.enable")
                    cdp.on("Audits.issueAdded", lambda e: cdp_issues.append(e["issue"]["code"]))

                    def capture_headers(params):
                        if params.get("type") == "Document":
                            doc_headers.update(params["response"].get("headers", {}))

                    cdp.on("Network.responseReceived", capture_headers)

                    await page.reload(wait_until="domcontentloaded")
                    await page.wait_for_timeout(1500)

                    report = await run_gemini_security_harness(
                        page=page,
                        cdp=cdp,
                        doc_headers=doc_headers,
                        cdp_issues=cdp_issues,
                        asvs_requirements=asvs_requirements,
                        on_step_callback=lambda trace: save_live_trace(scan_id, trace),
                    )

                    await browser.close()

            _save_scan_report(scan_id, report)

        except Exception as exc:
            with Session(engine) as db:
                scan = db.get(Scan, scan_id)
                if scan:
                    scan.status = "failed"
                    scan.error = str(exc)
                    scan.score = None
                    scan.grade = "NOT_ASSESSED"
                    db.add(scan)
                    db.commit()

        finally:
            if session_id:
                try:
                    async with httpx.AsyncClient(timeout=15.0) as http_client:
                        await http_client.delete(f"{TINYFISH_URL}/{session_id}", headers=headers)
                except Exception:
                    pass
