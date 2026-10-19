import os
import asyncio
from typing import Optional, List, Dict, Any
import httpx
from dotenv import load_dotenv
from sqlmodel import Session
from sqlalchemy.orm.attributes import flag_modified
from playwright.async_api import async_playwright
from database import engine, Scan
from agent_harness import run_gemini_security_harness
from asvs_loader import get_test_suite
from harness.engine import HarnessEngine

load_dotenv()

TINYFISH_URL = "https://api.browser.tinyfish.ai"
TINYFISH_API_KEY = os.getenv("TINYFISH_API_KEY", "")

# Concurrency limit for TinyFish browser sessions
MAX_CONCURRENT_SESSIONS = int(os.getenv("MAX_CONCURRENT_SESSIONS", "2"))
tinyfish_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SESSIONS)

def update_scan_status(scan_id: int, status: str, error: str = None):
    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = status
            if error:
                scan.error = error
            db.add(scan)
            db.commit()

def save_live_trace(scan_id: int, trace: list):
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

import urllib.parse
import ipaddress

BLOCKED_METADATA_HOSTS = {
    "169.254.169.254",          # AWS / GCP / Azure link-local metadata
    "metadata.google.internal",
    "instance-data",
}

def validate_target_scope(url_str: str) -> tuple[bool, Optional[str]]:
    """
    Validates whether a target URL is in scope for security scanning.
    Rejects:
    - Non-HTTP/HTTPS schemes (e.g. ftp://, file://, javascript:, gopher://)
    - Empty or malformed hostnames
    - Cloud metadata IP/endpoints or link-local addresses
    """
    try:
        parsed = urllib.parse.urlparse(str(url_str).strip())
        scheme = (parsed.scheme or "").lower()
        if scheme not in ["http", "https"]:
            return False, f"Unsupported scheme '{scheme}'. Only http:// and https:// URLs are permitted."

        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return False, "Target URL is missing a valid hostname."

        if hostname in BLOCKED_METADATA_HOSTS:
            return False, f"Target host '{hostname}' is blocked (cloud metadata endpoint)."

        # Reject link-local IPs
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_link_local:
                return False, f"Target IP '{hostname}' is out of scope (link-local address)."
        except ValueError:
            pass  # Not an IP literal, it's a domain name

        return True, None
    except Exception as e:
        return False, f"Invalid target URL: {str(e)}"

async def execute_scan_task(
    scan_id: int, 
    target_url: str, 
    suite: str = "v1",
    test_id: Optional[str] = None,
):
    headers = {"X-API-Key": TINYFISH_API_KEY, "Content-Type": "application/json"}
    session_id = None
    cdp_issues = []
    doc_headers = {}

    # Target Scope Validation
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

    # Check for Chapter V1 Deterministic Harness execution
    if suite in ["v1", "chapter_v1"] or test_id:
        update_scan_status(scan_id, "running")
        try:
            engine_instance = HarnessEngine(tinyfish_api_key=TINYFISH_API_KEY)
            report = await engine_instance.execute_harness(
                target_url=target_url,
                chapter="V1",
                single_test_id=test_id,
                on_step_callback=lambda trace: save_live_trace(scan_id, trace),
            )
            with Session(engine) as db:
                scan = db.get(Scan, scan_id)
                if scan:
                    scan.status = report.get("scan_status", "completed")
                    scan.score = report.get("score")
                    scan.grade = report.get("grade", "NOT_ASSESSED")
                    scan.results = report
                    flag_modified(scan, "results")
                    db.add(scan)
                    db.commit()
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

    # 1. Load the requested ASVS test requirements
    try:
        asvs_requirements = get_test_suite(suite)
    except Exception as e:
        update_scan_status(scan_id, "failed", f"Failed to load ASVS standards: {str(e)}")
        return

    # Update state: Waiting for an available TinyFish browser slot
    update_scan_status(scan_id, "queued")

    async with tinyfish_semaphore:
        update_scan_status(scan_id, "running")
        try:
            async with httpx.AsyncClient(timeout=65.0) as http_client:
                # 2. Start isolated TinyFish browser session
                resp = await http_client.post(TINYFISH_URL, headers=headers, json={"url": target_url})
                resp.raise_for_status()
                session_data = resp.json()
                session_id = session_data["session_id"]
                cdp_url = session_data["cdp_url"]

                # 3. Attach Playwright over CDP
                async with async_playwright() as p:
                    browser = await p.chromium.connect_over_cdp(cdp_url)
                    context = browser.contexts[0]
                    page = context.pages[0]
                    cdp = await context.new_cdp_session(page)

                    await cdp.send("Audits.enable")
                    await cdp.send("Network.enable")
                    cdp.on("Audits.issueAdded", lambda e: cdp_issues.append(e["issue"]["code"]))

                    def capture_headers(params):
                        if params.get("type") == "Document":
                            doc_headers.update(params["response"].get("headers", {}))

                    cdp.on("Network.responseReceived", capture_headers)

                    await page.reload(wait_until="domcontentloaded")
                    await page.wait_for_timeout(1500)

                    # 4. Run the OWASP ASVS verification harness
                    report = await run_gemini_security_harness(
                        page=page,
                        cdp=cdp,
                        doc_headers=doc_headers,
                        cdp_issues=cdp_issues,
                        asvs_requirements=asvs_requirements,
                        on_step_callback=lambda trace: save_live_trace(scan_id, trace),
                    )

                    await browser.close()

            # 5. Save final scored report to SQLite
            with Session(engine) as db:
                scan = db.get(Scan, scan_id)
                if scan:
                    scan.status = report.get("scan_status", "completed")
                    scan.score = report.get("score")
                    scan.grade = report.get("grade", "NOT_ASSESSED")
                    scan.results = report
                    flag_modified(scan, "results")
                    db.add(scan)
                    db.commit()

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
            # 6. Always close TinyFish session on exit to prevent slot leaks
            if session_id:
                try:
                    async with httpx.AsyncClient(timeout=15.0) as http_client:
                        await http_client.delete(f"{TINYFISH_URL}/{session_id}", headers=headers)
                except Exception:
                    pass
