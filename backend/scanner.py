import os
import httpx
from dotenv import load_dotenv
from sqlmodel import Session
from sqlalchemy.orm.attributes import flag_modified
from playwright.async_api import async_playwright
from database import engine, Scan
from agent_harness import run_gemini_security_harness

load_dotenv()

TINYFISH_URL = "https://api.browser.tinyfish.ai"
TINYFISH_API_KEY = os.getenv("TINYFISH_API_KEY", "")

def save_live_trace(scan_id: int, trace: list):
    """Writes intermediate Gemini tool steps to SQLite so Next.js polling shows live progress."""
    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.results = {"agent_trace": list(trace), "findings": []}
            flag_modified(scan, "results")
            db.add(scan)
            db.commit()

# FIXED: Added focus_prompt as the 3rd argument with a default value
async def execute_scan_task(
    scan_id: int, 
    target_url: str, 
    focus_prompt: str = "Perform a full passive web vulnerability audit."
):
    headers = {"X-API-Key": TINYFISH_API_KEY, "Content-Type": "application/json"}
    session_id = None
    cdp_issues = []
    doc_headers = {}

    try:
        async with httpx.AsyncClient(timeout=65.0) as http_client:
            # 1. Start isolated TinyFish browser session
            resp = await http_client.post(TINYFISH_URL, headers=headers, json={"url": target_url})
            resp.raise_for_status()
            session_data = resp.json()
            session_id = session_data["session_id"]
            cdp_url = session_data["cdp_url"]

            # 2. Attach Playwright over CDP
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

                # 3. Run the Gemini 2.5 Flash ReAct Harness (passing focus_prompt)
                report = await run_gemini_security_harness(
                    page=page,
                    cdp=cdp,
                    doc_headers=doc_headers,
                    cdp_issues=cdp_issues,
                    focus_prompt=focus_prompt,
                    on_step_callback=lambda trace: save_live_trace(scan_id, trace),
                )

                await browser.close()

        # 4. Save final scored report to SQLite
        with Session(engine) as db:
            scan = db.get(Scan, scan_id)
            scan.status = "completed"
            scan.score = report["score"]
            scan.grade = report["grade"]
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
                db.add(scan)
                db.commit()

    finally:
        # 5. Always close TinyFish session on exit
        if session_id:
            async with httpx.AsyncClient(timeout=15.0) as http_client:
                await http_client.delete(f"{TINYFISH_URL}/{session_id}", headers=headers)
