import os
import httpx
from sqlmodel import Session
from playwright.async_api import async_playwright
from database import engine, Scan
from checks import DOM_AUDIT_JS, score_scan

TINYFISH_URL = "https://api.browser.tinyfish.ai"
TINYFISH_API_KEY = os.getenv("TINYFISH_API_KEY", "")

async def execute_scan_task(scan_id: int, target_url: str):
    headers = {"X-API-Key": TINYFISH_API_KEY, "Content-Type": "application/json"}
    session_id = None
    cdp_issues = []
    doc_headers = {}

    try:
        async with httpx.AsyncClient(timeout=65.0) as client:
            # 1. Create remote TinyFish browser session
            resp = await client.post(TINYFISH_URL, headers=headers, json={"url": target_url})
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

                # Enable native Chrome DevTools Security/Audit/Network listeners
                await cdp.send("Audits.enable")
                await cdp.send("Network.enable")
                cdp.on("Audits.issueAdded", lambda e: cdp_issues.append(e["issue"]["code"]))

                def capture_headers(params):
                    if params.get("type") == "Document":
                        doc_headers.update(params["response"].get("headers", {}))

                cdp.on("Network.responseReceived", capture_headers)

                # Reload once so listeners catch initial Document headers & issues
                await page.reload(wait_until="domcontentloaded")
                await page.wait_for_timeout(1500)

                # Collect cookies & execute DOM audit script
                cookie_resp = await cdp.send("Network.getAllCookies")
                cookies = cookie_resp.get("cookies", [])
                dom_data = await page.evaluate(DOM_AUDIT_JS)

                await browser.close()

        # 3. Grade findings and save to SQLite
        graded = score_scan(doc_headers, cookies, dom_data, cdp_issues)
        with Session(engine) as db:
            scan = db.get(Scan, scan_id)
            scan.status = "completed"
            scan.score = graded["score"]
            scan.grade = graded["grade"]
            scan.results = {
                "findings": graded["findings"],
                "dom_audit": dom_data,
                "devtools_issues": list(set(cdp_issues)),
                "raw_headers": doc_headers,
            }
            db.add(scan)
            db.commit()

    except Exception as exc:
        with Session(engine) as db:
            scan = db.get(Scan, scan_id)
            scan.status = "failed"
            scan.error = str(exc)
            db.add(scan)
            db.commit()

    finally:
        # 4. Always tear down TinyFish session to save credits
        if session_id:
            async with httpx.AsyncClient(timeout=15.0) as client:
                await client.delete(f"{TINYFISH_URL}/{session_id}", headers=headers)
