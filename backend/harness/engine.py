import os
import json
import asyncio
import httpx
from typing import Dict, Any, List, Optional, Callable
from playwright.async_api import async_playwright
from tinyfah_loader import get_chapter_requirements, get_requirement
from harness.registry import (
    HarnessContext,
    TestResult,
    get_registered_test,
    list_registered_tests,
)
# Ensure scripts are registered
import harness.scripts.v1_encoding as v1_scripts
from harness.reporter import generate_site_report

TINYFISH_URL = "https://api.browser.tinyfish.ai"

import urllib.parse

def _is_local_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        return (
            host in ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
            or host.startswith("192.168.")
            or host.startswith("10.")
            or host.endswith(".local")
        )
    except Exception:
        return False

class HarnessEngine:
    def __init__(
        self,
        tinyfish_api_key: Optional[str] = None,
        use_local_fallback: bool = True,
        max_concurrency: int = 2,
    ):
        self.api_key = tinyfish_api_key or os.getenv("TINYFISH_API_KEY", "")
        self.use_local_fallback = use_local_fallback
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def execute_harness(
        self,
        target_url: str,
        chapter: str = "V1",
        single_test_id: Optional[str] = None,
        on_step_callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    ) -> Dict[str, Any]:
        """
        Executes deterministic testing workflow against target_url.
        Uses TinyFish Cloud Browser API over CDP, or local browser fallback.
        """
        session_id = None
        cdp_url = None
        doc_headers: Dict[str, str] = {}
        cdp_issues: List[str] = []
        agent_trace: List[Dict[str, Any]] = []

        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        # Remote TinyFish cloud browsers cannot route to local loopback addresses (127.0.0.1 / localhost)
        can_use_tinyfish = (
            bool(self.api_key and self.api_key.startswith("sk-tinyfish"))
            and not _is_local_url(target_url)
        )

        async with self.semaphore:
            # 1. Acquire Browser Session (TinyFish or Local Playwright)
            async with async_playwright() as p:
                browser = None
                try:
                    if can_use_tinyfish:
                        try:
                            async with httpx.AsyncClient(timeout=45.0) as http_client:
                                resp = await http_client.post(
                                    TINYFISH_URL,
                                    headers=headers,
                                    json={"url": target_url},
                                )
                                resp.raise_for_status()
                                session_data = resp.json()
                                session_id = session_data.get("session_id")
                                cdp_url = session_data.get("cdp_url")

                            browser = await p.chromium.connect_over_cdp(cdp_url)
                            context = browser.contexts[0]
                            page = context.pages[0] if context.pages else await context.new_page()
                        except Exception as tf_err:
                            if not self.use_local_fallback:
                                raise RuntimeError(f"TinyFish session initialization failed: {tf_err}")
                            # Fallback to local Chromium
                            browser = await p.chromium.launch(headless=True)
                            context = await browser.new_context()
                            page = await context.new_page()
                    else:
                        browser = await p.chromium.launch(headless=True)
                        context = await browser.new_context()
                        page = await context.new_page()

                    # Set up CDP listeners if available
                    cdp_session = None
                    try:
                        cdp_session = await context.new_cdp_session(page)
                        await cdp_session.send("Page.enable")
                        await cdp_session.send("Audits.enable")
                        await cdp_session.send("Network.enable")

                        cdp_session.on(
                            "Audits.issueAdded",
                            lambda e: cdp_issues.append(e.get("issue", {}).get("code", "unknown")),
                        )

                        def capture_doc_headers(params):
                            if params.get("type") == "Document":
                                doc_headers.update(params.get("response", {}).get("headers", {}))

                        cdp_session.on("Network.responseReceived", capture_doc_headers)
                    except Exception:
                        pass  # CDP session not critical for all assertions

                    # Navigate to target
                    http_status = None
                    try:
                        resp = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
                        if resp:
                            http_status = resp.status
                            if not doc_headers:
                                doc_headers.update(resp.headers)
                    except Exception:
                        pass

                    # 2. Determine Requirements to Run
                    if single_test_id:
                        req_meta = get_requirement(single_test_id)
                        all_reqs = [req_meta] if req_meta else []
                    else:
                        all_reqs = get_chapter_requirements(chapter)

                    executed_results: Dict[str, TestResult] = {}
                    step_num = 1

                    # 3. Execute Registered Deterministic Scripts
                    for req in all_reqs:
                        sc = req.get("shortcode", "")
                        registered = get_registered_test(sc)
                        if not registered:
                            continue

                        fn = registered["fn"]
                        harness_ctx = HarnessContext(
                            page=page,
                            cdp=cdp_session,
                            target_url=target_url,
                            doc_headers=doc_headers,
                            cdp_issues=cdp_issues,
                            metadata=req,
                            http_status=http_status,
                        )

                        trace_entry = {
                            "step": step_num,
                            "tool": f"deterministic_test_{sc.lower()}",
                            "reason": f"Executing deterministic probe for {sc}: {registered['name']}",
                            "status": "running",
                        }
                        agent_trace.append(trace_entry)
                        if on_step_callback:
                            on_step_callback(agent_trace)

                        try:
                            res = await asyncio.wait_for(fn(harness_ctx), timeout=25.0)
                        except asyncio.TimeoutError:
                            res = TestResult(
                                shortcode=sc,
                                name=registered["name"],
                                status="ERROR",
                                severity="info",
                                evidence="Test probe timed out after 25s",
                                remediation="Review server responsiveness.",
                                chapter="V1 Encoding and Sanitization",
                                target_url=target_url,
                                http_status=http_status,
                                execution_error="asyncio.TimeoutError",
                            )
                        except Exception as e:
                            res = TestResult(
                                shortcode=sc,
                                name=registered["name"],
                                status="ERROR",
                                severity="info",
                                evidence=f"Test probe exception: {str(e)}",
                                remediation="Inspect test script or page interaction.",
                                chapter="V1 Encoding and Sanitization",
                                target_url=target_url,
                                http_status=http_status,
                                execution_error=str(e),
                            )

                        # Capture screenshot via CDP session after each test for concrete visual evidence
                        screenshot = await harness_ctx.capture_screenshot()
                        if screenshot and not res.screenshot:
                            res.screenshot = screenshot

                        if res.http_status is None:
                            res.http_status = http_status
                        if not res.target_url:
                            res.target_url = target_url

                        executed_results[sc] = res
                        trace_entry["status"] = res.status
                        trace_entry["observation_preview"] = res.evidence[:250]
                        if res.screenshot:
                            trace_entry["screenshot"] = res.screenshot
                        if on_step_callback:
                            on_step_callback(agent_trace)

                        step_num += 1

                    # 4. If Chapter Suite, evaluate remaining passive and review requirements
                    if not single_test_id:
                        harness_ctx = HarnessContext(
                            page=page,
                            cdp=cdp_session,
                            target_url=target_url,
                            doc_headers=doc_headers,
                            cdp_issues=cdp_issues,
                            http_status=http_status,
                        )
                        landing_screenshot = await harness_ctx.capture_screenshot()
                        passive_results = await v1_scripts.evaluate_v1_passive_and_review_requirements(
                            all_v1_reqs=all_reqs,
                            ctx=harness_ctx,
                            executed_results=executed_results,
                        )
                        for pr in passive_results:
                            if pr.http_status is None:
                                pr.http_status = http_status
                            if not pr.target_url:
                                pr.target_url = target_url
                            if not pr.screenshot and landing_screenshot:
                                pr.screenshot = landing_screenshot
                            executed_results[pr.shortcode] = pr

                    # Order results in canonical ASVS order
                    ordered_results: List[TestResult] = []
                    for req in all_reqs:
                        sc = req.get("shortcode", "")
                        if sc in executed_results:
                            ordered_results.append(executed_results[sc])

                    # 5. Generate Scored Site Report
                    report = await generate_site_report(
                        target_url=target_url,
                        results=ordered_results,
                        raw_headers=doc_headers,
                        agent_trace=agent_trace,
                    )

                    return report

                finally:
                    # Clean up local browser if launched
                    if browser:
                        try:
                            await browser.close()
                        except Exception:
                            pass

                    # Clean up TinyFish session if created
                    if session_id:
                        try:
                            async with httpx.AsyncClient(timeout=10.0) as http_client:
                                await http_client.delete(
                                    f"{TINYFISH_URL}/{session_id}",
                                    headers=headers,
                                )
                        except Exception:
                            pass
