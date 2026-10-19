import os
import json
import asyncio
import urllib.parse
from typing import Dict, Any, List, Optional, Callable
import httpx
from playwright.async_api import async_playwright
from google import genai
from google.genai import types

from tinyfah_loader import get_chapter_requirements, get_requirement
from harness.registry import (
    HarnessContext,
    TestResult,
    get_registered_test,
    list_registered_tests,
    get_script_definition,
    list_script_definitions,
)
import harness.scripts.v1_encoding as v1_scripts
from harness.reporter import generate_site_report
from harness.console_hud import attach_console_listeners

TINYFISH_URL = "https://api.browser.tinyfish.ai"
DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

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

# Function declaration for Gemini Agent Script Orchestration
V1_AGENT_TOOLS = types.Tool(
    function_declarations=[
        types.FunctionDeclaration(
            name="execute_v1_test_script",
            description=(
                "Executes a predefined, deterministic backend test script for an OWASP ASVS Chapter V1 requirement "
                "(e.g., V1.3.7 for template injection, V1.2.1 for HTML encoding, V1.2.2 for URL schemes). "
                "The backend runs the defined browser workflow, collects concrete evidence and CDP screenshots, "
                "and deterministically evaluates the requirement status (PASS, FAIL, MANUAL_VERIFY, NOT_TESTED)."
            ),
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "requirement_id": types.Schema(
                        type="STRING",
                        description="The ASVS requirement shortcode to execute (e.g., 'V1.3.7', 'V1.2.1', 'V1.2.2', 'V1.1.1')",
                    ),
                    "reason": types.Schema(
                        type="STRING",
                        description="Why this test script is relevant based on the page attack surface (forms, parameters, scripts)",
                    ),
                },
                required=["requirement_id", "reason"],
            ),
        ),
        types.FunctionDeclaration(
            name="inspect_page_dom",
            description="Executes a read-only JavaScript arrow function in the page context via page.evaluate() to inspect DOM elements or global variables.",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "reason": types.Schema(type="STRING", description="Why this DOM inspection is needed"),
                    "js_expression": types.Schema(type="STRING", description="Read-only JavaScript arrow function, e.g. () => document.forms.length"),
                },
                required=["reason", "js_expression"],
            ),
        ),
        types.FunctionDeclaration(
            name="capture_page_screenshot",
            description="Captures a visual screenshot of the current page state via Chrome DevTools Protocol (Page.captureScreenshot).",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "reason": types.Schema(type="STRING", description="Why the visual evidence is being captured"),
                },
                required=["reason"],
            ),
        ),
    ]
)

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
        on_session_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """
        Executes testing workflow against target_url using the hybrid architecture:
        Gemini Agent coordinates script selection and workflow;
        Backend predefined test scripts execute deterministic browser workflows and collect evidence;
        Evidence collector captures DOM observations and CDP screenshots;
        Deterministic evaluator assigns status;
        Gemini synthesizes the executive summary.
        """
        session_id = None
        cdp_url = None
        live_view_url = None
        browser_session: Dict[str, Any] = {}
        doc_headers: Dict[str, str] = {}
        cdp_issues: List[str] = []
        agent_trace: List[Dict[str, Any]] = []

        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
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
                        agent_trace.append({
                            "step": 1,
                            "phase": "browser_provisioning",
                            "agent": "TinyFish Cloud Provisioner",
                            "tool": "tinyfish_browser_api",
                            "action": "session_request",
                            "reason": f"Allocating cloud browser sandbox for target: {target_url}",
                            "observation_preview": f"Contacting TinyFish API ({TINYFISH_URL}) to create remote browser container...",
                            "status": "requesting",
                        })
                        if on_step_callback:
                            on_step_callback(list(agent_trace))

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
                                live_view_url = session_data.get("live_view_url") or session_data.get("viewer_url")

                            browser_session = {
                                "provider": "tinyfish",
                                "session_id": session_id,
                                "cdp_url": cdp_url,
                                "live_view_url": live_view_url,
                                "status": "connected",
                                "target_url": target_url,
                            }
                            if on_session_callback:
                                on_session_callback(browser_session)

                            agent_trace.append({
                                "step": 2,
                                "phase": "browser_provisioning",
                                "agent": "TinyFish Cloud Provisioner",
                                "tool": "tinyfish_browser_api",
                                "action": "cdp_connected",
                                "reason": "TinyFish browser session allocated and CDP WebSocket ready",
                                "observation_preview": f"Session ID: '{session_id}'. CDP WebSocket acquired. Connecting Playwright to browser over CDP...",
                                "status": "connected",
                                "session_id": session_id,
                                "cdp_url": cdp_url,
                                "live_view_url": live_view_url,
                            })
                            if on_step_callback:
                                on_step_callback(list(agent_trace))

                            browser = await p.chromium.connect_over_cdp(cdp_url)
                            context = browser.contexts[0]
                            # Clean up any stale tabs from pooled remote sessions
                            while len(context.pages) > 1:
                                try:
                                    await context.pages[-1].close()
                                except Exception:
                                    break
                            page = context.pages[0] if context.pages else await context.new_page()
                            # Clear session cookies to prevent cross-scan contamination
                            try:
                                await context.clear_cookies()
                            except Exception:
                                pass
                        except Exception as tf_err:
                            if not self.use_local_fallback:
                                raise RuntimeError(f"TinyFish session initialization failed: {tf_err}")
                            browser = await p.chromium.launch(headless=True)
                            context = await browser.new_context()
                            page = await context.new_page()
                            browser_session = {
                                "provider": "local_playwright",
                                "session_id": "local_chromium",
                                "cdp_url": "local_cdp",
                                "live_view_url": None,
                                "status": "fallback",
                                "target_url": target_url,
                            }
                            if on_session_callback:
                                on_session_callback(browser_session)
                            agent_trace.append({
                                "step": 2,
                                "phase": "browser_provisioning",
                                "agent": "Local Playwright Provisioner",
                                "tool": "playwright_local",
                                "action": "browser_launched",
                                "reason": f"TinyFish session request failed ({tf_err}); fallback to local headless Chromium",
                                "observation_preview": "Local Chromium instance launched and attached successfully.",
                                "status": "fallback",
                                "session_id": "local_chromium",
                                "cdp_url": "local_cdp",
                            })
                            if on_step_callback:
                                on_step_callback(list(agent_trace))
                    else:
                        browser = await p.chromium.launch(headless=True)
                        context = await browser.new_context()
                        page = await context.new_page()
                        browser_session = {
                            "provider": "local_playwright",
                            "session_id": "local_chromium",
                            "cdp_url": "local_cdp",
                            "live_view_url": None,
                            "status": "connected",
                            "target_url": target_url,
                        }
                        if on_session_callback:
                            on_session_callback(browser_session)
                        agent_trace.append({
                            "step": 1,
                            "phase": "browser_provisioning",
                            "agent": "Local Playwright Provisioner",
                            "tool": "playwright_local",
                            "action": "browser_launched",
                            "reason": "Target is local or running without remote TinyFish API key",
                            "observation_preview": "Launched isolated local headless Chromium instance. CDP session established.",
                            "status": "connected",
                            "session_id": "local_chromium",
                            "cdp_url": "local_cdp",
                        })
                        if on_step_callback:
                            on_step_callback(list(agent_trace))

                    # Set up CDP session and listeners
                    cdp_session = None
                    console_logs: List[Dict[str, Any]] = []
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
                        pass

                    # Attach console listeners for live DevTools Console HUD capture
                    try:
                        attach_console_listeners(page, cdp_session, console_logs)
                    except Exception:
                        pass

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

                    # Capture initial baseline screenshot via CDP only if URL belongs to target domain
                    landing_ctx = HarnessContext(
                        page=page,
                        cdp=cdp_session,
                        target_url=target_url,
                        doc_headers=doc_headers,
                        cdp_issues=cdp_issues,
                        console_logs=console_logs,
                        http_status=http_status,
                    )
                    landing_screenshot = None
                    try:
                        target_host = urllib.parse.urlparse(target_url).netloc.lower()
                        page_host = urllib.parse.urlparse(page.url).netloc.lower()
                        if not page_host or target_host in page_host or page_host in target_host:
                            landing_meta = {
                                "shortcode": "AUDIT",
                                "name": "Navigation & Baseline Header Audit",
                                "status": "PASS" if http_status and http_status < 400 else "INFO",
                                "evidence": f"HTTP {http_status or 'N/A'} - DOM ready",
                            }
                            landing_screenshot = await landing_ctx.capture_screenshot(test_info=landing_meta)
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

                    # Helper to run a single registered test script
                    async def run_single_script(sc_id: str, reason: str = "") -> TestResult:
                        nonlocal step_num
                        sc_upper = sc_id.strip().upper()
                        registered = get_registered_test(sc_upper)
                        req_obj = get_requirement(sc_upper) or {"shortcode": sc_upper}

                        h_ctx = HarnessContext(
                            page=page,
                            cdp=cdp_session,
                            target_url=target_url,
                            doc_headers=doc_headers,
                            cdp_issues=cdp_issues,
                            console_logs=console_logs,
                            metadata=req_obj,
                            http_status=http_status,
                        )

                        trace_entry = {
                            "step": step_num,
                            "tool": f"test_script_{sc_upper.lower()}",
                            "requirement_id": sc_upper,
                            "reason": reason or f"Executing test script for {sc_upper}: {registered['name'] if registered else sc_upper}",
                            "status": "running",
                        }
                        agent_trace.append(trace_entry)
                        if on_step_callback:
                            on_step_callback(agent_trace)

                        if not registered:
                            res = TestResult(
                                shortcode=sc_upper,
                                script_id=sc_upper.replace(".", "_"),
                                name=f"Requirement {sc_upper}",
                                status="NOT_TESTED",
                                severity="info",
                                evidence=f"No executable test script registered for requirement {sc_upper}.",
                                chapter="V1 Encoding and Sanitization",
                                target_url=target_url,
                                http_status=http_status,
                            )
                        else:
                            fn = registered["fn"]
                            try:
                                res = await asyncio.wait_for(fn(h_ctx), timeout=25.0)
                            except asyncio.TimeoutError:
                                res = TestResult(
                                    shortcode=sc_upper,
                                    script_id=sc_upper.replace(".", "_"),
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
                            except Exception as exc:
                                res = TestResult(
                                    shortcode=sc_upper,
                                    script_id=sc_upper.replace(".", "_"),
                                    name=registered["name"],
                                    status="ERROR",
                                    severity="info",
                                    evidence=f"Test probe exception: {str(exc)}",
                                    remediation="Inspect test script or page interaction.",
                                    chapter="V1 Encoding and Sanitization",
                                    target_url=target_url,
                                    http_status=http_status,
                                    execution_error=str(exc),
                                )

                        # Capture DevTools console screenshot via CDP session after test execution
                        test_meta = {
                            "shortcode": sc_upper,
                            "name": registered["name"] if registered else f"Requirement {sc_upper}",
                            "status": res.status,
                            "evidence": res.evidence,
                        }
                        shot = await h_ctx.capture_screenshot(test_info=test_meta)
                        if shot and not res.screenshot:
                            res.screenshot = shot

                        if res.http_status is None:
                            res.http_status = http_status
                        if not res.target_url:
                            res.target_url = target_url

                        executed_results[sc_upper] = res
                        trace_entry["status"] = res.status
                        trace_entry["observation_preview"] = res.evidence[:250]
                        if res.screenshot:
                            trace_entry["screenshot"] = res.screenshot
                        if on_step_callback:
                            on_step_callback(agent_trace)

                        step_num += 1
                        return res

                    # 3. Execution Phase
                    if single_test_id:
                        # Direct single-test invocation
                        await run_single_script(single_test_id, f"Direct execution of requirement {single_test_id}")
                    else:
                        # Full Chapter V1 Suite: Agent-Coordinated Execution
                        gemini_key = os.getenv("GEMINI_API_KEY")
                        use_agent_coordination = bool(gemini_key)

                        if use_agent_coordination:
                            try:
                                client = genai.Client(api_key=gemini_key)

                                # Page reconnaissance for the Gemini Agent
                                recon_summary = await page.evaluate("""() => ({
                                    title: document.title,
                                    url: location.href,
                                    formsCount: document.forms.length,
                                    inputCount: document.querySelectorAll('input, textarea, select').length,
                                    inputs: Array.from(document.querySelectorAll('input[name], textarea[name]'))
                                        .map(i => ({ name: i.name, type: i.type || 'text' }))
                                        .slice(0, 10),
                                    scriptCount: document.scripts.length,
                                    linksCount: document.querySelectorAll('a[href]').length,
                                })""")

                                available_scripts = list_script_definitions()
                                script_catalog = [
                                    {
                                        "requirement_id": s.requirement_id,
                                        "script_id": s.script_id,
                                        "name": s.name,
                                        "objective": s.objective,
                                        "execution_mode": s.execution_mode,
                                    }
                                    for s in available_scripts.values()
                                ]

                                agent_trace.append({
                                    "step": step_num,
                                    "tool": "gemini_agent_planner",
                                    "reason": f"Agent analyzing target attack surface on {target_url} to coordinate Chapter V1 test scripts.",
                                    "observation_preview": f"Discovered {recon_summary.get('formsCount', 0)} forms, {recon_summary.get('inputCount', 0)} inputs. Available scripts: {len(script_catalog)}.",
                                    "status": "completed",
                                })
                                step_num += 1
                                if on_step_callback:
                                    on_step_callback(agent_trace)

                                system_instruction = (
                                    "You are an automated OWASP ASVS verification security auditor coordinating Chapter V1 (Encoding and Sanitization). "
                                    "Your backend provides predefined, deterministic test scripts for requirements like V1.3.7 (template injection), "
                                    "V1.2.1 (HTML output encoding), V1.2.2 (URL schemes), V1.1.1 (canonical input decoding), etc. "
                                    "Analyze the page attack surface (forms, inputs, URL structure) and invoke the relevant test scripts via "
                                    "the 'execute_v1_test_script' tool. "
                                    "Your backend's deterministic test scripts evaluate real evidence; you coordinate the workflow and conclude when relevant tests have run."
                                )

                                contents = [
                                    types.Content(
                                        role="user",
                                        parts=[
                                            types.Part.from_text(
                                                text=json.dumps({
                                                    "task": "Coordinate Chapter V1 (Encoding and Sanitization) verification",
                                                    "target_url": target_url,
                                                    "page_reconnaissance": recon_summary,
                                                    "http_headers": doc_headers,
                                                    "available_scripts": script_catalog[:15],
                                                })
                                            )
                                        ],
                                    )
                                ]

                                # Up to 4 agent coordination turns
                                for turn in range(4):
                                    resp = await client.aio.models.generate_content(
                                        model=DEFAULT_GEMINI_MODEL,
                                        contents=contents,
                                        config=types.GenerateContentConfig(
                                            system_instruction=system_instruction,
                                            tools=[V1_AGENT_TOOLS],
                                        ),
                                    )

                                    if not resp.candidates or not resp.candidates[0].content:
                                        break
                                    contents.append(resp.candidates[0].content)

                                    if not resp.function_calls:
                                        break

                                    func_responses = []
                                    for call in resp.function_calls:
                                        fn_name = call.name
                                        fn_args = dict(call.args) if call.args else {}

                                        if fn_name == "execute_v1_test_script":
                                            req_id = fn_args.get("requirement_id", "V1.3.7")
                                            r_reason = fn_args.get("reason", "Auditing requirement via agent coordination")
                                            script_res = await run_single_script(req_id, r_reason)
                                            output = {
                                                "requirement_id": script_res.shortcode,
                                                "script_id": script_res.script_id,
                                                "verification_status": script_res.verification_status,
                                                "evidence": script_res.evidence,
                                                "tests_executed": len(script_res.tests),
                                                "has_screenshot": bool(script_res.screenshot),
                                            }
                                        elif fn_name == "inspect_page_dom":
                                            expr = fn_args.get("js_expression", "() => ({})")
                                            try:
                                                dom_val = await page.evaluate(expr)
                                                output = {"status": "ok", "result": dom_val}
                                            except Exception as d_err:
                                                output = {"status": "error", "error": str(d_err)}
                                        elif fn_name == "capture_page_screenshot":
                                            agent_meta = {
                                                "shortcode": "AGENT",
                                                "name": "Gemini Agent Interactive Probe",
                                                "status": "INFO",
                                                "evidence": "Agent requested page console snapshot",
                                            }
                                            s_data = await landing_ctx.capture_screenshot(test_info=agent_meta)
                                            output = {"status": "ok", "has_screenshot": bool(s_data)}
                                        else:
                                            output = {"error": f"Unknown tool: {fn_name}"}

                                        resp_kwargs = {"name": fn_name, "response": {"result": output}}
                                        call_id = getattr(call, "id", None)
                                        if call_id:
                                            resp_kwargs["id"] = call_id
                                        func_responses.append(types.Part.from_function_response(**resp_kwargs))

                                    contents.append(types.Content(role="user", parts=func_responses))

                            except Exception as agent_err:
                                agent_trace.append({
                                    "step": step_num,
                                    "tool": "gemini_agent_fallback",
                                    "reason": f"Agent coordination notice: {str(agent_err)[:150]}. Executing complete deterministic test suite.",
                                    "observation_preview": "Deterministic test runner activated for full Chapter V1 coverage.",
                                    "status": "fallback",
                                })
                                step_num += 1
                                if on_step_callback:
                                    on_step_callback(agent_trace)

                        # Ensure all registered test scripts in V1 are executed
                        for req in all_reqs:
                            sc = req.get("shortcode", "").strip().upper()
                            if sc not in executed_results and get_registered_test(sc):
                                await run_single_script(sc, f"Deterministic execution of registered script for {sc}")

                    # 4. Evaluate remaining passive and review requirements in Chapter V1
                    if not single_test_id:
                        landing_h_ctx = HarnessContext(
                            page=page,
                            cdp=cdp_session,
                            target_url=target_url,
                            doc_headers=doc_headers,
                            cdp_issues=cdp_issues,
                            http_status=http_status,
                        )
                        passive_results = await v1_scripts.evaluate_v1_passive_and_review_requirements(
                            all_v1_reqs=all_reqs,
                            ctx=landing_h_ctx,
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

                    # Order results canonically
                    ordered_results: List[TestResult] = []
                    for req in all_reqs:
                        sc = req.get("shortcode", "").strip().upper()
                        if sc in executed_results:
                            ordered_results.append(executed_results[sc])

                    # 5. Generate Scored Site Report
                    report = await generate_site_report(
                        target_url=target_url,
                        results=ordered_results,
                        raw_headers=doc_headers,
                        agent_trace=agent_trace,
                    )
                    if isinstance(report, dict):
                        report["browser_session"] = browser_session

                    return report

                finally:
                    if browser:
                        try:
                            await browser.close()
                        except Exception:
                            pass

                    if session_id:
                        try:
                            async with httpx.AsyncClient(timeout=10.0) as http_client:
                                await http_client.delete(
                                    f"{TINYFISH_URL}/{session_id}",
                                    headers=headers,
                                )
                        except Exception:
                            pass
