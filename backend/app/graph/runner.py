import os
import urllib.parse
from typing import Dict, Any, List, Optional, Callable
import httpx
from playwright.async_api import async_playwright

from app.config import TINYFISH_URL, TINYFISH_API_KEY
from app.graph.workflow import create_security_audit_graph
from harness.console_hud import attach_console_listeners

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

async def run_langgraph_security_audit(
    target_url: str,
    suite: str = "all",
    on_step_callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    on_session_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    max_iterations: int = 7,
    use_local_fallback: bool = True,
) -> Dict[str, Any]:
    """
    Executes the multi-agent security audit via LangGraph.
    Manages browser session acquisition, telemetry capture, and graph state execution.
    """
    session_id = None
    cdp_url = None
    live_view_url = None
    browser_session: Dict[str, Any] = {}
    trace: List[Dict[str, Any]] = []
    doc_headers: Dict[str, str] = {}
    cdp_issues: List[str] = []
    console_logs: List[Dict[str, Any]] = []

    api_key = os.getenv("TINYFISH_API_KEY", TINYFISH_API_KEY)
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    can_use_tinyfish = (
        bool(api_key and api_key.startswith("sk-tinyfish"))
        and not _is_local_url(target_url)
    )

    async with async_playwright() as p:
        browser = None
        try:
            if can_use_tinyfish:
                trace.append({
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
                    on_step_callback(list(trace))

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

                    trace.append({
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
                        on_step_callback(list(trace))

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
                except Exception as tf_err:
                    if not use_local_fallback:
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
                    trace.append({
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
                        on_step_callback(list(trace))
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
                trace.append({
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
                    on_step_callback(list(trace))

            # Set up CDP session and event listeners
            cdp_session = None
            try:
                cdp_session = await context.new_cdp_session(page)
                await cdp_session.send("Page.enable")
                await cdp_session.send("Audits.enable")
                await cdp_session.send("Network.enable")
                await cdp_session.send("Network.setCacheDisabled", {"cacheDisabled": True})

                try:
                    await context.set_extra_http_headers({
                        "Pragma": "no-cache",
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                    })
                except Exception:
                    pass

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

            try:
                attach_console_listeners(page, cdp_session, console_logs)
            except Exception:
                pass

            http_status = None
            nav_error = None
            resp = None
            try:
                resp = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
                if resp:
                    http_status = resp.status
                    if not doc_headers:
                        doc_headers.update(resp.headers)
            except Exception as e:
                nav_error = str(e)

            # Check if target is unreachable (connection error, tunnel failure, or Chrome error page)
            page_current_url = getattr(page, "url", "") if page else ""
            if nav_error or resp is None or page_current_url.startswith("chrome-error://"):
                err_detail = "net::ERR_TUNNEL_CONNECTION_FAILED" if "ERR_TUNNEL_CONNECTION_FAILED" in str(nav_error) else (nav_error or "net::ERR_CONNECTION_FAILED")
                if "Error: " in err_detail:
                    err_detail = err_detail.split("Error: ")[-1].split("\n")[0].strip()
                fail_msg = f"Target cannot be reached ({err_detail}). Session terminated."

                trace.append({
                    "step": len(trace) + 1,
                    "phase": "browser_navigation",
                    "tool": "browser_navigator",
                    "agent": "Browser Controller",
                    "action": "navigate_failed",
                    "reason": f"Connecting to {target_url} via CDP session",
                    "observation_preview": fail_msg,
                    "status": "failed",
                    "error": fail_msg,
                })
                if on_step_callback:
                    on_step_callback(list(trace))

                if on_session_callback:
                    on_session_callback({
                        "provider": "tinyfish" if session_id else "local",
                        "session_id": session_id,
                        "status": "terminated",
                        "target_url": target_url,
                        "error": fail_msg,
                    })

                return {
                    "target_url": target_url,
                    "workflow": "langgraph_multi_agent",
                    "score": None,
                    "grade": "NOT_ASSESSED",
                    "scan_status": "failed",
                    "coverage_percentage": 0.0,
                    "pass_rate_percentage": None,
                    "summary": fail_msg,
                    "error": fail_msg,
                    "metrics": {
                        "total_requirements": 0,
                        "total_evaluated": 0,
                        "passed": 0,
                        "failed": 0,
                        "manual_verify": 0,
                        "not_tested": 0,
                        "errors": 1,
                    },
                    "findings": [],
                    "asvs_results": [],
                    "chapter_breakdown": {},
                    "agent_trace": trace,
                    "raw_headers": {},
                    "screenshot": None,
                    "browser_session": {
                        "status": "terminated",
                        "target_url": target_url,
                        "error": fail_msg,
                    },
                }

            trace.append({
                "step": len(trace) + 1,
                "phase": "browser_navigation",
                "tool": "browser_navigator",
                "agent": "Browser Controller",
                "action": "navigate",
                "reason": f"Navigating to {target_url} via CDP session",
                "observation_preview": f"HTTP status: {http_status or 200}. Document headers: {len(doc_headers)} captured.",
                "status": "completed",
            })
            if on_step_callback:
                on_step_callback(list(trace))

            # Initialize LangGraph State
            initial_state = {
                "target_url": target_url,
                "suite_type": suite,
                "protocol": "https:" if target_url.startswith("https:") else "http:",
                "http_status": http_status,
                "doc_headers": doc_headers,
                "cdp_issues": cdp_issues,
                "console_logs": console_logs,
                "page": page,
                "cdp": cdp_session,
                "current_step": len(trace) + 1,
                "agent_trace": trace,
                "browser_session": browser_session,
                "raw_findings": [],
                "asvs_results": [],
                "chapter_breakdown": {},
                "completed_agents": [],
                "iteration_count": 0,
                "max_iterations": max_iterations,
            }

            audit_graph = create_security_audit_graph()

            final_state = dict(initial_state)
            async for event in audit_graph.astream(initial_state):
                for node_name, node_output in event.items():
                    final_state.update(node_output)
                    trace = final_state.get("agent_trace", [])
                    if on_step_callback and trace:
                        on_step_callback(trace)

            report = final_state.get("final_report")
            if not report:
                report = {
                    "target_url": target_url,
                    "workflow": "langgraph_multi_agent",
                    "score": final_state.get("score"),
                    "grade": final_state.get("grade", "NOT_ASSESSED"),
                    "scan_status": final_state.get("scan_status", "completed"),
                    "coverage_percentage": final_state.get("coverage_percentage", 0.0),
                    "pass_rate_percentage": final_state.get("pass_rate_percentage"),
                    "summary": final_state.get("summary", ""),
                    "metrics": final_state.get("metrics", {}),
                    "findings": final_state.get("raw_findings", []),
                    "asvs_results": final_state.get("asvs_results", []),
                    "chapter_breakdown": final_state.get("chapter_breakdown", {}),
                    "agent_trace": final_state.get("agent_trace", []),
                    "raw_headers": doc_headers,
                    "screenshot": final_state.get("baseline_screenshot"),
                    "browser_session": browser_session,
                }
            elif isinstance(report, dict) and "browser_session" not in report:
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
                        await http_client.delete(f"{TINYFISH_URL}/{session_id}", headers=headers)
                except Exception:
                    pass
