from typing import Dict, Any, List
from app.graph.state import AuditGraphState
from app.core.screenshots import capture_hud_screenshot

async def recon_node(state: AuditGraphState) -> Dict[str, Any]:
    """Navigates to the target, collects initial DOM recon, cookies, and captures baseline screenshot."""
    page = state.get("page")
    cdp = state.get("cdp")
    target_url = state.get("target_url", "")
    doc_headers = state.get("doc_headers", {})
    console_logs = state.get("console_logs", [])
    agent_trace = list(state.get("agent_trace", []))
    step = state.get("current_step", 1)

    initial_recon = {}
    cookies: List[Dict[str, Any]] = []

    if page:
        try:
            initial_recon = await page.evaluate("""() => ({
                title: document.title,
                url: location.href,
                protocol: location.protocol,
                forms: Array.from(document.forms).map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.elements)
                        .filter(e => e.tagName === 'INPUT' || e.tagName === 'TEXTAREA')
                        .map(e => ({ name: e.name, type: e.type || 'text', id: e.id }))
                })),
                inputCount: document.querySelectorAll('input, textarea, select').length,
                scriptCount: document.scripts.length,
                externalScriptCount: Array.from(document.scripts).filter(s => s.src && !s.src.startsWith(location.origin)).length,
                metaTags: Array.from(document.querySelectorAll('meta[http-equiv], meta[name="referrer"]'))
                    .map(m => ({ name: m.name || m.httpEquiv, content: m.content }))
            })""")
        except Exception:
            initial_recon = {
                "title": "",
                "url": target_url,
                "protocol": "https:" if target_url.startswith("https:") else "http:",
                "forms": [],
                "inputCount": 0,
                "scriptCount": 0,
                "externalScriptCount": 0,
                "metaTags": [],
            }

    if cdp:
        try:
            cookies_res = await cdp.send("Network.getAllCookies")
            cookies = cookies_res.get("cookies", [])
        except Exception:
            cookies = []

    # Check if page is an internal browser error page or unreachable
    page_current_url = getattr(page, "url", "") if page else ""
    is_chrome_error = page_current_url.startswith("chrome-error://") or not state.get("http_status")

    # Capture baseline screenshot with DevTools Console HUD
    test_meta = {
        "shortcode": "RECON",
        "name": "Reconnaissance & Baseline Audit",
        "status": "FAIL" if is_chrome_error else ("PASS" if (state.get("http_status") or 200) < 400 else "INFO"),
        "evidence": "Target cannot be reached. Session terminated." if is_chrome_error else f"Navigated to {target_url} - Extracted attack surface",
    }
    baseline_shot = await capture_hud_screenshot(
        page=page,
        cdp=cdp,
        target_url=target_url,
        doc_headers=doc_headers,
        http_status=state.get("http_status"),
        console_logs=console_logs,
        test_info=test_meta,
        prefix="recon_baseline",
    )

    forms_count = len(initial_recon.get("forms", []))
    inputs_count = initial_recon.get("inputCount", 0)

    trace_entry = {
        "step": step,
        "tool": "recon_agent",
        "reason": f"Discovered page attack surface for {target_url}" if not is_chrome_error else f"Connecting to {target_url}",
        "observation_preview": (
            "Target cannot be reached. Session terminated."
            if is_chrome_error
            else f"Page title: '{initial_recon.get('title', 'N/A')}'. Discovered {forms_count} form(s), "
                 f"{inputs_count} input(s), {len(cookies)} cookie(s), and {len(doc_headers)} header(s)."
        ),
        "status": "failed" if is_chrome_error else "completed",
    }
    if baseline_shot:
        trace_entry["screenshot"] = baseline_shot

    agent_trace.append(trace_entry)

    return {
        "initial_recon": initial_recon,
        "cookies": cookies,
        "protocol": initial_recon.get("protocol", "https:"),
        "baseline_screenshot": baseline_shot,
        "agent_trace": agent_trace,
        "current_step": step + 1,
        "iteration_count": 0,
        "completed_agents": [],
        "tasks_planned": ["transport_headers", "input_encoding", "client_dom"],
    }
