import time
import json
from typing import Dict, Any, List, Optional

import asyncio

def _safe_on(emitter: Any, event: str, handler: Any):
    try:
        ret = emitter.on(event, handler)
        if asyncio.iscoroutine(ret):
            ret.close()
    except Exception:
        pass

def attach_console_listeners(page: Any, cdp: Any, log_sink: List[Dict[str, Any]]):
    """Hooks into Playwright Page and CDP session to capture real browser console telemetry."""
    if not page:
        return

    def on_console(msg):
        try:
            log_sink.append({
                "type": "error" if msg.type == "error" else "warn" if msg.type == "warning" else "info",
                "text": msg.text,
                "source": msg.location.get("url", "console") if msg.location else "console",
                "time": time.strftime("%H:%M:%S"),
            })
        except Exception:
            pass

    _safe_on(page, "console", on_console)

    def on_pageerror(err):
        try:
            log_sink.append({
                "type": "error",
                "text": f"Uncaught exception: {str(err)}",
                "source": "runtime",
                "time": time.strftime("%H:%M:%S"),
            })
        except Exception:
            pass

    _safe_on(page, "pageerror", on_pageerror)

    def on_requestfailed(req):
        try:
            failure = req.failure
            err_text = failure.get("errorText", "Failed") if isinstance(failure, dict) else str(failure)
            log_sink.append({
                "type": "error",
                "text": f"Failed to load resource: net::{err_text} at {req.url}",
                "source": "network",
                "time": time.strftime("%H:%M:%S"),
            })
        except Exception:
            pass

    _safe_on(page, "requestfailed", on_requestfailed)

    if cdp:
        def on_audit(params):
            try:
                issue = params.get("issue", {})
                code = issue.get("code", "SecurityIssue")
                details = issue.get("details", {})
                log_sink.append({
                    "type": "warn",
                    "text": f"[CDP Audit] {code}: {json.dumps(details)[:120]}",
                    "source": "audits",
                    "time": time.strftime("%H:%M:%S"),
                })
            except Exception:
                pass

        _safe_on(cdp, "Audits.issueAdded", on_audit)

def build_console_logs(
    target_url: str,
    doc_headers: Dict[str, str],
    http_status: Optional[int],
    captured_logs: List[Dict[str, Any]],
    current_test: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Synthesizes browser console messages, security headers, and test execution probes."""
    logs: List[Dict[str, Any]] = []

    # 1. Navigation baseline log
    status_label = f" (HTTP {http_status})" if http_status else ""
    logs.append({
        "type": "info",
        "text": f"Navigated to {target_url}{status_label}",
        "source": "navigation",
        "time": time.strftime("%H:%M:%S"),
    })

    # 2. Key Security Header Telemetry
    lower_headers = {k.lower(): v for k, v in doc_headers.items()}
    if "content-security-policy" not in lower_headers:
        logs.append({
            "type": "warn",
            "text": f"[Security Audit] Missing Content-Security-Policy (CSP) on {target_url}",
            "source": "security",
            "time": time.strftime("%H:%M:%S"),
        })
    else:
        logs.append({
            "type": "info",
            "text": f"[Security Audit] Content-Security-Policy active: {lower_headers['content-security-policy'][:80]}...",
            "source": "security",
            "time": time.strftime("%H:%M:%S"),
        })

    if "strict-transport-security" not in lower_headers and target_url.startswith("https:"):
        logs.append({
            "type": "warn",
            "text": f"[Security Audit] Missing Strict-Transport-Security (HSTS) on {target_url}",
            "source": "security",
            "time": time.strftime("%H:%M:%S"),
        })

    # 3. Append captured browser console events (errors, warnings, pageerrors)
    for l in captured_logs[-12:]:  # Keep recent 12 entries
        logs.append(l)

    # 4. Append current test execution probe log if available
    if current_test:
        sc = current_test.get("shortcode", "")
        name = current_test.get("name", "")
        status = current_test.get("status", "RUNNING")
        evidence = current_test.get("evidence", "") or current_test.get("observations", "")
        
        log_type = "error" if status == "FAIL" else "warn" if status == "MANUAL_VERIFY" else "info"
        badge = f"[{status}]"
        logs.append({
            "type": log_type,
            "text": f"[Tinyfah::{sc}] {badge} {name}: {evidence[:160]}",
            "source": f"asvs_{sc.lower()}",
            "time": time.strftime("%H:%M:%S"),
        })

    return logs

INJECT_CONSOLE_JS = """
(args) => {
    const logs = args.logs || [];
    const targetUrl = args.target_url || '';
    const currentTest = args.current_test || '';
    
    const existing = document.getElementById('tinyfah-devtools-dock');
    if (existing) existing.remove();
    
    let errorCount = 0;
    let warnCount = 0;
    let infoCount = 0;
    logs.forEach(l => {
        if (l.type === 'error') errorCount++;
        else if (l.type === 'warn') warnCount++;
        else infoCount++;
    });

    const dock = document.createElement('div');
    dock.id = 'tinyfah-devtools-dock';
    dock.style.cssText = `
        position: fixed;
        bottom: 0;
        left: 0;
        width: 100vw;
        height: 380px;
        background-color: #202124;
        color: #e8eaed;
        font-family: 'Consolas', 'Menlo', 'Monaco', 'Courier New', monospace;
        font-size: 12px;
        z-index: 2147483647;
        display: flex;
        flex-direction: column;
        border-top: 2px solid #5f6368;
        box-shadow: 0 -4px 20px rgba(0,0,0,0.7);
        box-sizing: border-box;
    `;

    // Header bar
    const header = document.createElement('div');
    header.style.cssText = `
        display: flex;
        align-items: center;
        background: #292a2d;
        border-bottom: 1px solid #3c4043;
        padding: 5px 10px;
        user-select: none;
        gap: 10px;
    `;
    
    header.innerHTML = `
        <div style="display:flex; gap:16px; font-family:-apple-system,BlinkMacSystemFont,Roboto,sans-serif; font-size:12px; color:#9aa0a6;">
            <span>Elements</span>
            <span style="color:#8ab4f8; font-weight:600; border-bottom:2px solid #8ab4f8; padding-bottom:3px;">Console</span>
            <span>Sources</span>
            <span>Network</span>
            <span>Security</span>
            <span>Application</span>
        </div>
        <div style="flex:1; display:flex; align-items:center; gap:8px; margin-left:12px; color:#9aa0a6; font-size:11px;">
            <span style="color:#bdc1c6;">Target: <strong style="color:#8ab4f8;">${targetUrl}</strong></span>
            ${currentTest ? `<span style="background:#3c4043; padding:1px 6px; border-radius:3px; color:#e8eaed;">${currentTest}</span>` : ''}
        </div>
        <div style="display:flex; gap:8px; font-size:11px; align-items:center;">
            <span style="background:#ea4335; color:#fff; border-radius:10px; padding:1px 7px; font-weight:bold;">⨂ ${errorCount}</span>
            <span style="background:#fbbc04; color:#202124; border-radius:10px; padding:1px 7px; font-weight:bold;">⚠️ ${warnCount}</span>
            <span style="background:#1a73e8; color:#fff; border-radius:10px; padding:1px 7px; font-weight:bold;">ℹ️ ${infoCount}</span>
            <span style="color:#9aa0a6; border:1px solid #5f6368; padding:2px 6px; border-radius:3px;">Top ▼</span>
        </div>
    `;
    dock.appendChild(header);

    // Logs Container
    const body = document.createElement('div');
    body.style.cssText = `
        flex: 1;
        overflow-y: auto;
        padding: 4px 0;
        background: #202124;
    `;

    logs.forEach(l => {
        const row = document.createElement('div');
        let bg = 'transparent';
        let color = '#e8eaed';
        let icon = 'ℹ️';
        let border = '#2d2f31';
        
        if (l.type === 'error') {
            bg = 'rgba(234, 67, 53, 0.15)';
            color = '#f28b82';
            icon = '⨂';
            border = '#5c1d1d';
        } else if (l.type === 'warn') {
            bg = 'rgba(251, 188, 4, 0.12)';
            color = '#fdd663';
            icon = '⚠️';
            border = '#534200';
        }

        row.style.cssText = `
            display: flex;
            padding: 4px 10px;
            border-bottom: 1px solid ${border};
            background: ${bg};
            align-items: flex-start;
            line-height: 1.45;
        `;

        row.innerHTML = `
            <span style="width:22px; font-size:12px; flex-shrink:0;">${icon}</span>
            <span style="color:${color}; flex:1; word-break:break-word;">${l.text}</span>
            <span style="color:#9aa0a6; font-size:11px; margin-left:14px; flex-shrink:0; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${l.source}</span>
        `;
        body.appendChild(row);
    });

    // Console Input Line
    const prompt = document.createElement('div');
    prompt.style.cssText = `
        display: flex;
        align-items: center;
        padding: 5px 10px;
        border-top: 1px solid #3c4043;
        background: #202124;
        color: #8ab4f8;
    `;
    prompt.innerHTML = `
        <span style="margin-right:8px; font-weight:bold; font-size:13px;">&gt;</span>
        <span style="display:inline-block; width:7px; height:13px; background:#8ab4f8;"></span>
    `;
    body.appendChild(prompt);

    dock.appendChild(body);
    document.body.appendChild(dock);
}
"""

REMOVE_CONSOLE_JS = """
() => {
    const existing = document.getElementById('tinyfah-devtools-dock');
    if (existing) existing.remove();
}
"""
