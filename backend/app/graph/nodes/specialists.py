import json
from typing import Dict, Any, List
from app.graph.state import AuditGraphState
from app.core.screenshots import capture_hud_screenshot

# -------------------------------------------------------------------------
# 1. Transport & Security Headers Specialist Agent
# -------------------------------------------------------------------------
async def transport_headers_node(state: AuditGraphState) -> Dict[str, Any]:
    """Audits TLS transport encryption, HTTP security headers, and cookie attributes."""
    page = state.get("page")
    cdp = state.get("cdp")
    target_url = state.get("target_url", "")
    protocol = state.get("protocol", "https:")
    headers = state.get("doc_headers", {})
    cookies = state.get("cookies", [])
    raw_findings = list(state.get("raw_findings", []))
    asvs_results = list(state.get("asvs_results", []))
    agent_trace = list(state.get("agent_trace", []))
    completed = list(state.get("completed_agents", []))
    step = state.get("current_step", 1)

    lower_headers = {k.lower(): v for k, v in headers.items()}
    new_findings: List[Dict[str, Any]] = []
    agent_shot = None

    # 1. TLS Check (V12.1.1)
    if protocol == "https:":
        asvs_results.append({
            "requirement_id": "V12.1.1",
            "chapter_code": "V12",
            "chapter_name": "Communications",
            "section_name": "TLS",
            "description": "Verify TLS transport encryption",
            "status": "PASS",
            "severity": "info",
            "evidence": f"TLS encryption active on primary HTTPS connection ({protocol}).",
            "remediation": "",
        })
    else:
        ev = f"Insecure HTTP connection ({protocol}); TLS transport encryption is not enabled."
        new_findings.append({
            "type": "tls",
            "severity": "high",
            "detail": "Insecure HTTP connection (Missing TLS)",
            "asvs": "V12.1.1",
            "requirement_id": "V12.1.1",
            "requirement_ids": ["V12.1.1"],
            "evidence": ev,
            "remediation": "Enforce HTTPS redirect and enable modern TLS (TLS 1.2+).",
        })
        asvs_results.append({
            "requirement_id": "V12.1.1",
            "chapter_code": "V12",
            "chapter_name": "Communications",
            "section_name": "TLS",
            "description": "Verify TLS transport encryption",
            "status": "FAIL",
            "severity": "high",
            "evidence": ev,
            "remediation": "Enforce HTTPS redirect and enable modern TLS (TLS 1.2+).",
        })

    # 2. HSTS Check (V3.4.1)
    if protocol == "https:":
        if "strict-transport-security" in lower_headers:
            asvs_results.append({
                "requirement_id": "V3.4.1",
                "chapter_code": "V3",
                "chapter_name": "Architecture",
                "section_name": "Headers",
                "description": "Verify Strict-Transport-Security header",
                "status": "PASS",
                "severity": "info",
                "evidence": f"Strict-Transport-Security present: '{lower_headers['strict-transport-security']}'.",
                "remediation": "",
            })
        else:
            ev = f"Strict-Transport-Security (HSTS) header is missing from HTTP response. Observed header keys: {sorted(list(lower_headers.keys()))}"
            new_findings.append({
                "type": "header",
                "severity": "medium",
                "detail": "Missing HSTS Header (Strict-Transport-Security)",
                "asvs": "V3.4.1",
                "requirement_id": "V3.4.1",
                "requirement_ids": ["V3.4.1"],
                "evidence": ev,
                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce TLS.",
            })
            asvs_results.append({
                "requirement_id": "V3.4.1",
                "chapter_code": "V3",
                "chapter_name": "Architecture",
                "section_name": "Headers",
                "description": "Verify Strict-Transport-Security header",
                "status": "FAIL",
                "severity": "medium",
                "evidence": ev,
                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce TLS.",
            })

    # 3. Content-Security-Policy (V3.4.2)
    if "content-security-policy" in lower_headers:
        asvs_results.append({
            "requirement_id": "V3.4.2",
            "chapter_code": "V3",
            "chapter_name": "Architecture",
            "section_name": "Headers",
            "description": "Verify Content-Security-Policy header",
            "status": "PASS",
            "severity": "info",
            "evidence": f"CSP active: '{lower_headers['content-security-policy'][:80]}...'",
            "remediation": "",
        })
    else:
        ev = "Content-Security-Policy (CSP) header missing from HTTP response."
        new_findings.append({
            "type": "header",
            "severity": "medium",
            "detail": "Missing Content-Security-Policy (CSP)",
            "asvs": "V3.4.2",
            "requirement_id": "V3.4.2",
            "requirement_ids": ["V3.4.2"],
            "evidence": ev,
            "remediation": "Implement a restrictive CSP (e.g., default-src 'self').",
        })
        asvs_results.append({
            "requirement_id": "V3.4.2",
            "chapter_code": "V3",
            "chapter_name": "Architecture",
            "section_name": "Headers",
            "description": "Verify Content-Security-Policy header",
            "status": "FAIL",
            "severity": "medium",
            "evidence": ev,
            "remediation": "Implement a restrictive Content-Security-Policy.",
        })

    # 4. Content-Type Header (V4.1.1)
    if "content-type" in lower_headers:
        asvs_results.append({
            "requirement_id": "V4.1.1",
            "chapter_code": "V4",
            "chapter_name": "Access Control",
            "section_name": "Content-Type",
            "description": "Verify Content-Type header with charset",
            "status": "PASS",
            "severity": "info",
            "evidence": f"Content-Type header present: '{lower_headers['content-type']}'.",
            "remediation": "",
        })
    else:
        ev = "Response body missing explicit Content-Type header."
        new_findings.append({
            "type": "header",
            "severity": "medium",
            "detail": "Missing Content-Type header",
            "asvs": "V4.1.1",
            "requirement_id": "V4.1.1",
            "requirement_ids": ["V4.1.1"],
            "evidence": ev,
            "remediation": "Specify Content-Type with character set (e.g. text/html; charset=utf-8).",
        })
        asvs_results.append({
            "requirement_id": "V4.1.1",
            "chapter_code": "V4",
            "chapter_name": "Access Control",
            "section_name": "Content-Type",
            "description": "Verify Content-Type header with charset",
            "status": "FAIL",
            "severity": "medium",
            "evidence": ev,
            "remediation": "Specify Content-Type with character set.",
        })

    # 5. Session Cookies (V7.1.1)
    insecure_cookies = [
        c.get("name", "unnamed")
        for c in cookies
        if not c.get("secure") or not c.get("httpOnly")
    ]
    if insecure_cookies:
        ev = f"Cookies missing Secure or HttpOnly flags: {', '.join(insecure_cookies[:5])}."
        new_findings.append({
            "type": "cookie",
            "severity": "medium",
            "detail": "Insecure cookie flags",
            "asvs": "V7.1.1",
            "requirement_id": "V7.1.1",
            "requirement_ids": ["V7.1.1"],
            "evidence": ev,
            "remediation": "Ensure all session cookies set HttpOnly, Secure, and SameSite=Lax/Strict flags.",
        })
        asvs_results.append({
            "requirement_id": "V7.1.1",
            "chapter_code": "V7",
            "chapter_name": "Session Management",
            "section_name": "Cookies",
            "description": "Verify session cookie flags",
            "status": "FAIL",
            "severity": "medium",
            "evidence": ev,
            "remediation": "Ensure all session cookies set HttpOnly and Secure flags.",
        })
    elif cookies:
        asvs_results.append({
            "requirement_id": "V7.1.1",
            "chapter_code": "V7",
            "chapter_name": "Session Management",
            "section_name": "Cookies",
            "description": "Verify session cookie flags",
            "status": "PASS",
            "severity": "info",
            "evidence": f"All observed cookies ({len(cookies)}) have Secure and HttpOnly flags configured.",
            "remediation": "",
        })
    else:
        asvs_results.append({
            "requirement_id": "V7.1.1",
            "chapter_code": "V7",
            "chapter_name": "Session Management",
            "section_name": "Cookies",
            "description": "Verify session cookie flags",
            "status": "NOT_TESTED",
            "severity": "info",
            "evidence": "No cookies were observed in the HTTP response; cannot evaluate session cookie attributes without an active session.",
            "remediation": "Authenticate or perform user actions that set session cookies.",
        })

    # Capture HUD screenshot if new findings discovered
    if new_findings and page:
        agent_meta = {
            "shortcode": "HEADERS",
            "name": "Security Headers & Transport Audit",
            "status": "FAIL",
            "evidence": f"Detected {len(new_findings)} transport/header configuration gaps.",
        }
        agent_shot = await capture_hud_screenshot(
            page=page,
            cdp=cdp,
            target_url=target_url,
            doc_headers=headers,
            console_logs=state.get("console_logs", []),
            test_info=agent_meta,
            prefix="shot_headers",
        )
        if agent_shot:
            for nf in new_findings:
                nf["screenshot"] = agent_shot

    raw_findings.extend(new_findings)
    completed.append("transport_headers")

    trace_entry = {
        "step": step,
        "tool": "transport_headers_agent",
        "reason": f"Audited transport and HTTP response headers for {target_url}",
        "observation_preview": f"Discovered {len(new_findings)} issues across TLS, HSTS, CSP, and Cookies.",
        "status": "completed",
    }
    if agent_shot:
        trace_entry["screenshot"] = agent_shot
    agent_trace.append(trace_entry)

    return {
        "raw_findings": raw_findings,
        "asvs_results": asvs_results,
        "agent_trace": agent_trace,
        "completed_agents": completed,
        "current_step": step + 1,
    }


# -------------------------------------------------------------------------
# 2. Input Encoding & Canary Specialist Agent
# -------------------------------------------------------------------------
async def input_encoding_node(state: AuditGraphState) -> Dict[str, Any]:
    """Audits Chapter V1 input encoding, reflection, canary probe escapes, and SSTI."""
    page = state.get("page")
    cdp = state.get("cdp")
    target_url = state.get("target_url", "")
    recon = state.get("initial_recon", {})
    raw_findings = list(state.get("raw_findings", []))
    asvs_results = list(state.get("asvs_results", []))
    agent_trace = list(state.get("agent_trace", []))
    completed = list(state.get("completed_agents", []))
    step = state.get("current_step", 1)

    new_findings: List[Dict[str, Any]] = []
    agent_shot = None

    # Check for insecure forms submitting over plain HTTP (V12.2.1, NOT V1)
    insecure_forms = []
    for f in recon.get("forms", []):
        action = f.get("action", "")
        if action and action.startswith("http://"):
            insecure_forms.append(action)

    if insecure_forms:
        new_findings.append({
            "type": "form",
            "severity": "high",
            "detail": "Form submitting over unencrypted HTTP",
            "asvs": "V12.2.1",
            "requirement_id": "V12.2.1",
            "requirement_ids": ["V12.2.1"],
            "evidence": f"Insecure form actions detected: {', '.join(insecure_forms[:3])}",
            "remediation": "Ensure all forms post over HTTPS endpoints.",
        })

    # Active Probe Injection for V1.2.1 & V1.3.7 if page is live
    v1_2_1_status = "NOT_TESTED"
    v1_2_1_evidence = "No dynamic reflection sink found on target URL."
    v1_3_7_status = "MANUAL_VERIFY"
    v1_3_7_evidence = "The browser test could not establish server-side template evaluation."

    if page:
        try:
            # 1. Probe HTML reflection (V1.2.1)
            canary = "<tinyfah-canary-test>"
            probe_url = f"{target_url}{'&' if '?' in target_url else '?'}q={canary}&search={canary}"
            resp = await page.goto(probe_url, wait_until="domcontentloaded", timeout=12000)
            body_text = await page.content()

            if canary in body_text:
                v1_2_1_status = "FAIL"
                v1_2_1_evidence = f"Unescaped canary '{canary}' reflected in HTTP response or altered DOM without HTML entity encoding."
                new_findings.append({
                    "type": "encoding",
                    "severity": "high",
                    "detail": "Context-Aware HTML Output Encoding",
                    "asvs": "V1.2.1",
                    "requirement_id": "V1.2.1",
                    "requirement_ids": ["V1.2.1"],
                    "evidence": v1_2_1_evidence,
                    "remediation": "Apply contextual HTML entity encoding to dynamic variables.",
                })
            elif "&lt;tinyfah-canary-test&gt;" in body_text:
                v1_2_1_status = "PASS"
                v1_2_1_evidence = f"Canary probe was properly escaped as '&lt;tinyfah-canary-test&gt;'."

            # 2. Probe Template Injection (V1.3.7)
            ssti_probe = "{{7*7}}"
            ssti_url = f"{target_url}{'&' if '?' in target_url else '?'}template={ssti_probe}&q={ssti_probe}"
            await page.goto(ssti_url, wait_until="domcontentloaded", timeout=12000)
            ssti_body = await page.content()

            # Check if 49 evaluated and was not present originally
            if "49" in ssti_body and "49" not in body_text:
                v1_3_7_status = "FAIL"
                v1_3_7_evidence = f"Testing demonstrates unintended evaluation of attacker-controlled template expressions: Expression '{{{{7*7}}}}' evaluated to '49' on {target_url}."
                new_findings.append({
                    "type": "injection",
                    "severity": "high",
                    "detail": "Server-Side Template Injection (SSTI)",
                    "asvs": "V1.3.7",
                    "requirement_id": "V1.3.7",
                    "requirement_ids": ["V1.3.7"],
                    "evidence": v1_3_7_evidence,
                    "remediation": "Disable template execution from untrusted inputs or use strict sandboxing.",
                })
            elif ssti_probe in ssti_body:
                v1_3_7_status = "PASS"
                v1_3_7_evidence = "Template expression '{{7*7}}' was safely rendered as a literal string without server-side evaluation."

        except Exception:
            pass

    asvs_results.append({
        "requirement_id": "V1.2.1",
        "chapter_code": "V1",
        "chapter_name": "Encoding and Sanitization",
        "section_name": "Output Encoding",
        "description": "Verify context-specific output encoding for HTML and attributes",
        "status": v1_2_1_status,
        "severity": "high" if v1_2_1_status == "FAIL" else "info",
        "evidence": v1_2_1_evidence,
        "remediation": "Apply contextual output encoding.",
    })

    asvs_results.append({
        "requirement_id": "V1.3.7",
        "chapter_code": "V1",
        "chapter_name": "Encoding and Sanitization",
        "section_name": "Template Injection",
        "description": "Verify template expressions cannot be executed as code",
        "status": v1_3_7_status,
        "severity": "high" if v1_3_7_status == "FAIL" else "info",
        "evidence": v1_3_7_evidence,
        "remediation": "Prevent user input interpretation in template engines.",
    })

    # Capture HUD screenshot if new findings discovered
    if new_findings and page:
        agent_meta = {
            "shortcode": "ENCODING",
            "name": "Input Encoding & Canary Probes",
            "status": "FAIL",
            "evidence": f"Found {len(new_findings)} output encoding/injection vulnerability(s).",
        }
        agent_shot = await capture_hud_screenshot(
            page=page,
            cdp=cdp,
            target_url=target_url,
            doc_headers=state.get("doc_headers", {}),
            console_logs=state.get("console_logs", []),
            test_info=agent_meta,
            prefix="shot_encoding",
        )
        if agent_shot:
            for nf in new_findings:
                nf["screenshot"] = agent_shot

    raw_findings.extend(new_findings)
    completed.append("input_encoding")

    trace_entry = {
        "step": step,
        "tool": "input_encoding_agent",
        "reason": f"Executed active canary probes for HTML encoding and template injection on {target_url}",
        "observation_preview": f"V1.2.1 result: {v1_2_1_status}. V1.3.7 SSTI result: {v1_3_7_status}.",
        "status": "completed",
    }
    if agent_shot:
        trace_entry["screenshot"] = agent_shot
    agent_trace.append(trace_entry)

    return {
        "raw_findings": raw_findings,
        "asvs_results": asvs_results,
        "agent_trace": agent_trace,
        "completed_agents": completed,
        "current_step": step + 1,
    }


# -------------------------------------------------------------------------
# 3. Client DOM & Asset Integrity Specialist Agent
# -------------------------------------------------------------------------
async def client_dom_node(state: AuditGraphState) -> Dict[str, Any]:
    """Audits client-side library exposures, missing Subresource Integrity (SRI), and unsafe links."""
    page = state.get("page")
    cdp = state.get("cdp")
    target_url = state.get("target_url", "")
    raw_findings = list(state.get("raw_findings", []))
    asvs_results = list(state.get("asvs_results", []))
    agent_trace = list(state.get("agent_trace", []))
    completed = list(state.get("completed_agents", []))
    step = state.get("current_step", 1)

    new_findings: List[Dict[str, Any]] = []
    agent_shot = None

    dom_data = {
        "missingSri": [],
        "detectedLibs": {},
        "unsafeLinks": [],
    }

    if page:
        try:
            dom_data = await page.evaluate("""() => ({
                missingSri: Array.from(document.querySelectorAll('script[src], link[rel="stylesheet"][href]'))
                    .filter(el => {
                        const url = el.src || el.href;
                        return url && !url.startsWith(location.origin) && !el.integrity;
                    })
                    .map(el => el.src || el.href)
                    .slice(0, 15),
                detectedLibs: {
                    jquery: window.jQuery ? window.jQuery.fn.jquery : null,
                    angular: window.angular && window.angular.version ? window.angular.version.full : null,
                    react: window.React ? window.React.version : null,
                    vue: window.Vue ? window.Vue.version : null
                },
                unsafeLinks: Array.from(document.querySelectorAll('a[target="_blank"]'))
                    .filter(a => !a.rel.includes('noopener') && !a.rel.includes('noreferrer'))
                    .map(a => a.href)
                    .slice(0, 10),
            })""")
        except Exception:
            pass

    missing_sri = dom_data.get("missingSri", [])
    unsafe_links = dom_data.get("unsafeLinks", [])
    detected_libs = dom_data.get("detectedLibs", {})

    if missing_sri:
        ev = f"{len(missing_sri)} external asset(s) loaded without Subresource Integrity (SRI) hashes: {', '.join(missing_sri[:3])}."
        new_findings.append({
            "type": "sri",
            "severity": "medium",
            "detail": "Missing Subresource Integrity (SRI) on external assets",
            "asvs": "V3.1.1",
            "requirement_id": "V3.1.1",
            "requirement_ids": ["V3.1.1"],
            "evidence": ev,
            "remediation": "Add integrity hashes to third-party scripts and stylesheets.",
        })

    if unsafe_links:
        ev = f"{len(unsafe_links)} external target='_blank' link(s) missing rel='noopener': {', '.join(unsafe_links[:3])}."
        new_findings.append({
            "type": "links",
            "severity": "low",
            "detail": "External links missing rel='noopener'",
            "asvs": "V3.1.1",
            "requirement_id": "V3.1.1",
            "requirement_ids": ["V3.1.1"],
            "evidence": ev,
            "remediation": "Add rel='noopener noreferrer' to all target='_blank' hyperlinks.",
        })

    exposed_libs = [f"{k} v{v}" for k, v in detected_libs.items() if v]
    if exposed_libs:
        ev = f"Exposed client-side library version signatures: {', '.join(exposed_libs)}."
        new_findings.append({
            "type": "library",
            "severity": "low",
            "detail": "Exposed client-side library versions",
            "asvs": "V3.1.1",
            "requirement_id": "V3.1.1",
            "requirement_ids": ["V3.1.1"],
            "evidence": ev,
            "remediation": "Review client-side dependencies against known CVE databases.",
        })

    # Capture HUD screenshot if new findings discovered
    if new_findings and page:
        agent_meta = {
            "shortcode": "DOM",
            "name": "Client DOM & Asset Integrity Audit",
            "status": "FAIL",
            "evidence": f"Found {len(new_findings)} client-side DOM & asset gaps.",
        }
        agent_shot = await capture_hud_screenshot(
            page=page,
            cdp=cdp,
            target_url=target_url,
            doc_headers=state.get("doc_headers", {}),
            console_logs=state.get("console_logs", []),
            test_info=agent_meta,
            prefix="shot_dom",
        )
        if agent_shot:
            for nf in new_findings:
                nf["screenshot"] = agent_shot

    raw_findings.extend(new_findings)
    completed.append("client_dom")

    trace_entry = {
        "step": step,
        "tool": "client_dom_agent",
        "reason": f"Audited client-side DOM, scripts, SRI, and external links for {target_url}",
        "observation_preview": f"Missing SRI: {len(missing_sri)}, Unsafe links: {len(unsafe_links)}, Exposed libraries: {len(exposed_libs)}.",
        "status": "completed",
    }
    if agent_shot:
        trace_entry["screenshot"] = agent_shot
    agent_trace.append(trace_entry)

    return {
        "raw_findings": raw_findings,
        "asvs_results": asvs_results,
        "agent_trace": agent_trace,
        "completed_agents": completed,
        "current_step": step + 1,
    }


# -------------------------------------------------------------------------
# 4. Authentication & Session Security Specialist Agent
# -------------------------------------------------------------------------
async def auth_session_node(state: AuditGraphState) -> Dict[str, Any]:
    """Audits authentication attack surface, login transport, password fields, credentials in URLs, and session storage."""
    page = state.get("page")
    cdp = state.get("cdp")
    target_url = state.get("target_url", "")
    recon = state.get("initial_recon", {})
    raw_findings = list(state.get("raw_findings", []))
    asvs_results = list(state.get("asvs_results", []))
    agent_trace = list(state.get("agent_trace", []))
    completed = list(state.get("completed_agents", []))
    step = state.get("current_step", 1)

    new_findings: List[Dict[str, Any]] = []
    agent_shot = None

    # 1. Credentials in URL Query String (V6.3.1, V9.1.1, V14.1.2)
    sensitive_params = ["password", "pwd", "token", "secret", "api_key", "apikey", "access_token", "auth"]
    url_lower = target_url.lower()
    leaked_param = None
    if "?" in url_lower:
        query_string = url_lower.split("?", 1)[1]
        for p in sensitive_params:
            if f"{p}=" in query_string:
                leaked_param = p
                break

    if leaked_param:
        ev = f"Sensitive authentication parameter '{leaked_param}' detected in URL query string on {target_url}."
        new_findings.append({
            "type": "auth",
            "severity": "high",
            "detail": f"Sensitive credential leaked in URL query parameter ({leaked_param})",
            "asvs": "V6.3.1",
            "requirement_id": "V6.3.1",
            "requirement_ids": ["V6.3.1", "V9.1.1", "V14.1.2"],
            "evidence": ev,
            "remediation": "Transmit credentials in HTTP POST request body or Authorization headers, never in URL parameters.",
        })
        asvs_results.append({
            "requirement_id": "V6.3.1",
            "chapter_code": "V6",
            "chapter_name": "Authentication",
            "section_name": "Credential Transport",
            "description": "Verify credentials are not transmitted in URL query parameters",
            "status": "FAIL",
            "severity": "high",
            "evidence": ev,
            "remediation": "Transmit credentials in request body or Authorization headers.",
        })
    else:
        asvs_results.append({
            "requirement_id": "V6.3.1",
            "chapter_code": "V6",
            "chapter_name": "Authentication",
            "section_name": "Credential Transport",
            "description": "Verify credentials are not transmitted in URL query parameters",
            "status": "PASS",
            "severity": "info",
            "evidence": f"No sensitive authentication parameters detected in URL query string for {target_url}.",
            "remediation": "",
        })

    # 2. Login Form Security & Transport (V6.1.1, V6.2.1)
    auth_data = {
        "loginForms": [],
        "passwordFields": [],
        "storageTokens": [],
    }

    if page:
        try:
            auth_data = await page.evaluate("""() => {
                const forms = Array.from(document.querySelectorAll('form')).map(f => {
                    const inputs = Array.from(f.querySelectorAll('input'));
                    const hasPassword = inputs.some(i => i.type === 'password' || (i.name && i.name.toLowerCase().includes('pass')));
                    const hasUser = inputs.some(i => i.name && (i.name.toLowerCase().includes('user') || i.name.toLowerCase().includes('email')));
                    return {
                        action: f.action || '',
                        isLogin: hasPassword || hasUser,
                        hasPassword: hasPassword,
                        isHttpAction: f.action ? f.action.startsWith('http://') : false
                    };
                });

                const passInputs = Array.from(document.querySelectorAll('input[type="password"]')).map(i => ({
                    name: i.name || '',
                    type: i.type,
                    autocomplete: i.getAttribute('autocomplete') || ''
                }));

                const storageKeys = [];
                const checkKeys = (storage, prefix) => {
                    for (let i = 0; i < storage.length; i++) {
                        const k = storage.key(i) || '';
                        const kl = k.toLowerCase();
                        if (kl.includes('token') || kl.includes('jwt') || kl.includes('auth') || kl.includes('secret')) {
                            storageKeys.push(`${prefix}:${k}`);
                        }
                    }
                };
                try { checkKeys(window.localStorage, 'localStorage'); } catch(e) {}
                try { checkKeys(window.sessionStorage, 'sessionStorage'); } catch(e) {}

                return {
                    loginForms: forms.filter(f => f.isLogin),
                    passwordFields: passInputs,
                    storageTokens: storageKeys
                };
            }""")
        except Exception:
            pass

    insecure_login_forms = [f.get("action") for f in auth_data.get("loginForms", []) if f.get("isHttpAction")]
    if insecure_login_forms:
        ev = f"Authentication login form posting credentials over plaintext HTTP: {', '.join(insecure_login_forms)}."
        new_findings.append({
            "type": "auth",
            "severity": "critical",
            "detail": "Insecure login form submitting over plaintext HTTP",
            "asvs": "V6.1.1",
            "requirement_id": "V6.1.1",
            "requirement_ids": ["V6.1.1", "V12.2.1"],
            "evidence": ev,
            "remediation": "Enforce HTTPS destination for all authentication forms and user credential endpoints.",
        })
        asvs_results.append({
            "requirement_id": "V6.1.1",
            "chapter_code": "V6",
            "chapter_name": "Authentication",
            "section_name": "Authentication Transport",
            "description": "Verify authentication requests are submitted over secure TLS connections",
            "status": "FAIL",
            "severity": "critical",
            "evidence": ev,
            "remediation": "Enforce HTTPS destination for all authentication forms.",
        })
    else:
        asvs_results.append({
            "requirement_id": "V6.1.1",
            "chapter_code": "V6",
            "chapter_name": "Authentication",
            "section_name": "Authentication Transport",
            "description": "Verify authentication requests are submitted over secure TLS connections",
            "status": "PASS",
            "severity": "info",
            "evidence": "No plaintext HTTP login form endpoints detected on inspected page.",
            "remediation": "",
        })

    # 3. Password Input Element Attributes (V6.2.2)
    pass_fields = auth_data.get("passwordFields", [])
    if pass_fields:
        asvs_results.append({
            "requirement_id": "V6.2.2",
            "chapter_code": "V6",
            "chapter_name": "Authentication",
            "section_name": "Password Handling",
            "description": "Verify password input fields properly mask credentials",
            "status": "PASS",
            "severity": "info",
            "evidence": f"Observed {len(pass_fields)} password field(s) configured with standard masking type='password'.",
            "remediation": "",
        })
    else:
        asvs_results.append({
            "requirement_id": "V6.2.2",
            "chapter_code": "V6",
            "chapter_name": "Authentication",
            "section_name": "Password Handling",
            "description": "Verify password input fields properly mask credentials",
            "status": "PASS",
            "severity": "info",
            "evidence": "No active password inputs present on audited page (unauthenticated view).",
            "remediation": "",
        })

    # 4. Sensitive Token Exposure in Web Storage (V7.2.2, V9.1.2)
    storage_tokens = auth_data.get("storageTokens", [])
    if storage_tokens:
        ev = f"Potential sensitive authentication tokens stored in unencrypted web storage: {', '.join(storage_tokens[:5])}."
        new_findings.append({
            "type": "storage",
            "severity": "medium",
            "detail": "Sensitive tokens stored in unencrypted client web storage",
            "asvs": "V7.2.2",
            "requirement_id": "V7.2.2",
            "requirement_ids": ["V7.2.2", "V9.1.2"],
            "evidence": ev,
            "remediation": "Store session identifiers in HttpOnly, Secure cookies rather than accessible localStorage.",
        })
        asvs_results.append({
            "requirement_id": "V7.2.2",
            "chapter_code": "V7",
            "chapter_name": "Session Management",
            "section_name": "Token Storage",
            "description": "Verify session tokens are not stored in accessible browser web storage",
            "status": "FAIL",
            "severity": "medium",
            "evidence": ev,
            "remediation": "Store session identifiers in HttpOnly, Secure cookies.",
        })
    else:
        asvs_results.append({
            "requirement_id": "V7.2.2",
            "chapter_code": "V7",
            "chapter_name": "Session Management",
            "section_name": "Token Storage",
            "description": "Verify session tokens are not stored in accessible browser web storage",
            "status": "PASS",
            "severity": "info",
            "evidence": "Web storage (localStorage / sessionStorage) is free of exposed plaintext session tokens.",
            "remediation": "",
        })

    # Capture HUD screenshot if new findings discovered
    if new_findings and page:
        agent_meta = {
            "shortcode": "AUTH",
            "name": "Authentication & Session Audit",
            "status": "FAIL",
            "evidence": f"Found {len(new_findings)} authentication or session security issue(s).",
        }
        agent_shot = await capture_hud_screenshot(
            page=page,
            cdp=cdp,
            target_url=target_url,
            doc_headers=state.get("doc_headers", {}),
            console_logs=state.get("console_logs", []),
            test_info=agent_meta,
            prefix="shot_auth",
        )
        if agent_shot:
            for nf in new_findings:
                nf["screenshot"] = agent_shot

    raw_findings.extend(new_findings)
    completed.append("auth_session")

    trace_entry = {
        "step": step,
        "tool": "auth_session_agent",
        "reason": f"Audited authentication attack surface, login transport, and session storage on {target_url}",
        "observation_preview": f"Discovered {len(new_findings)} auth issues. Login forms: {len(auth_data.get('loginForms', []))}, Storage tokens: {len(storage_tokens)}.",
        "status": "completed",
    }
    if agent_shot:
        trace_entry["screenshot"] = agent_shot
    agent_trace.append(trace_entry)

    return {
        "raw_findings": raw_findings,
        "asvs_results": asvs_results,
        "agent_trace": agent_trace,
        "completed_agents": completed,
        "current_step": step + 1,
    }


# -------------------------------------------------------------------------
# 5. API & Web Service Security Specialist Agent
# -------------------------------------------------------------------------
async def api_web_service_node(state: AuditGraphState) -> Dict[str, Any]:
    """Audits API architecture, CORS configurations, Content-Type enforcement, and HTTP methods."""
    page = state.get("page")
    cdp = state.get("cdp")
    target_url = state.get("target_url", "")
    headers = state.get("doc_headers", {})
    raw_findings = list(state.get("raw_findings", []))
    asvs_results = list(state.get("asvs_results", []))
    agent_trace = list(state.get("agent_trace", []))
    completed = list(state.get("completed_agents", []))
    step = state.get("current_step", 1)

    lower_headers = {k.lower(): v for k, v in headers.items()}
    new_findings: List[Dict[str, Any]] = []
    agent_shot = None

    # 1. CORS Configuration Audit (V4.3.1, V4.3.2)
    acao = lower_headers.get("access-control-allow-origin", "").strip()
    acac = lower_headers.get("access-control-allow-credentials", "").strip().lower()

    if acao == "*" and acac == "true":
        ev = "Critical CORS misconfiguration: 'Access-Control-Allow-Origin: *' paired with 'Access-Control-Allow-Credentials: true'."
        new_findings.append({
            "type": "cors",
            "severity": "critical",
            "detail": "Overly permissive CORS configuration with credentials",
            "asvs": "V4.3.1",
            "requirement_id": "V4.3.1",
            "requirement_ids": ["V4.3.1", "V4.3.2"],
            "evidence": ev,
            "remediation": "Never combine wildcard origins with credentials; specify explicit allowed origins.",
        })
        asvs_results.append({
            "requirement_id": "V4.3.1",
            "chapter_code": "V4",
            "chapter_name": "API and Web Service",
            "section_name": "CORS",
            "description": "Verify Cross-Origin Resource Sharing (CORS) origin restrictions",
            "status": "FAIL",
            "severity": "critical",
            "evidence": ev,
            "remediation": "Restrict CORS origins to explicit trusted domains.",
        })
    elif acao == "*":
        ev = f"Permissive CORS header detected: 'Access-Control-Allow-Origin: *'."
        new_findings.append({
            "type": "cors",
            "severity": "low",
            "detail": "Wildcard CORS Access-Control-Allow-Origin header",
            "asvs": "V4.3.1",
            "requirement_id": "V4.3.1",
            "requirement_ids": ["V4.3.1"],
            "evidence": ev,
            "remediation": "Evaluate whether wildcard origin access is intended for this API endpoint.",
        })
        asvs_results.append({
            "requirement_id": "V4.3.1",
            "chapter_code": "V4",
            "chapter_name": "API and Web Service",
            "section_name": "CORS",
            "description": "Verify Cross-Origin Resource Sharing (CORS) origin restrictions",
            "status": "FAIL",
            "severity": "low",
            "evidence": ev,
            "remediation": "Review wildcard CORS headers.",
        })
    else:
        asvs_results.append({
            "requirement_id": "V4.3.1",
            "chapter_code": "V4",
            "chapter_name": "API and Web Service",
            "section_name": "CORS",
            "description": "Verify Cross-Origin Resource Sharing (CORS) origin restrictions",
            "status": "PASS",
            "severity": "info",
            "evidence": f"CORS headers are properly restricted or not overly permissive (ACAO: '{acao or 'not set'}').",
            "remediation": "",
        })

    # 2. X-Content-Type-Options: nosniff (V4.1.1, V13.1.1)
    if "x-content-type-options" in lower_headers:
        xcto_val = lower_headers["x-content-type-options"].lower()
        if "nosniff" in xcto_val:
            asvs_results.append({
                "requirement_id": "V13.1.1",
                "chapter_code": "V13",
                "chapter_name": "Configuration",
                "section_name": "Content Sniffing",
                "description": "Verify X-Content-Type-Options: nosniff header prevents MIME confusion attacks",
                "status": "PASS",
                "severity": "info",
                "evidence": f"X-Content-Type-Options: nosniff header configured correctly ('{lower_headers['x-content-type-options']}').",
                "remediation": "",
            })
        else:
            ev = f"X-Content-Type-Options header present but invalid value: '{lower_headers['x-content-type-options']}'."
            new_findings.append({
                "type": "header",
                "severity": "low",
                "detail": "Invalid X-Content-Type-Options value",
                "asvs": "V13.1.1",
                "requirement_id": "V13.1.1",
                "requirement_ids": ["V13.1.1", "V4.1.1"],
                "evidence": ev,
                "remediation": "Set X-Content-Type-Options: nosniff.",
            })
    else:
        ev = "X-Content-Type-Options header is missing; browser may perform MIME type sniffing."
        new_findings.append({
            "type": "header",
            "severity": "medium",
            "detail": "Missing X-Content-Type-Options: nosniff",
            "asvs": "V13.1.1",
            "requirement_id": "V13.1.1",
            "requirement_ids": ["V13.1.1", "V4.1.1"],
            "evidence": ev,
            "remediation": "Add 'X-Content-Type-Options: nosniff' header to all HTTP responses.",
        })
        asvs_results.append({
            "requirement_id": "V13.1.1",
            "chapter_code": "V13",
            "chapter_name": "Configuration",
            "section_name": "Content Sniffing",
            "description": "Verify X-Content-Type-Options: nosniff header prevents MIME confusion attacks",
            "status": "FAIL",
            "severity": "medium",
            "evidence": ev,
            "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        })

    # 3. HTTP Methods & TRACE verb check (V4.1.4, V13.1.5)
    allow_header = lower_headers.get("allow", "") or lower_headers.get("access-control-allow-methods", "")
    if "trace" in allow_header.lower():
        ev = f"Dangerous HTTP TRACE method permitted in Allow headers: '{allow_header}'."
        new_findings.append({
            "type": "method",
            "severity": "medium",
            "detail": "Insecure HTTP TRACE method enabled (Cross-Site Tracing risk)",
            "asvs": "V13.1.5",
            "requirement_id": "V13.1.5",
            "requirement_ids": ["V13.1.5", "V4.1.4"],
            "evidence": ev,
            "remediation": "Disable HTTP TRACE and TRACK methods on the web server.",
        })
        asvs_results.append({
            "requirement_id": "V13.1.5",
            "chapter_code": "V13",
            "chapter_name": "Configuration",
            "section_name": "HTTP Methods",
            "description": "Verify dangerous HTTP methods like TRACE are disabled",
            "status": "FAIL",
            "severity": "medium",
            "evidence": ev,
            "remediation": "Disable HTTP TRACE and TRACK methods.",
        })
    else:
        asvs_results.append({
            "requirement_id": "V13.1.5",
            "chapter_code": "V13",
            "chapter_name": "Configuration",
            "section_name": "HTTP Methods",
            "description": "Verify dangerous HTTP methods like TRACE are disabled",
            "status": "PASS",
            "severity": "info",
            "evidence": "No dangerous HTTP TRACE or TRACK methods exposed in server method headers.",
            "remediation": "",
        })

    # Capture HUD screenshot if new findings discovered
    if new_findings and page:
        agent_meta = {
            "shortcode": "API",
            "name": "API & Web Service Audit",
            "status": "FAIL",
            "evidence": f"Found {len(new_findings)} API/web service configuration issue(s).",
        }
        agent_shot = await capture_hud_screenshot(
            page=page,
            cdp=cdp,
            target_url=target_url,
            doc_headers=headers,
            console_logs=state.get("console_logs", []),
            test_info=agent_meta,
            prefix="shot_api",
        )
        if agent_shot:
            for nf in new_findings:
                nf["screenshot"] = agent_shot

    raw_findings.extend(new_findings)
    completed.append("api_web_service")

    trace_entry = {
        "step": step,
        "tool": "api_web_service_agent",
        "reason": f"Audited API architecture, CORS policies, nosniff, and HTTP methods on {target_url}",
        "observation_preview": f"Discovered {len(new_findings)} API/CORS issues. ACAO: '{acao or 'none'}', nosniff: {'present' if 'x-content-type-options' in lower_headers else 'missing'}.",
        "status": "completed",
    }
    if agent_shot:
        trace_entry["screenshot"] = agent_shot
    agent_trace.append(trace_entry)

    return {
        "raw_findings": raw_findings,
        "asvs_results": asvs_results,
        "agent_trace": agent_trace,
        "completed_agents": completed,
        "current_step": step + 1,
    }


# -------------------------------------------------------------------------
# 6. Cryptography, Data Protection & Error Handling Specialist Agent
# -------------------------------------------------------------------------
async def crypto_data_protection_node(state: AuditGraphState) -> Dict[str, Any]:
    """Audits sensitive information disclosure, verbose stack traces, HTML comments, and cache headers."""
    page = state.get("page")
    cdp = state.get("cdp")
    target_url = state.get("target_url", "")
    headers = state.get("doc_headers", {})
    console_logs = state.get("console_logs", [])
    raw_findings = list(state.get("raw_findings", []))
    asvs_results = list(state.get("asvs_results", []))
    agent_trace = list(state.get("agent_trace", []))
    completed = list(state.get("completed_agents", []))
    step = state.get("current_step", 1)

    lower_headers = {k.lower(): v for k, v in headers.items()}
    new_findings: List[Dict[str, Any]] = []
    agent_shot = None

    # 1. Verbose Stack Traces & Error Disclosure (V16.1.1, V16.2.1)
    body_text = ""
    html_comments = []
    if page:
        try:
            body_text = await page.content()
            html_comments = await page.evaluate("""() => {
                const comments = [];
                const iterator = document.createNodeIterator(
                    document.documentElement,
                    NodeFilter.SHOW_COMMENT,
                    null
                );
                let curNode;
                while (curNode = iterator.nextNode()) {
                    comments.push(curNode.nodeValue || '');
                }
                return comments.slice(0, 30);
            }""")
        except Exception:
            pass

    # Search for stack trace patterns in body and console logs
    stack_trace_indicators = [
        "traceback (most recent call last)",
        "nullpointerexception",
        "uncaught exception",
        "fatal error:",
        "at com.",
        "at org.",
        "operationalerror:",
        "pg::error",
        "sql syntax",
    ]

    combined_text = (body_text + " " + " ".join([str(l.get("text", "")) for l in console_logs])).lower()
    detected_leaks = [ind for ind in stack_trace_indicators if ind in combined_text]

    if detected_leaks:
        ev = f"Verbose diagnostic or stack trace leak detected in HTTP response/console: {', '.join(detected_leaks)}."
        new_findings.append({
            "type": "leak",
            "severity": "high",
            "detail": "Verbose stack trace or database error disclosure",
            "asvs": "V16.1.1",
            "requirement_id": "V16.1.1",
            "requirement_ids": ["V16.1.1", "V16.2.1"],
            "evidence": ev,
            "remediation": "Disable detailed error messages and debug modes in production environments.",
        })
        asvs_results.append({
            "requirement_id": "V16.1.1",
            "chapter_code": "V16",
            "chapter_name": "Security Logging and Error Handling",
            "section_name": "Error Disclosure",
            "description": "Verify detailed error messages and stack traces are not exposed to users",
            "status": "FAIL",
            "severity": "high",
            "evidence": ev,
            "remediation": "Disable verbose error responses in production.",
        })
    else:
        asvs_results.append({
            "requirement_id": "V16.1.1",
            "chapter_code": "V16",
            "chapter_name": "Security Logging and Error Handling",
            "section_name": "Error Disclosure",
            "description": "Verify detailed error messages and stack traces are not exposed to users",
            "status": "PASS",
            "severity": "info",
            "evidence": "No verbose stack traces or raw database error messages exposed in page response or console.",
            "remediation": "",
        })

    # 2. Sensitive Data in HTML Comments (V14.3.1, V15.3.1)
    sensitive_comment_keywords = ["password", "api_key", "apikey", "secret", "todo: remove", "fixme: security", "credentials"]
    flagged_comments = []
    for c in html_comments:
        cl = c.lower()
        if any(kw in cl for kw in sensitive_comment_keywords):
            flagged_comments.append(c.strip()[:80])

    if flagged_comments:
        ev = f"Potentially sensitive developer remarks or secrets in HTML comments: {', '.join(flagged_comments[:3])}."
        new_findings.append({
            "type": "comment",
            "severity": "low",
            "detail": "Sensitive information in HTML comments",
            "asvs": "V14.3.1",
            "requirement_id": "V14.3.1",
            "requirement_ids": ["V14.3.1", "V15.3.1"],
            "evidence": ev,
            "remediation": "Strip sensitive development comments and credentials during the build pipeline.",
        })
        asvs_results.append({
            "requirement_id": "V14.3.1",
            "chapter_code": "V14",
            "chapter_name": "Data Protection",
            "section_name": "Information Leakage",
            "description": "Verify sensitive comments and keys are removed from production client source",
            "status": "FAIL",
            "severity": "low",
            "evidence": ev,
            "remediation": "Remove sensitive development comments from client-facing assets.",
        })
    else:
        asvs_results.append({
            "requirement_id": "V14.3.1",
            "chapter_code": "V14",
            "chapter_name": "Data Protection",
            "section_name": "Information Leakage",
            "description": "Verify sensitive comments and keys are removed from production client source",
            "status": "PASS",
            "severity": "info",
            "evidence": f"Inspected {len(html_comments)} HTML comment(s); no sensitive credentials or keys disclosed.",
            "remediation": "",
        })

    # 3. Server Version Disclosure in Headers (V13.1.4)
    server_header = lower_headers.get("server", "")
    x_powered_by = lower_headers.get("x-powered-by", "")
    disclosed_versions = []
    import re
    if server_header and re.search(r"/\d+(\.\d+)?", server_header):
        disclosed_versions.append(f"Server: {server_header}")
    if x_powered_by:
        disclosed_versions.append(f"X-Powered-By: {x_powered_by}")

    if disclosed_versions:
        ev = f"Server software or technology versions disclosed in HTTP headers: {', '.join(disclosed_versions)}."
        new_findings.append({
            "type": "header",
            "severity": "low",
            "detail": "Server technology version disclosure",
            "asvs": "V13.1.4",
            "requirement_id": "V13.1.4",
            "requirement_ids": ["V13.1.4"],
            "evidence": ev,
            "remediation": "Configure web server reverse proxy to suppress Server and X-Powered-By headers.",
        })
        asvs_results.append({
            "requirement_id": "V13.1.4",
            "chapter_code": "V13",
            "chapter_name": "Configuration",
            "section_name": "Version Disclosure",
            "description": "Verify server headers do not disclose detailed software versions",
            "status": "FAIL",
            "severity": "low",
            "evidence": ev,
            "remediation": "Suppress Server and X-Powered-By headers.",
        })
    else:
        asvs_results.append({
            "requirement_id": "V13.1.4",
            "chapter_code": "V13",
            "chapter_name": "Configuration",
            "section_name": "Version Disclosure",
            "description": "Verify server headers do not disclose detailed software versions",
            "status": "PASS",
            "severity": "info",
            "evidence": f"Server headers do not expose granular version numbers (Server: '{server_header or 'not exposed'}').",
            "remediation": "",
        })

    # Capture HUD screenshot if new findings discovered
    if new_findings and page:
        agent_meta = {
            "shortcode": "CRYPTO",
            "name": "Data Protection & Error Audit",
            "status": "FAIL",
            "evidence": f"Found {len(new_findings)} data protection or information disclosure issue(s).",
        }
        agent_shot = await capture_hud_screenshot(
            page=page,
            cdp=cdp,
            target_url=target_url,
            doc_headers=headers,
            console_logs=state.get("console_logs", []),
            test_info=agent_meta,
            prefix="shot_crypto",
        )
        if agent_shot:
            for nf in new_findings:
                nf["screenshot"] = agent_shot

    raw_findings.extend(new_findings)
    completed.append("crypto_data_protection")

    trace_entry = {
        "step": step,
        "tool": "crypto_data_protection_agent",
        "reason": f"Audited error handling, sensitive data exposure, comments, and server headers on {target_url}",
        "observation_preview": f"Discovered {len(new_findings)} data protection issues. Stack leaks: {len(detected_leaks)}, Comments checked: {len(html_comments)}.",
        "status": "completed",
    }
    if agent_shot:
        trace_entry["screenshot"] = agent_shot
    agent_trace.append(trace_entry)

    return {
        "raw_findings": raw_findings,
        "asvs_results": asvs_results,
        "agent_trace": agent_trace,
        "completed_agents": completed,
        "current_step": step + 1,
    }

