from typing import Dict, Any, List, Optional
from app.core.screenshots import save_screenshot
from app.services.scoring import SEVERITY_ORDER, calculate_grade, calculate_score_and_grade

DOM_AUDIT_JS = """
() => {
    // 1. External scripts missing Subresource Integrity (SRI)
    const missingSri = Array.from(document.querySelectorAll('script[src], link[rel="stylesheet"][href]'))
        .filter(el => {
            const url = el.src || el.href;
            return url && !url.startsWith(window.location.origin) && !el.integrity;
        })
        .map(el => el.src || el.href);

    // 2. Forms submitting over HTTP or password inputs missing autocomplete="off"
    const insecureForms = Array.from(document.querySelectorAll('form'))
        .filter(f => f.action && f.action.startsWith('http://'))
        .map(f => f.action);

    // 3. Detect exposed client-side library versions on window
    const detectedLibs = {
        jquery: window.jQuery ? window.jQuery.fn.jquery : null,
        angular: window.angular && window.angular.version ? window.angular.version.full : null,
        lodash: window._ && window._.VERSION ? window._.VERSION : null,
        react: window.React ? window.React.version : null,
        vue: window.Vue ? window.Vue.version : null,
    };

    // 4. External target="_blank" links missing rel="noopener"
    const unsafeLinks = Array.from(document.querySelectorAll('a[target="_blank"]'))
        .filter(a => !a.rel.includes('noopener') && !a.rel.includes('noreferrer'))
        .map(a => a.href)
        .slice(0, 10);

    return { missingSri, insecureForms, detectedLibs, unsafeLinks };
}
"""

REQUIRED_HEADERS = {
    "strict-transport-security": {"weight": 20, "label": "Missing HSTS Header", "asvs": "V3.4.1"},
    "content-security-policy": {"weight": 25, "label": "Missing Content-Security-Policy (CSP)", "asvs": "V3.4.2"},
    "x-frame-options": {"weight": 15, "label": "Missing X-Frame-Options (Clickjacking defense)", "asvs": "V3.4.3"},
    "x-content-type-options": {"weight": 10, "label": "Missing X-Content-Type-Options (nosniff)", "asvs": "V4.1.1"},
    "referrer-policy": {"weight": 10, "label": "Missing Referrer-Policy", "asvs": "V3.4.5"},
}

def _canonical_finding_key(f: Dict[str, Any]) -> tuple:
    f_type = (f.get("type") or f.get("category") or "").strip().lower()
    detail = (f.get("detail") or f.get("title") or "").strip().lower()
    asvs = str(f.get("asvs") or f.get("requirement_id") or "").strip().upper()
    combined = f"{f_type} {detail} {asvs}".lower()

    if "strict-transport-security" in combined or "hsts" in combined or asvs == "V3.4.1":
        return ("header", "hsts")
    if "content-security-policy" in combined or "csp" in combined or asvs == "V3.4.2":
        return ("header", "csp")
    if "x-frame-options" in combined or "xfo" in combined or "clickjacking" in combined or asvs == "V3.4.3":
        return ("header", "xfo")
    if "x-content-type-options" in combined or "nosniff" in combined or asvs == "V4.1.1":
        return ("header", "xcto")
    if "referrer-policy" in combined or asvs == "V3.4.5":
        return ("header", "referrer")
    if f_type == "form" or "insecure form" in combined:
        return ("form", "insecure_transport")
    return (f_type, detail)

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicates identical findings while preserving all evidence, severity, and ASVS mappings."""
    deduped: Dict[tuple, Dict[str, Any]] = {}

    for f in findings:
        key = _canonical_finding_key(f)

        ids_to_add: List[str] = []
        if isinstance(f.get("requirement_ids"), list):
            ids_to_add.extend([str(x).strip() for x in f["requirement_ids"] if x])
        if f.get("asvs"):
            ids_to_add.append(str(f["asvs"]).strip())
        if f.get("requirement_id"):
            for part in str(f["requirement_id"]).split(","):
                part_clean = part.strip()
                if part_clean and part_clean not in ids_to_add:
                    ids_to_add.append(part_clean)

        raw_ev = f.get("evidence") or f.get("detail") or ""
        evidence_parts = [e.strip() for e in str(raw_ev).split(" | ") if e.strip()]

        if key not in deduped:
            entry = dict(f)
            seen_ids = set()
            unique_ids = []
            for rid in ids_to_add:
                if rid and rid not in seen_ids:
                    seen_ids.add(rid)
                    unique_ids.append(rid)
            entry["requirement_ids"] = unique_ids
            entry["asvs"] = unique_ids[0] if unique_ids else entry.get("asvs", "")
            entry["requirement_id"] = ", ".join(unique_ids) if unique_ids else entry.get("requirement_id", "")
            entry["evidence_parts"] = evidence_parts
            entry["evidence"] = " | ".join(evidence_parts) if evidence_parts else ""
            deduped[key] = entry
        else:
            entry = deduped[key]
            for rid in ids_to_add:
                if rid and rid not in entry["requirement_ids"]:
                    entry["requirement_ids"].append(rid)
            entry["requirement_id"] = ", ".join(entry["requirement_ids"])
            if not entry.get("asvs") and entry["requirement_ids"]:
                entry["asvs"] = entry["requirement_ids"][0]

            for ep in evidence_parts:
                if ep and ep not in entry["evidence_parts"]:
                    entry["evidence_parts"].append(ep)
            entry["evidence"] = " | ".join(entry["evidence_parts"])

            cur_sev = str(entry.get("severity", "info")).lower()
            new_sev = str(f.get("severity", "info")).lower()
            if SEVERITY_ORDER.get(new_sev, 0) > SEVERITY_ORDER.get(cur_sev, 0):
                entry["severity"] = f.get("severity", new_sev)

            if not entry.get("screenshot") and f.get("screenshot"):
                entry["screenshot"] = f.get("screenshot")

            if not entry.get("tests") and f.get("tests"):
                entry["tests"] = f.get("tests")
            if not entry.get("script_id") and f.get("script_id"):
                entry["script_id"] = f.get("script_id")

    result = []
    for entry in deduped.values():
        entry.pop("evidence_parts", None)
        entry.pop("evidence_list", None)
        result.append(entry)
    return result

def evaluate_asvs_requirements(
    requirements: List[Dict[str, Any]],
    headers: dict,
    cookies: list,
    dom_data: dict,
    cdp_issues: list,
    protocol: str = "https:",
    screenshot: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluates ASVS requirements against live CDP, header, cookie, and DOM evidence."""
    if screenshot and screenshot.startswith("data:"):
        screenshot = save_screenshot(screenshot, prefix="check_shot")

    if not requirements:
        return {
            "score": None,
            "grade": "NOT_ASSESSED",
            "scan_status": "not_assessed",
            "coverage_percentage": 0.0,
            "pass_rate_percentage": None,
            "screenshot": screenshot,
            "asvs_results": [],
            "findings": [],
            "metrics": {
                "total_requirements": 0,
                "total_evaluated": 0,
                "passed": 0,
                "failed": 0,
                "manual_verify": 0,
                "not_tested": 0,
                "errors": 0,
            }
        }

    lower_headers = {k.lower(): v for k, v in headers.items()}
    raw_findings: List[Dict[str, Any]] = []
    asvs_results: List[Dict[str, Any]] = []

    has_hsts = "strict-transport-security" in lower_headers
    has_csp = "content-security-policy" in lower_headers
    has_xfo = "x-frame-options" in lower_headers
    has_xcto = "x-content-type-options" in lower_headers
    content_type_header = lower_headers.get("content-type", "")

    insecure_cookies = [
        c.get("name", "unnamed")
        for c in cookies
        if not c.get("secure") or not c.get("httpOnly")
    ]
    missing_sri = dom_data.get("missingSri", [])
    insecure_forms = dom_data.get("insecureForms", [])
    unsafe_links = dom_data.get("unsafeLinks", [])

    score = 100
    passed_count = 0
    failed_count = 0
    manual_count = 0
    not_tested_count = 0

    for req in requirements:
        req_id = req.get("requirement_id", "")
        chap_code = req.get("chapter_code", "")
        chap_name = req.get("chapter_name", "")
        sec_name = req.get("section_name", "")
        desc = req.get("description", "")

        status = "NOT_TESTED"
        severity = "info"
        evidence = ""
        remediation = ""

        # 1. Content-Type Header (V4.1.1)
        if req_id == "V4.1.1" or ("content-type" in desc.lower() and chap_code in ["V4", "V13"]):
            if content_type_header:
                status = "PASS"
                passed_count += 1
                evidence = f"Content-Type header present: '{content_type_header}'."
            else:
                status = "FAIL"
                failed_count += 1
                severity = "medium"
                score -= 15
                evidence = "Response body missing explicit Content-Type header."
                remediation = "Ensure server specifies Content-Type with character set (e.g. text/html; charset=utf-8)."
                raw_findings.append({
                    "type": "header",
                    "severity": "medium",
                    "detail": "Missing Content-Type header",
                    "asvs": req_id or "V4.1.1",
                    "evidence": evidence,
                })

        # 2. Strict-Transport-Security (HSTS) (ASVS V3.4.1)
        elif req_id in ["V3.4.1", "V3.7.4"] or ("strict-transport-security" in desc.lower() or "hsts" in desc.lower()):
            if protocol == "https:":
                if has_hsts:
                    status = "PASS"
                    passed_count += 1
                    evidence = f"Strict-Transport-Security header present: '{lower_headers.get('strict-transport-security')}'."
                else:
                    status = "FAIL"
                    failed_count += 1
                    severity = "medium"
                    score -= 15
                    evidence = f"Strict-Transport-Security (HSTS) header is missing from HTTP response. Observed header keys: {sorted(list(lower_headers.keys()))}"
                    remediation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce TLS."
                    raw_findings.append({
                        "type": "header",
                        "severity": "medium",
                        "detail": "Missing HSTS Header (Strict-Transport-Security)",
                        "asvs": req_id or "V3.4.1",
                        "requirement_id": req_id or "V3.4.1",
                        "requirement_ids": [req_id or "V3.4.1"],
                        "evidence": evidence,
                    })
            else:
                status = "NOT_TESTED"
                not_tested_count += 1
                evidence = f"Page served over unencrypted protocol ({protocol}); HSTS header requires HTTPS."
                remediation = "Serve application over HTTPS before enabling HSTS."

        # 3. TLS Protocol Usage (ASVS V12.1.1, V12.2.1)
        elif req_id in ["V12.1.1", "V12.2.1", "V12.3.1"] or (chap_code == "V12" and "tls" in desc.lower()):
            if protocol == "https:":
                status = "PASS"
                passed_count += 1
                evidence = f"TLS encryption active on primary HTTPS connection (protocol='{protocol}')."
            else:
                status = "FAIL"
                failed_count += 1
                severity = "high"
                score -= 25
                evidence = f"Insecure HTTP connection ({protocol}); TLS transport encryption is not enabled."
                remediation = "Enforce HTTPS redirect and enable modern TLS (TLS 1.2+)."
                raw_findings.append({
                    "type": "tls",
                    "severity": "high",
                    "detail": "Insecure HTTP connection (Missing TLS)",
                    "asvs": req_id or "V12.1.1",
                    "requirement_id": req_id or "V12.1.1",
                    "requirement_ids": [req_id or "V12.1.1"],
                    "evidence": evidence,
                })

        # 4. Web Frontend Security Headers (ASVS V3.1.1)
        elif req_id == "V3.1.1" or chap_code == "V3":
            issues = []
            if not has_csp:
                issues.append("Missing Content-Security-Policy header")
            if not has_xfo:
                issues.append("Missing X-Frame-Options (Clickjacking defense)")
            if missing_sri:
                issues.append(f"{len(missing_sri)} external scripts/stylesheets missing Subresource Integrity")
            if unsafe_links:
                issues.append(f"{len(unsafe_links)} target='_blank' links missing rel='noopener'")

            if issues:
                status = "FAIL"
                failed_count += 1
                severity = "medium"
                score -= 15
                evidence = "; ".join(issues)
                remediation = "Implement Content-Security-Policy, X-Frame-Options: DENY, and integrity hashes on CDN assets."
                raw_findings.append({
                    "type": "frontend",
                    "severity": "medium",
                    "detail": f"Frontend security configuration gaps: {evidence}",
                    "asvs": req_id or "V3.1.1",
                    "evidence": evidence,
                })
            else:
                status = "PASS"
                passed_count += 1
                evidence = "Frontend security headers (CSP, X-Frame-Options) and asset integrity checks passed."

        # 5. Session Management & Cookies (ASVS V7.1.1)
        elif req_id == "V7.1.1" or chap_code == "V7":
            if insecure_cookies:
                status = "FAIL"
                failed_count += 1
                severity = "medium"
                score -= 15
                evidence = f"Cookies missing Secure or HttpOnly flags: {', '.join(insecure_cookies[:5])}."
                remediation = "Ensure all session cookies set HttpOnly, Secure, and SameSite=Lax/Strict flags."
                raw_findings.append({
                    "type": "cookie",
                    "severity": "medium",
                    "detail": "Insecure cookie flags",
                    "asvs": req_id or "V7.1.1",
                    "evidence": evidence,
                })
            elif cookies:
                status = "PASS"
                passed_count += 1
                evidence = f"All observed cookies ({len(cookies)}) have Secure and HttpOnly flags configured."
            else:
                status = "NOT_TESTED"
                not_tested_count += 1
                evidence = "No cookies were observed in the HTTP response; cannot evaluate session cookie attributes without an active session."
                remediation = "Authenticate or perform user actions that set session cookies to evaluate cookie security."

        # 6. Base Security Headers (ASVS V13.1.1)
        elif req_id == "V13.1.1" or chap_code == "V13":
            missing = []
            if not has_xcto:
                missing.append("X-Content-Type-Options: nosniff")
            if "referrer-policy" not in lower_headers:
                missing.append("Referrer-Policy")
            if missing:
                status = "FAIL"
                failed_count += 1
                severity = "low"
                score -= 10
                evidence = f"Missing configuration headers: {', '.join(missing)}."
                remediation = "Add X-Content-Type-Options: nosniff and Referrer-Policy headers to responses."
                raw_findings.append({
                    "type": "header",
                    "severity": "low",
                    "detail": f"Missing security headers: {', '.join(missing)}",
                    "asvs": req_id or "V13.1.1",
                    "evidence": evidence,
                })
            else:
                status = "PASS"
                passed_count += 1
                evidence = "Base configuration headers (X-Content-Type-Options, Referrer-Policy) are configured."

        # 7. Chapter V1: Encoding & Sanitization
        elif req_id.startswith("V1.") or chap_code == "V1":
            status = "NOT_TESTED"
            not_tested_count += 1
            evidence = "Passive inspection cannot verify input encoding and sanitization without deterministic probe injection."
            remediation = "Execute Chapter V1 deterministic browser test suite with active canary probes."

        else:
            status = "MANUAL_VERIFY"
            manual_count += 1
            severity = "info"
            evidence = f"Standard requirement '{req_id}' requires manual architecture or source code review."
            remediation = f"Review organization policy and codebase implementation for: {desc}"

        asvs_item = {
            "requirement_id": req_id,
            "chapter_code": chap_code,
            "chapter_name": chap_name,
            "section_name": sec_name,
            "description": desc,
            "status": status,
            "severity": severity,
            "evidence": evidence,
            "remediation": remediation,
        }
        if screenshot:
            asvs_item["screenshot"] = screenshot
        asvs_results.append(asvs_item)

        # Check for insecure forms submitting over HTTP (maps to V12.2.1, NOT V1)
    if insecure_forms:
        raw_findings.append({
            "type": "form",
            "severity": "high",
            "detail": "Form submitting over unencrypted HTTP",
            "asvs": "V12.2.1",
            "requirement_id": "V12.2.1",
            "requirement_ids": ["V12.2.1"],
            "evidence": f"Insecure form actions detected: {', '.join(insecure_forms[:3])}",
        })
        score -= 20

    if screenshot:
        for rf in raw_findings:
            if not rf.get("screenshot"):
                rf["screenshot"] = screenshot

    findings = deduplicate_findings(raw_findings)

    total_evaluated = passed_count + failed_count
    coverage_pct = round((total_evaluated / len(requirements) * 100), 1) if requirements else 0.0
    pass_rate_pct = round((passed_count / total_evaluated * 100), 1) if total_evaluated > 0 else None

    if total_evaluated == 0:
        final_score = None
        grade = "NOT_ASSESSED"
        scan_status = "not_assessed"
    else:
        scan_status = "completed"
        final_score, grade = calculate_score_and_grade(asvs_results)

    return {
        "score": final_score,
        "grade": grade,
        "scan_status": scan_status,
        "coverage_percentage": coverage_pct,
        "pass_rate_percentage": pass_rate_pct,
        "screenshot": screenshot,
        "asvs_results": asvs_results,
        "findings": findings,
        "metrics": {
            "total_requirements": len(requirements),
            "total_evaluated": total_evaluated,
            "passed": passed_count,
            "failed": failed_count,
            "manual_verify": manual_count,
            "not_tested": not_tested_count,
            "errors": 0,
        }
    }
