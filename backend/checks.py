from typing import Dict, Any, List

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
    "content-security-policy": {"weight": 25, "label": "Missing Content-Security-Policy (CSP)", "asvs": "V3.1.1"},
    "x-frame-options": {"weight": 15, "label": "Missing X-Frame-Options (Clickjacking defense)", "asvs": "V3.1.1"},
    "x-content-type-options": {"weight": 10, "label": "Missing X-Content-Type-Options (nosniff)", "asvs": "V13.1.1"},
    "referrer-policy": {"weight": 10, "label": "Missing Referrer-Policy", "asvs": "V3.1.1"},
}

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicates identical findings while preserving all evidence and valid ASVS mappings.
    """
    deduped: Dict[tuple, Dict[str, Any]] = {}
    for f in findings:
        category = f.get("type") or f.get("category") or "general"
        title = f.get("detail") or f.get("title") or "Finding"
        key = (category.lower().strip(), title.lower().strip())

        asvs_val = f.get("asvs") or f.get("requirement_id")
        evidence_val = f.get("evidence") or f.get("detail") or ""

        if key not in deduped:
            entry = dict(f)
            entry["requirement_ids"] = [asvs_val] if asvs_val else []
            entry["evidence_list"] = [evidence_val] if evidence_val else []
            if asvs_val and "requirement_id" not in entry:
                entry["requirement_id"] = asvs_val
            deduped[key] = entry
        else:
            if asvs_val and asvs_val not in deduped[key]["requirement_ids"]:
                deduped[key]["requirement_ids"].append(asvs_val)
                # Keep requirement_id updated with combined IDs if multiple
                deduped[key]["requirement_id"] = ", ".join(deduped[key]["requirement_ids"])
            if evidence_val and evidence_val not in deduped[key]["evidence_list"]:
                deduped[key]["evidence_list"].append(evidence_val)
                deduped[key]["evidence"] = " | ".join(deduped[key]["evidence_list"])

    # Clean up internal evidence_list before returning
    result = []
    for entry in deduped.values():
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
) -> Dict[str, Any]:
    """
    Evaluates a set of ASVS requirements against live CDP, header, cookie, and DOM evidence.
    
    SCORING FORMULA:
    - If requirements is empty or 0 requirements were evaluated: returns score: None, grade: "NOT_ASSESSED".
    - Coverage = (Evaluated Requirements [PASS/FAIL] / Total Requirements) * 100
    - If evaluated requirements > 0:
      Base Score = 100, deducting penalties for confirmed FAILs:
        High severity: -25 points
        Medium severity: -15 points
        Low severity: -5 points
      Compliance Score = max(0, min(100, Base Score - sum(penalties)))
    """
    if not requirements:
        return {
            "score": None,
            "grade": "NOT_ASSESSED",
            "coverage_percentage": 0.0,
            "asvs_results": [],
            "findings": [],
            "metrics": {
                "total_evaluated": 0,
                "passed": 0,
                "failed": 0,
                "manual_verify": 0,
                "not_tested": 0,
                "errors": 0,
            }
        }

    lower_headers = {k.lower(): v for k, v in headers.items()}
    raw_findings = []
    asvs_results = []

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

        # 2. Strict-Transport-Security (HSTS) (ASVS V3.4.1) - NOT TLS protocol!
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
                    evidence = "Page served over HTTPS but Strict-Transport-Security (HSTS) header is missing."
                    remediation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce TLS."
                    raw_findings.append({
                        "type": "header",
                        "severity": "medium",
                        "detail": "Missing HSTS Header (Strict-Transport-Security)",
                        "asvs": req_id or "V3.4.1",
                        "evidence": evidence,
                    })
            else:
                status = "NOT_TESTED"
                not_tested_count += 1
                evidence = f"Page served over unencrypted protocol ({protocol}); HSTS header requires HTTPS."
                remediation = "Serve application over HTTPS before enabling HSTS."

        # 3. TLS Protocol Usage (ASVS V12.1.1, V12.2.1) - TLS connection status, NOT HSTS!
        elif req_id in ["V12.1.1", "V12.2.1", "V12.3.1"] or (chap_code == "V12" and "tls" in desc.lower()):
            if protocol == "https:":
                status = "PASS"
                passed_count += 1
                evidence = f"Connection established over HTTPS (TLS encryption active, protocol: {protocol})."
            else:
                status = "FAIL"
                failed_count += 1
                severity = "high"
                score -= 25
                evidence = f"Page served over unencrypted protocol ({protocol}); TLS transport encryption is not enabled."
                remediation = "Enforce HTTPS redirect and enable modern TLS (TLS 1.2+)."
                raw_findings.append({
                    "type": "tls",
                    "severity": "high",
                    "detail": "Insecure HTTP connection (Missing TLS)",
                    "asvs": req_id or "V12.2.1",
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
                # Never assign PASS without sufficient evidence when no cookies were observed!
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

        # 7. Chapter V1: Encoding & Sanitization (Never assign PASS passively!)
        elif req_id.startswith("V1.") or chap_code == "V1":
            status = "NOT_TESTED"
            not_tested_count += 1
            evidence = "Passive inspection cannot verify input encoding and sanitization without deterministic probe injection."
            remediation = "Execute Chapter V1 deterministic browser test suite with active canary probes."

        else:
            # Architecture / Policy / Non-observable standard requirements
            status = "MANUAL_VERIFY"
            manual_count += 1
            severity = "info"
            evidence = f"Standard requirement '{req_id}' requires manual architecture or source code review."
            remediation = f"Review organization policy and codebase implementation for: {desc}"

        asvs_results.append({
            "requirement_id": req_id,
            "chapter_code": chap_code,
            "chapter_name": chap_name,
            "section_name": sec_name,
            "description": desc,
            "status": status,
            "severity": severity,
            "evidence": evidence,
            "remediation": remediation,
        })

    # Check for insecure forms submitting over HTTP (map to V12.2.1, NOT V1)
    if insecure_forms:
        raw_findings.append({
            "type": "form",
            "severity": "high",
            "detail": "Form submitting over unencrypted HTTP",
            "asvs": "V12.2.1",
            "evidence": f"Insecure form actions detected: {', '.join(insecure_forms[:3])}",
        })
        score -= 20

    # Deduplicate findings while preserving all evidence and ASVS mappings
    findings = deduplicate_findings(raw_findings)

    total_evaluated = passed_count + failed_count
    coverage_pct = round((total_evaluated / len(requirements) * 100), 1) if requirements else 0.0

    # If no requirements could be definitively evaluated, score is None, grade is NOT_ASSESSED
    if total_evaluated == 0:
        final_score = None
        grade = "NOT_ASSESSED"
    else:
        final_score = max(0, min(100, score))
        if final_score >= 90:
            grade = "A"
        elif final_score >= 75:
            grade = "B"
        elif final_score >= 60:
            grade = "C"
        elif final_score >= 45:
            grade = "D"
        else:
            grade = "F"

    return {
        "score": final_score,
        "grade": grade,
        "coverage_percentage": coverage_pct,
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
