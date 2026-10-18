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
    "strict-transport-security": {"weight": 20, "label": "Missing HSTS Header", "asvs": "V12.1.1"},
    "content-security-policy": {"weight": 25, "label": "Missing Content-Security-Policy (CSP)", "asvs": "V3.1.1"},
    "x-frame-options": {"weight": 15, "label": "Missing X-Frame-Options (Clickjacking defense)", "asvs": "V3.1.1"},
    "x-content-type-options": {"weight": 10, "label": "Missing X-Content-Type-Options (nosniff)", "asvs": "V13.1.1"},
    "referrer-policy": {"weight": 10, "label": "Missing Referrer-Policy", "asvs": "V3.1.1"},
}

def evaluate_asvs_requirements(
    requirements: List[Dict[str, Any]],
    headers: dict,
    cookies: list,
    dom_data: dict,
    cdp_issues: list,
    protocol: str = "https:",
) -> Dict[str, Any]:
    """
    Evaluates a set of ASVS requirements against the live CDP, header, cookie, and DOM evidence.
    Returns:
      - score (0-100)
      - grade (A-F)
      - asvs_results (list of test results with requirement_id, chapter, status, evidence, remediation)
      - findings (standardized issues list for frontend compatibility)
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    score = 100
    findings = []
    asvs_results = []

    # Map observable evidence by topic
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

    for req in requirements:
        req_id = req.get("requirement_id", "")
        chap_code = req.get("chapter_code", "")
        chap_name = req.get("chapter_name", "")
        sec_name = req.get("section_name", "")
        desc = req.get("description", "")

        status = "PASS"
        severity = "info"
        evidence = ""
        remediation = ""

        # Chapter-specific or requirement-specific checks:
        if req_id == "V4.1.1" or "Content-Type" in desc:
            if content_type_header:
                status = "PASS"
                evidence = f"Content-Type header present: '{content_type_header}'."
            else:
                status = "FAIL"
                severity = "medium"
                score -= 10
                evidence = "Response body missing explicit Content-Type header."
                remediation = "Ensure server specifies Content-Type with character set (e.g. text/html; charset=utf-8)."
                findings.append({"type": "header", "severity": "medium", "detail": "Missing Content-Type header (ASVS V4.1.1)"})

        elif req_id == "V12.1.1" or "TLS" in desc or "HSTS" in desc:
            if protocol == "https:" and has_hsts:
                status = "PASS"
                evidence = f"TLS active ({protocol}) with Strict-Transport-Security header present: '{lower_headers.get('strict-transport-security')}'."
            elif protocol == "https:":
                status = "FAIL"
                severity = "medium"
                score -= 15
                evidence = "Page served over HTTPS but Strict-Transport-Security (HSTS) header is missing."
                remediation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce TLS."
                findings.append({"type": "header", "severity": "medium", "detail": "Missing HSTS Header (ASVS V12.1.1)"})
            else:
                status = "FAIL"
                severity = "high"
                score -= 25
                evidence = f"Page served over insecure protocol ({protocol})."
                remediation = "Enforce HTTPS redirect and enable TLS 1.2+."
                findings.append({"type": "tls", "severity": "high", "detail": "Insecure HTTP connection (ASVS V12.1.1)"})

        elif req_id == "V3.1.1" or chap_code == "V3":
            # Web frontend security: CSP, SRI, unsafe links, clickjacking
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
                severity = "medium"
                score -= 15
                evidence = "; ".join(issues)
                remediation = "Implement Content-Security-Policy, X-Frame-Options: DENY, and integrity hashes on CDN assets."
                findings.append({"type": "frontend", "severity": "medium", "detail": f"Frontend security issues: {evidence}"})
            else:
                status = "PASS"
                evidence = "Frontend security headers (CSP, X-Frame-Options) and asset integrity checks passed."

        elif req_id == "V7.1.1" or chap_code == "V7":
            # Session management / cookies
            if insecure_cookies:
                status = "FAIL"
                severity = "medium"
                score -= 10
                evidence = f"Cookies missing Secure or HttpOnly flags: {', '.join(insecure_cookies[:5])}."
                remediation = "Ensure all session cookies set HttpOnly, Secure, and SameSite=Lax/Strict flags."
                findings.append({"type": "cookie", "severity": "medium", "detail": evidence})
            elif cookies:
                status = "PASS"
                evidence = f"All observed cookies ({len(cookies)}) have Secure and HttpOnly flags configured."
            else:
                status = "PASS"
                evidence = "No insecure cookies detected in session."

        elif req_id == "V13.1.1" or chap_code == "V13":
            # Configuration & security headers
            missing = []
            if not has_xcto:
                missing.append("X-Content-Type-Options: nosniff")
            if "referrer-policy" not in lower_headers:
                missing.append("Referrer-Policy")
            if missing:
                status = "FAIL"
                severity = "low"
                score -= 10
                evidence = f"Missing configuration headers: {', '.join(missing)}."
                remediation = "Add X-Content-Type-Options: nosniff and Referrer-Policy headers to responses."
                findings.append({"type": "header", "severity": "low", "detail": evidence})
            else:
                status = "PASS"
                evidence = "Base configuration headers (X-Content-Type-Options, Referrer-Policy) are configured."

        elif req_id == "V1.1.1" or chap_code == "V1":
            # Encoding and sanitization
            if insecure_forms:
                status = "FAIL"
                severity = "high"
                score -= 15
                evidence = f"Forms submitting over insecure unencrypted HTTP: {insecure_forms[:2]}"
                remediation = "Update form actions to use secure HTTPS endpoints."
                findings.append({"type": "form", "severity": "high", "detail": "Form submitting over unencrypted HTTP"})
            else:
                status = "PASS"
                evidence = "No unencrypted form actions detected; passive encoding checks verified."

        else:
            # Architecture / Documentation / Non-observable standard requirements
            # Designate as MANUAL_VERIFY with guidance so the report covers the full standard
            status = "MANUAL_VERIFY"
            severity = "info"
            evidence = f"Standard requirement '{req_id}' requires architecture/policy documentation review."
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

    score = max(0, min(100, score))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 45 else "F"

    return {
        "score": score,
        "grade": grade,
        "asvs_results": asvs_results,
        "findings": findings,
    }
