# Runs inside page.evaluate() over CDP to inspect DOM security posture
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
        angular: window.angular ? window.angular.version.full : null,
        lodash: window._ && window._.VERSION ? window._.VERSION : null,
        react: window.React ? window.React.version : null,
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
    "strict-transport-security": {"weight": 20, "label": "Missing HSTS Header"},
    "content-security-policy": {"weight": 25, "label": "Missing Content-Security-Policy (CSP)"},
    "x-frame-options": {"weight": 15, "label": "Missing X-Frame-Options (Clickjacking risk)"},
    "x-content-type-options": {"weight": 10, "label": "Missing X-Content-Type-Options (nosniff)"},
    "referrer-policy": {"weight": 10, "label": "Missing Referrer-Policy"},
}

def score_scan(headers: dict, cookies: list, dom_data: dict, cdp_issues: list) -> dict:
    score = 100
    findings = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # 1. Check security headers
    for header, meta in REQUIRED_HEADERS.items():
        if header not in lower_headers:
            score -= meta["weight"]
            findings.append({"type": "header", "severity": "medium", "detail": meta["label"]})

    # 2. Check cookies for missing HttpOnly / Secure flags
    for cookie in cookies:
        if not cookie.get("secure") or not cookie.get("httpOnly"):
            score -= 5
            findings.append({
                "type": "cookie",
                "severity": "low",
                "detail": f"Cookie '{cookie.get('name')}' missing Secure or HttpOnly flag"
            })

    # 3. Check missing SRI tags
    if dom_data.get("missingSri"):
        score -= 10
        findings.append({
            "type": "sri",
            "severity": "medium",
            "detail": f"{len(dom_data['missingSri'])} third-party asset(s) loaded without SRI integrity hashes"
        })

    score = max(0, score)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 45 else "F"
    return {"score": score, "grade": grade, "findings": findings}
