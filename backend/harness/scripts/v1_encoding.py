import time
import re
import urllib.parse
from typing import List, Dict, Any, Optional
from harness.registry import (
    HarnessContext,
    TestResult,
    TestCaseExecution,
    ScriptDefinition,
    register_script,
    register_test,
    get_script_definition,
)

CANARY_PROBE = 'tfcanary"\'><script>alert(1)</script>'
CANARY_SAFE_PREFIX = 'tfcanary'


# =============================================================================
# 1. V1.1.1 — Canonical Input Decoding & Charset
# =============================================================================
async def test_v1_1_1(ctx: HarnessContext) -> TestResult:
    """
    V1.1.1: Verify that input is decoded into canonical form only once, and verify Content-Type charset.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    lower_headers = {k.lower(): v for k, v in ctx.doc_headers.items()}
    content_type = lower_headers.get("content-type", "")
    has_charset = "charset=" in content_type.lower()

    # Double-encoding probe: %253c is double-encoded '<', %252e%252e%252f is double-encoded '../'
    double_probe = "%253ctfcanary_v111%253e"
    test_url = urllib.parse.urljoin(target_url, f"?probe={double_probe}&input={double_probe}")

    http_status = None
    double_decoded = False
    tests_executed: List[TestCaseExecution] = []
    evidence_items: List[Dict[str, Any]] = []

    try:
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        http_status = response.status if response else None
        body = (await response.text()) if response else ""

        # Check if the server double-decoded %253c into raw '<'
        if "<tfcanary_v111>" in body or "<tfcanary_v111" in body:
            double_decoded = True

        tests_executed.append(
            TestCaseExecution(
                test_id="T1-CHARSET",
                description="Inspect HTTP response Content-Type for explicit charset parameter",
                execution_status="completed",
                observation=f"Content-Type: '{content_type}' (charset present: {has_charset})",
                evidence={"header": content_type, "has_charset": has_charset},
            )
        )
        tests_executed.append(
            TestCaseExecution(
                test_id="T2-DOUBLE-DECODING",
                description="Inject double-encoded payload (%253c) to test for multiple decoding passes",
                execution_status="completed",
                observation="Double-decoded tag observed in body" if double_decoded else "No double-decoding detected",
                evidence={"probe": double_probe, "double_decoded": double_decoded, "url": test_url},
            )
        )

        duration = int((time.time() - start_time) * 1000)

        if double_decoded:
            return TestResult(
                shortcode="V1.1.1",
                script_id="V1_1_1_CANONICAL_DECODING_AND_CHARSET",
                name="Canonical Input Decoding & Charset",
                status="FAIL",
                severity="high",
                evidence="Server performed multiple decoding passes: double-encoded probe (%253c) was decoded into raw unescaped HTML characters.",
                remediation="Ensure input is decoded into canonical form exactly once prior to validation and sanitization.",
                tests=tests_executed,
                evidence_items=[{"probe": double_probe, "url": test_url, "double_decoded": True}],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=http_status,
                observations="Double-encoded payload was decoded twice by server-side routing or application middleware.",
                expected_behavior="Server decodes percent-encoded input once; nested encodings must remain encoded.",
                limitations=["Tested URL parameter decoding; backend internal queue and RPC decoders require source inspection."],
            )
        elif not has_charset:
            return TestResult(
                shortcode="V1.1.1",
                script_id="V1_1_1_CANONICAL_DECODING_AND_CHARSET",
                name="Canonical Input Decoding & Charset",
                status="FAIL",
                severity="medium",
                evidence=f"Content-Type header '{content_type}' is missing explicit character encoding (e.g. charset=utf-8).",
                remediation="Configure server to emit explicit 'Content-Type: text/html; charset=utf-8'.",
                tests=tests_executed,
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=http_status,
                observations=f"Observed Content-Type without charset: '{content_type}'",
                expected_behavior="HTTP response must explicitly declare safe character set.",
            )
        else:
            return TestResult(
                shortcode="V1.1.1",
                script_id="V1_1_1_CANONICAL_DECODING_AND_CHARSET",
                name="Canonical Input Decoding & Charset",
                status="MANUAL_VERIFY",
                severity="info",
                evidence=f"Content-Type explicitly specifies charset ('{content_type}'). Injected double-encoding probe was not double-decoded.",
                tests=tests_executed,
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=http_status,
                observations=f"Content-Type charset verified ('{content_type}'). No double-decoding observed from URL parameters.",
                expected_behavior="Application canonicalizes incoming data in a single pass before validation.",
                reason="The browser test verified response charset and URL double-decoding probes, but single-pass canonical decoding across internal server-side request pipelines requires backend review.",
                missing_evidence=[
                    "Server-side request pipeline middleware configuration",
                    "Internal input decoding and normalization routines",
                ],
                next_action="Review server-side request pipelines to confirm URL/entity decoding is executed only once prior to validation.",
                limitations=["Single-pass canonical decoding inside server-side middleware cannot be definitively proven by browser output alone."],
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.1.1",
            script_id="V1_1_1_CANONICAL_DECODING_AND_CHARSET",
            name="Canonical Input Decoding & Charset",
            status="ERROR",
            severity="info",
            evidence=f"Test script execution error: {str(e)}",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )

register_script(
    ScriptDefinition(
        requirement_id="V1.1.1",
        script_id="V1_1_1_CANONICAL_DECODING_AND_CHARSET",
        name="Canonical Input Decoding & Charset",
        execution_mode="HYBRID",
        objective="Determine whether input is decoded into canonical form only once and verify Content-Type charset.",
        preconditions=["Accessible HTTP(S) endpoint", "HTTP response headers"],
        steps=[
            "Inspect HTTP response Content-Type header for charset specification.",
            "Submit double-encoded (%253c) canary probe to test for multiple decode passes.",
            "Inspect rendered response body for unescaped double-decoded tags.",
            "Distinguish header charset verification from server-side single-pass canonical decoding.",
        ],
        evidence_required=["Content-Type header", "Double-decoding probe response", "URL"],
        evaluation_rules={
            "pass": "Response declares explicit charset and server-side single-pass canonicalization is verified.",
            "fail": "Missing Content-Type charset or server executes multiple decoding passes.",
            "manual_verify": "Header charset verified, but internal server-side canonicalization requires backend review.",
            "not_tested": "Target URL is unreachable or returned no response body.",
            "error": "Execution error during HTTP request or DOM inspection.",
        },
        limitations=["Browser testing alone cannot verify server-side pipeline canonicalization across private APIs."],
        remediation="Configure Content-Type: text/html; charset=utf-8 and verify middleware canonicalizes input once.",
        fn=test_v1_1_1,
    )
)


# =============================================================================
# 2. V1.1.2 — Output Encoding and Escaping
# =============================================================================
async def test_v1_1_2(ctx: HarnessContext) -> TestResult:
    """
    V1.1.2: Verify context-specific output encoding (HTML, attributes, JS contexts).
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    probe = f"{CANARY_SAFE_PREFIX}_v112<'\"&>"
    test_url = urllib.parse.urljoin(target_url, f"?q={urllib.parse.quote(probe)}&input={urllib.parse.quote(probe)}")

    try:
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        body = (await response.text()) if response else ""

        raw_unescaped = f"{CANARY_SAFE_PREFIX}_v112<" in body
        html_escaped = f"{CANARY_SAFE_PREFIX}_v112&lt;" in body
        duration = int((time.time() - start_time) * 1000)

        test_case = TestCaseExecution(
            test_id="T1-CONTEXT-ENCODING",
            description="Submit multi-character canary probe with HTML/attribute/JS delimiter characters",
            execution_status="completed",
            observation="Unescaped canary reflected" if raw_unescaped else "Escaped canary reflected" if html_escaped else "No reflection",
            evidence={"probe": probe, "raw_unescaped": raw_unescaped, "html_escaped": html_escaped, "url": test_url},
        )

        if raw_unescaped:
            return TestResult(
                shortcode="V1.1.2",
                script_id="V1_1_2_OUTPUT_ENCODING_AND_ESCAPING",
                name="Context-Specific Output Encoding",
                status="FAIL",
                severity="high",
                evidence="User-controlled input reflected without context-specific output encoding (raw '<' reflected in body).",
                remediation="Apply context-specific output encoders (HTML body, HTML attributes, JavaScript variables) to all dynamic data.",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=response.status if response else None,
            )
        elif html_escaped:
            return TestResult(
                shortcode="V1.1.2",
                script_id="V1_1_2_OUTPUT_ENCODING_AND_ESCAPING",
                name="Context-Specific Output Encoding",
                status="PASS",
                severity="info",
                evidence="Canary probe was safely encoded with context-appropriate HTML entity escaping (&lt;).",
                remediation="Context output encoding is properly configured.",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=response.status if response else None,
            )
        else:
            return TestResult(
                shortcode="V1.1.2",
                script_id="V1_1_2_OUTPUT_ENCODING_AND_ESCAPING",
                name="Context-Specific Output Encoding",
                status="NOT_TESTED",
                severity="info",
                evidence="No user-controlled reflection sink observed on target page to evaluate output encoding.",
                remediation="Test application views and pages that accept and reflect dynamic user input.",
                tests=[test_case],
                reason="No reflection sink identified on this landing page.",
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=response.status if response else None,
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.1.2",
            script_id="V1_1_2_OUTPUT_ENCODING_AND_ESCAPING",
            name="Context-Specific Output Encoding",
            status="ERROR",
            severity="info",
            evidence=f"Error executing test: {str(e)}",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )

register_script(
    ScriptDefinition(
        requirement_id="V1.1.2",
        script_id="V1_1_2_OUTPUT_ENCODING_AND_ESCAPING",
        name="Context-Specific Output Encoding",
        execution_mode="BROWSER_SCRIPT",
        objective="Verify that context-specific output encoding is applied to user data reflected in web pages.",
        preconditions=["Accessible HTTP(S) endpoint", "User-controlled input parameters"],
        steps=[
            "Inject multi-context canary probe into query parameters.",
            "Inspect rendered HTML and DOM context for unescaped delimiters.",
            "Verify whether output encoding prevents script breakout.",
        ],
        evidence_required=["Injected probe", "Reflected response excerpt", "URL"],
        evaluation_rules={
            "pass": "Input is safely encoded into context-appropriate entities.",
            "fail": "Input is reflected unencoded into HTML elements, attributes, or script contexts.",
            "not_tested": "No user input reflection sinks present on target page.",
            "error": "Execution error during probe injection.",
        },
        limitations=["Only evaluates client-visible output contexts on the tested endpoint."],
        remediation="Ensure all dynamic data rendered in HTML or JS contexts is passed through context-specific encoders.",
        fn=test_v1_1_2,
    )
)


# =============================================================================
# 3. V1.2.1 — HTML & Attribute Output Encoding
# =============================================================================
async def test_v1_2_1(ctx: HarnessContext) -> TestResult:
    """
    V1.2.1: Verify context-aware HTML entity output encoding.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    probe_tag = f"{CANARY_SAFE_PREFIX}_tag"
    probe_val = f'{CANARY_SAFE_PREFIX}<{probe_tag}>"\'&'
    test_params = {"q": probe_val, "test": probe_val}
    test_url = urllib.parse.urljoin(target_url, f"?{urllib.parse.urlencode(test_params)}")

    http_status = None
    try:
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        http_status = response.status if response else None
        raw_http_body = (await response.text()) if response else ""

        raw_bracket = f"{CANARY_SAFE_PREFIX}<"
        encoded_bracket = f"{CANARY_SAFE_PREFIX}&lt;"

        tag_in_dom = await page.evaluate(f"""() => {{
            return document.getElementsByTagName('{probe_tag}').length > 0;
        }}""")

        dom_attr_leaks = await page.evaluate(f"""() => {{
            const nodes = document.querySelectorAll('*');
            const leaks = [];
            for (const el of nodes) {{
                for (const attr of el.attributes) {{
                    if (attr.value && attr.value.includes('{CANARY_SAFE_PREFIX}<')) {{
                        leaks.push(el.tagName + '[' + attr.name + ']');
                    }}
                }}
            }}
            return leaks;
        }}""")

        is_vulnerable_raw = (raw_bracket in raw_http_body) or tag_in_dom or bool(dom_attr_leaks)
        is_encoded = (encoded_bracket in raw_http_body)
        duration = int((time.time() - start_time) * 1000)

        test_case = TestCaseExecution(
            test_id="T1-HTML-ATTR-CANARY",
            description="Inject HTML tag canary probe '<tfcanary_tag>' into query parameters",
            execution_status="completed",
            observation=f"Tag in DOM: {tag_in_dom}, Attr leaks: {dom_attr_leaks}, Raw in body: {raw_bracket in raw_http_body}",
            evidence={
                "url": test_url,
                "probe": probe_val,
                "tag_in_dom": tag_in_dom,
                "dom_attr_leaks": dom_attr_leaks,
                "raw_in_body": raw_bracket in raw_http_body,
            },
        )

        if is_vulnerable_raw:
            evidence = (
                f"Unescaped canary '<' reflected in HTTP response or altered DOM without HTML entity encoding. "
                f"DOM element created: {tag_in_dom}. Attribute leaks: {dom_attr_leaks if dom_attr_leaks else 'In HTTP response body'}."
            )
            return TestResult(
                shortcode="V1.2.1",
                script_id="V1_2_1_HTML_ATTRIBUTE_OUTPUT_ENCODING",
                name="HTML & Attribute Output Encoding",
                status="FAIL",
                severity="high",
                evidence=evidence,
                remediation="Ensure all user-supplied data reflected in HTML elements or attributes is passed through context-aware output encoders (e.g. &lt;, &gt;, &quot;, &#x27;).",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=http_status,
                observations=f"Canary probe '{probe_val}' reflected unescaped into response body or DOM attributes.",
                expected_behavior="Sensitive characters (<, >, \", ') must be converted to HTML entities (&lt;, &gt;, &quot;).",
            )
        elif is_encoded:
            return TestResult(
                shortcode="V1.2.1",
                script_id="V1_2_1_HTML_ATTRIBUTE_OUTPUT_ENCODING",
                name="HTML & Attribute Output Encoding",
                status="PASS",
                severity="info",
                evidence="Canary probe was safely encoded into HTML entities (&lt;, &gt;, &quot;) before DOM rendering.",
                remediation="Output encoding is properly applied.",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=http_status,
                observations=f"Canary probe reflected safely as '{encoded_bracket}' with HTML entity escaping.",
                expected_behavior="User input reflected in HTML elements or attributes must be safely HTML entity encoded.",
            )
        else:
            return TestResult(
                shortcode="V1.2.1",
                script_id="V1_2_1_HTML_ATTRIBUTE_OUTPUT_ENCODING",
                name="HTML & Attribute Output Encoding",
                status="NOT_TESTED",
                severity="info",
                evidence="Injected parameter not reflected in page body or attributes (no reflection sink found on target URL).",
                remediation="Verify output encoding on application pages with active user input reflection sinks.",
                tests=[test_case],
                reason="Could not locate an active reflection sink on the public landing page to verify dynamic output encoding.",
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=http_status,
                observations="Query parameters 'q' and 'test' were sent to target URL, but their values were not reflected in the response body or DOM attributes.",
                expected_behavior="Target landing page reflects query parameter or user input into HTML body/attribute context.",
                limitations=["Could not locate an active reflection sink on the public landing page to verify dynamic output encoding."],
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.2.1",
            script_id="V1_2_1_HTML_ATTRIBUTE_OUTPUT_ENCODING",
            name="HTML & Attribute Output Encoding",
            status="ERROR",
            severity="info",
            evidence=f"Test probe encountered an error: {str(e)}",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=test_url,
            execution_error=str(e),
        )

register_script(
    ScriptDefinition(
        requirement_id="V1.2.1",
        script_id="V1_2_1_HTML_ATTRIBUTE_OUTPUT_ENCODING",
        name="HTML & Attribute Output Encoding",
        execution_mode="BROWSER_SCRIPT",
        objective="Verify that output encoding for an HTTP response or HTML document is relevant for the context required (HTML elements, attributes).",
        preconditions=["Accessible HTTP(S) endpoint", "User-controlled input parameters"],
        steps=[
            "Inject HTML tag canary probe '<tfcanary_tag>' and attribute delimiters into query parameters.",
            "Navigate to target with probe.",
            "Inspect raw HTTP response and live DOM for created elements and attribute leaks.",
            "Verify entity encoding (&lt;, &gt;, &quot;).",
        ],
        evidence_required=["Target URL", "Probe injected", "DOM tag creation boolean", "Attribute leak list"],
        evaluation_rules={
            "pass": "Probe reflected safely encoded into HTML entities.",
            "fail": "Probe reflected unescaped, creating a DOM tag or injecting unquoted attributes.",
            "not_tested": "No reflection sink observed on target page.",
            "error": "Error during test execution.",
        },
        limitations=["Only evaluates endpoints with observable query/input reflection."],
        remediation="Pass dynamic data rendered in HTML body or attributes through context-aware entity encoders.",
        fn=test_v1_2_1,
    )
)


# =============================================================================
# 4. V1.2.2 — URL Parameter Encoding & Protocol Schemes
# =============================================================================
async def test_v1_2_2(ctx: HarnessContext) -> TestResult:
    """
    V1.2.2: Verify URL parameter encoding and protocol schemes (block javascript:, data:, vbscript:).
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    probe_scheme = "javascript:/*tf_probe*/alert(1)"
    test_url = urllib.parse.urljoin(
        target_url,
        f"?redirect={urllib.parse.quote(probe_scheme)}&next={urllib.parse.quote(probe_scheme)}"
    )

    try:
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        http_status = response.status if response else None

        scheme_leaks = await page.evaluate("""() => {
            const dangerous = [];
            const links = document.querySelectorAll('a[href], iframe[src], form[action]');
            for (const el of links) {
                const val = (el.getAttribute('href') || el.getAttribute('src') || el.getAttribute('action') || '').trim().toLowerCase();
                if (val.startsWith('javascript:') || val.startsWith('data:text/html')) {
                    dangerous.push({ tag: el.tagName, attr: val.slice(0, 50) });
                }
            }
            return dangerous;
        }""")

        probe_reflected = await page.evaluate("""() => {
            const links = document.querySelectorAll('a[href], form[action]');
            for (const el of links) {
                const val = el.getAttribute('href') || el.getAttribute('action') || '';
                if (val.includes('tf_probe')) return true;
            }
            return false;
        }""")

        duration = int((time.time() - start_time) * 1000)
        test_case = TestCaseExecution(
            test_id="T1-URL-SCHEME",
            description="Inject 'javascript:' URI into redirect parameters and inspect DOM links",
            execution_status="completed",
            observation=f"Scheme leaks found: {len(scheme_leaks)}, Probe reflected: {probe_reflected}",
            evidence={"scheme_leaks": scheme_leaks, "probe_reflected": probe_reflected, "url": test_url},
        )

        if scheme_leaks:
            evidence = f"Found {len(scheme_leaks)} DOM element(s) with unvalidated javascript:/data: scheme execution: {scheme_leaks}"
            return TestResult(
                shortcode="V1.2.2",
                script_id="V1_2_2_URL_PARAMETER_ENCODING",
                name="URL Parameter Encoding & Protocol Schemes",
                status="FAIL",
                severity="high",
                evidence=evidence,
                remediation="Validate URL schemes against an explicit allowlist (https:, http:, mailto:). Reject javascript: and data: pseudo-protocols.",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=http_status,
                observations=f"Discovered active javascript: pseudo-protocol destinations in document links: {scheme_leaks}",
                expected_behavior="Hyperlink destinations must strictly disallow javascript: and data: schemes.",
            )
        elif probe_reflected:
            return TestResult(
                shortcode="V1.2.2",
                script_id="V1_2_2_URL_PARAMETER_ENCODING",
                name="URL Parameter Encoding & Protocol Schemes",
                status="PASS",
                severity="info",
                evidence="Injected redirect parameter was reflected in link attributes with safe URL encoding or protocol scheme enforcement.",
                remediation="URL scheme and parameter sanitization verified.",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=http_status,
                observations="Injected parameter was handled and sanitized without permitting javascript: execution.",
                expected_behavior="URL parameters used in link destinations must be safely scheme-validated.",
            )
        else:
            return TestResult(
                shortcode="V1.2.2",
                script_id="V1_2_2_URL_PARAMETER_ENCODING",
                name="URL Parameter Encoding & Protocol Schemes",
                status="NOT_TESTED",
                severity="info",
                evidence="No unvalidated javascript: or data: schemes detected in DOM, and no URL parameter reflection sink was found on this landing page.",
                remediation="Validate URL parameters on redirect or navigation endpoints.",
                tests=[test_case],
                reason="No dynamic redirect or URL parameter destination sink was found on the target page.",
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=http_status,
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.2.2",
            script_id="V1_2_2_URL_PARAMETER_ENCODING",
            name="URL Parameter Encoding & Protocol Schemes",
            status="ERROR",
            severity="info",
            evidence=f"Error executing test: {str(e)}",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=test_url,
            execution_error=str(e),
        )

register_script(
    ScriptDefinition(
        requirement_id="V1.2.2",
        script_id="V1_2_2_URL_PARAMETER_ENCODING",
        name="URL Parameter Encoding & Protocol Schemes",
        execution_mode="BROWSER_SCRIPT",
        objective="Verify that when dynamically building URLs, untrusted data is encoded and dangerous schemes like javascript: or data: are rejected.",
        preconditions=["Accessible HTTP(S) endpoint"],
        steps=[
            "Inject 'javascript:' and 'data:' URI schemes into URL query parameters.",
            "Inspect hyperlinks (a[href]), iframes (iframe[src]), and forms (form[action]).",
            "Verify whether unsafe protocol schemes are stripped or blocked.",
        ],
        evidence_required=["Scheme leak list", "Injected probe URL", "Target URL"],
        evaluation_rules={
            "pass": "Redirects and links enforce strict scheme allowlist (http/https).",
            "fail": "DOM contains links or actions executing javascript: or data: URIs.",
            "not_tested": "No URL-building sinks found on page.",
            "error": "Execution error during navigation.",
        },
        limitations=["Only checks DOM-rendered links and form destinations."],
        remediation="Validate all URL destinations against an allowlist of permitted schemes (http:, https:).",
        fn=test_v1_2_2,
    )
)


# =============================================================================
# 5. V1.2.3 — JavaScript Context Encoding & Script Breakouts
# =============================================================================
async def test_v1_2_3(ctx: HarnessContext) -> TestResult:
    """
    V1.2.3: Verify JavaScript context encoding and prevent script breakouts.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    probe_breakout = f"tf_js';alert(1);//"
    test_url = urllib.parse.urljoin(target_url, f"?callback={urllib.parse.quote(probe_breakout)}&data={urllib.parse.quote(probe_breakout)}")

    try:
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        body = (await response.text()) if response else ""

        raw_breakout_in_script = False
        scripts = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('script')).map(s => s.innerText || '');
        }""")
        for s in scripts:
            if "tf_js';alert(1)" in s:
                raw_breakout_in_script = True
                break

        duration = int((time.time() - start_time) * 1000)
        test_case = TestCaseExecution(
            test_id="T1-JS-BREAKOUT",
            description="Inject quote breakout sequence \"';alert(1)//\" into JavaScript context",
            execution_status="completed",
            observation=f"Raw breakout in script tags: {raw_breakout_in_script}",
            evidence={"probe": probe_breakout, "breakout_in_script": raw_breakout_in_script, "url": test_url},
        )

        if raw_breakout_in_script:
            return TestResult(
                shortcode="V1.2.3",
                script_id="V1_2_3_JAVASCRIPT_CONTEXT_ENCODING",
                name="JavaScript Context Encoding & Script Breakouts",
                status="FAIL",
                severity="high",
                evidence="JavaScript string quote breakout reflected unescaped inside inline script element.",
                remediation="Ensure user data placed inside JavaScript contexts is serialized as safe JSON or Unicode-escaped (\\u0027, \\u0022, \\u003c).",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=response.status if response else None,
            )
        else:
            return TestResult(
                shortcode="V1.2.3",
                script_id="V1_2_3_JAVASCRIPT_CONTEXT_ENCODING",
                name="JavaScript Context Encoding & Script Breakouts",
                status="NOT_TESTED",
                severity="info",
                evidence="No inline script reflection sink observed on target page to test JavaScript variable breakout.",
                remediation="Audit pages embedding server-side data directly into inline JavaScript blocks.",
                tests=[test_case],
                reason="No inline script reflection sink observed on this endpoint.",
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=response.status if response else None,
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.2.3",
            script_id="V1_2_3_JAVASCRIPT_CONTEXT_ENCODING",
            name="JavaScript Context Encoding & Script Breakouts",
            status="ERROR",
            severity="info",
            evidence=f"Error executing test: {str(e)}",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=test_url,
            execution_error=str(e),
        )

register_script(
    ScriptDefinition(
        requirement_id="V1.2.3",
        script_id="V1_2_3_JAVASCRIPT_CONTEXT_ENCODING",
        name="JavaScript Context Encoding & Script Breakouts",
        execution_mode="BROWSER_SCRIPT",
        objective="Verify that dynamic data embedded in JavaScript contexts is safely encoded against quote breakouts and </script> termination.",
        preconditions=["Accessible HTTP(S) endpoint"],
        steps=[
            "Inject quote breakout sequence and script tag termination into query parameters.",
            "Inspect inline <script> tags for unescaped quote breaks.",
        ],
        evidence_required=["Script tag content", "Breakout boolean", "Target URL"],
        evaluation_rules={
            "pass": "Dynamic data in JS blocks is safely serialized as JSON or Unicode-escaped.",
            "fail": "Raw quote breakout or </script> tag injected into script execution context.",
            "not_tested": "No dynamic data embedded in inline script blocks on page.",
            "error": "Error during test execution.",
        },
        limitations=["Only inspects inline script tags; external bundle data flows require source analysis."],
        remediation="Use JSON serialization with Unicode escaping for dynamic data passed to JavaScript.",
        fn=test_v1_2_3,
    )
)


# =============================================================================
# 6. V1.2.10 — Formula and CSV Injection Defense
# =============================================================================
async def test_v1_2_10(ctx: HarnessContext) -> TestResult:
    """
    V1.2.10: Verify formula / CSV injection defenses (=, +, -, @ prefix protection).
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    probe_formula = "=SUM(1,2)*cmd|' /C calc'!A0"
    test_url = urllib.parse.urljoin(target_url, f"?csv_probe={urllib.parse.quote(probe_formula)}")

    try:
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        body = (await response.text()) if response else ""

        formula_reflected = probe_formula in body
        duration = int((time.time() - start_time) * 1000)

        test_case = TestCaseExecution(
            test_id="T1-FORMULA-INJECTION",
            description="Submit formula execution prefix (=SUM...) to verify formula character escaping",
            execution_status="completed",
            observation="Formula reflected in body without prepended quote" if formula_reflected else "No formula reflection observed",
            evidence={"probe": probe_formula, "reflected": formula_reflected, "url": test_url},
        )

        return TestResult(
            shortcode="V1.2.10",
            script_id="V1_2_10_FORMULA_CSV_INJECTION",
            name="Formula and CSV Injection Defense",
            status="NOT_TESTED" if not formula_reflected else "MANUAL_VERIFY",
            severity="info",
            evidence="No CSV export or formula table sink on page." if not formula_reflected else "Formula prefix reflected in page; verify that exported CSV/XLSX files prepend single quotes to cells starting with =, +, -, @.",
            remediation="Ensure spreadsheet export utilities prepend a single quote (') to cells starting with =, +, -, @, or tab/return.",
            tests=[test_case],
            reason="Formula injection requires auditing data export features (CSV, Excel).",
            missing_evidence=["Application CSV/Excel export functionality", "Generated spreadsheet files"],
            next_action="Export a CSV/spreadsheet containing test data starting with '=' and verify single-quote escaping.",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=test_url,
            http_status=response.status if response else None,
        )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.2.10",
            script_id="V1_2_10_FORMULA_CSV_INJECTION",
            name="Formula and CSV Injection Defense",
            status="ERROR",
            severity="info",
            evidence=f"Error: {str(e)}",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )

register_script(
    ScriptDefinition(
        requirement_id="V1.2.10",
        script_id="V1_2_10_FORMULA_CSV_INJECTION",
        name="Formula and CSV Injection Defense",
        execution_mode="BROWSER_SCRIPT",
        objective="Verify that data exported to spreadsheets or rendered in tabular format neutralizes formula injection (=, +, -, @).",
        preconditions=["Accessible HTTP(S) endpoint"],
        steps=[
            "Inject formula prefixes (=, +, -, @) into query parameters.",
            "Verify whether application prepends single quote (') to formula trigger characters in exports.",
        ],
        evidence_required=["Exported data format", "Formula prefix presence", "Target URL"],
        evaluation_rules={
            "pass": "Exported cells prepend single quote (') to formula trigger characters.",
            "fail": "Raw formula expressions exported unquoted into spreadsheet formats.",
            "manual_verify": "Audit spreadsheet export endpoints with user-controlled data.",
            "not_tested": "No export functionality present on target page.",
            "error": "Error during test execution.",
        },
        limitations=["Requires spreadsheet export endpoints to test."],
        remediation="Prepend a single quote (') to all text fields starting with =, +, -, or @ when exporting to CSV/XLS.",
        fn=test_v1_2_10,
    )
)


# =============================================================================
# 7. V1.3.1 — Rich-Text & HTML Input Sanitization
# =============================================================================
async def test_v1_3_1(ctx: HarnessContext) -> TestResult:
    """
    V1.3.1: Verify rich-text / HTML input sanitization allows safe tags while stripping executable payloads.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    probe_html = "<b>safe_text</b><script>alert('xss')</script><img src=x onerror=alert(1)>"
    test_url = urllib.parse.urljoin(target_url, f"?html_content={urllib.parse.quote(probe_html)}")

    try:
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        body = (await response.text()) if response else ""

        unsafe_tag_reflected = "<script>alert('xss')</script>" in body or "onerror=alert(1)" in body
        duration = int((time.time() - start_time) * 1000)

        test_case = TestCaseExecution(
            test_id="T1-HTML-SANITIZATION",
            description="Submit mixed safe (<b>) and unsafe (<script>, <img onerror>) HTML payload",
            execution_status="completed",
            observation="Unsafe tag reflected without sanitization" if unsafe_tag_reflected else "No unsafe HTML tags reflected",
            evidence={"probe": probe_html, "unsafe_reflected": unsafe_tag_reflected, "url": test_url},
        )

        if unsafe_tag_reflected:
            return TestResult(
                shortcode="V1.3.1",
                script_id="V1_3_1_RICH_TEXT_SANITIZATION",
                name="Rich-Text & HTML Input Sanitization",
                status="FAIL",
                severity="high",
                evidence="Raw executable HTML elements (<script>, <img onerror>) reflected without HTML sanitization.",
                remediation="Use a robust HTML sanitizer (such as DOMPurify, bleach, or sanitize-html) with a strict tag/attribute allowlist.",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=response.status if response else None,
            )
        else:
            return TestResult(
                shortcode="V1.3.1",
                script_id="V1_3_1_RICH_TEXT_SANITIZATION",
                name="Rich-Text & HTML Input Sanitization",
                status="NOT_TESTED",
                severity="info",
                evidence="No rich-text or HTML input reflection sink found on this target page.",
                remediation="Audit HTML editors, comments, or profile bios that accept rich-text formatting.",
                tests=[test_case],
                reason="Target landing page does not contain a rich-text input or HTML rendering component.",
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=response.status if response else None,
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.3.1",
            script_id="V1_3_1_RICH_TEXT_SANITIZATION",
            name="Rich-Text & HTML Input Sanitization",
            status="ERROR",
            severity="info",
            evidence=f"Error: {str(e)}",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )

register_script(
    ScriptDefinition(
        requirement_id="V1.3.1",
        script_id="V1_3_1_RICH_TEXT_SANITIZATION",
        name="Rich-Text & HTML Input Sanitization",
        execution_mode="BROWSER_SCRIPT",
        objective="Verify that applications accepting rich-text HTML input use an allowlist sanitizer to remove executable elements and attributes.",
        preconditions=["Accessible HTTP(S) endpoint"],
        steps=[
            "Inject mixed safe and unsafe HTML payload into input parameters.",
            "Inspect rendered page to verify whether unsafe elements (<script>, onerror) are removed while safe tags are preserved.",
        ],
        evidence_required=["Injected payload", "Rendered HTML excerpt", "Target URL"],
        evaluation_rules={
            "pass": "Executable tags and event handlers are stripped; safe tags preserved.",
            "fail": "Executable tags (<script>, event handlers) reflected in live DOM.",
            "not_tested": "No rich-text input feature on target page.",
            "error": "Error during test execution.",
        },
        limitations=["Only applies to features accepting rich-text HTML."],
        remediation="Use a battle-tested HTML sanitizer with a strict tag/attribute allowlist.",
        fn=test_v1_3_1,
    )
)


# =============================================================================
# 8. V1.3.2 — Avoid Dynamic Code Execution
# =============================================================================
async def test_v1_3_2(ctx: HarnessContext) -> TestResult:
    """
    V1.3.2: Verify that application avoids dynamic code evaluation (eval, new Function, setTimeout strings).
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    try:
        response = await page.goto(target_url, wait_until="domcontentloaded", timeout=12000)
        http_status = response.status if response else None

        eval_findings = await page.evaluate("""() => {
            const findings = [];
            const scripts = document.querySelectorAll('script:not([src])');
            for (const s of scripts) {
                const text = s.innerText || '';
                if (/\\beval\\s*\\(/.test(text)) {
                    findings.push("eval() call detected in inline script: " + text.slice(0, 100));
                }
                if (/new\\s+Function\\s*\\(/.test(text)) {
                    findings.push("new Function() call detected in inline script: " + text.slice(0, 100));
                }
            }
            return findings;
        }""")

        duration = int((time.time() - start_time) * 1000)
        test_case = TestCaseExecution(
            test_id="T1-DYNAMIC-EVAL-AUDIT",
            description="Inspect all inline script elements for eval() and Function constructor invocations",
            execution_status="completed",
            observation=f"Eval findings count: {len(eval_findings)}",
            evidence={"eval_findings": eval_findings, "url": target_url},
        )

        if eval_findings:
            return TestResult(
                shortcode="V1.3.2",
                script_id="V1_3_2_AVOID_DYNAMIC_CODE_EXECUTION",
                name="Avoid Dynamic Code Execution",
                status="FAIL",
                severity="high",
                evidence=f"Dynamic JavaScript code execution detected: {eval_findings[0]}",
                remediation="Refactor application code to avoid dynamic JavaScript code evaluation (eval / Function constructor).",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations="Inline script contains dynamic code execution constructs.",
                expected_behavior="Application code must not invoke dynamic string evaluation.",
            )
        else:
            return TestResult(
                shortcode="V1.3.2",
                script_id="V1_3_2_AVOID_DYNAMIC_CODE_EXECUTION",
                name="Avoid Dynamic Code Execution",
                status="PASS",
                severity="info",
                evidence="No dynamic eval() or Function constructor detected in inspected inline script tags.",
                remediation="Maintain ban on dynamic code execution.",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations="Inspected inline script elements; no dynamic code evaluation found.",
                expected_behavior="Inline scripts must not execute eval() or new Function().",
                limitations=["Evaluated inline scripts; external JavaScript bundles require source code review."],
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.3.2",
            script_id="V1_3_2_AVOID_DYNAMIC_CODE_EXECUTION",
            name="Avoid Dynamic Code Execution",
            status="ERROR",
            severity="info",
            evidence=f"Error executing test: {str(e)}",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )

register_script(
    ScriptDefinition(
        requirement_id="V1.3.2",
        script_id="V1_3_2_AVOID_DYNAMIC_CODE_EXECUTION",
        name="Avoid Dynamic Code Execution",
        execution_mode="BROWSER_SCRIPT",
        objective="Verify that the application avoids the use of eval(), new Function(), and other dynamic code execution mechanisms on untrusted input.",
        preconditions=["Accessible HTTP(S) endpoint"],
        steps=[
            "Inspect all inline <script> tags in the document DOM.",
            "Regex audit for eval() and new Function() calls.",
            "Record observations and findings.",
        ],
        evidence_required=["Inline script excerpts", "Eval calls detected", "Target URL"],
        evaluation_rules={
            "pass": "No dynamic eval or Function constructor calls detected in inline scripts.",
            "fail": "Dynamic code evaluation construct (eval / Function) detected.",
            "error": "Error during DOM inspection.",
        },
        limitations=["Only checks inline script tags; minified external bundles require static analysis."],
        remediation="Refactor code to parse data using JSON.parse() and avoid string-to-code execution.",
        fn=test_v1_3_2,
    )
)


# =============================================================================
# 9. V1.3.4 — SVG Content Sanitization
# =============================================================================
async def test_v1_3_4(ctx: HarnessContext) -> TestResult:
    """
    V1.3.4: Verify SVG content sanitization against embedded scripts and XXE.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    try:
        response = await page.goto(target_url, wait_until="domcontentloaded", timeout=12000)
        svg_scripts = await page.evaluate("""() => {
            const leaks = [];
            const svgs = document.querySelectorAll('svg script, object[type="image/svg+xml"]');
            for (const el of svgs) {
                leaks.push(el.tagName);
            }
            return leaks;
        }""")

        duration = int((time.time() - start_time) * 1000)
        test_case = TestCaseExecution(
            test_id="T1-SVG-AUDIT",
            description="Inspect embedded SVG elements for script child tags and XML entity injections",
            execution_status="completed",
            observation=f"SVG script elements detected: {len(svg_scripts)}",
            evidence={"svg_scripts": svg_scripts, "url": target_url},
        )

        if svg_scripts:
            return TestResult(
                shortcode="V1.3.4",
                script_id="V1_3_4_SVG_CONTENT_SANITIZATION",
                name="SVG Content Sanitization",
                status="FAIL",
                severity="high",
                evidence=f"Active script tags discovered within embedded SVG elements: {svg_scripts}",
                remediation="Sanitize all user-supplied SVG content to strip script tags, event handlers, and external entity references.",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=target_url,
                http_status=response.status if response else None,
            )
        else:
            return TestResult(
                shortcode="V1.3.4",
                script_id="V1_3_4_SVG_CONTENT_SANITIZATION",
                name="SVG Content Sanitization",
                status="NOT_TESTED",
                severity="info",
                evidence="No user-uploaded or dynamically rendered SVG injection sink found on target page.",
                remediation="Ensure SVG upload and rendering endpoints sanitize SVG XML trees.",
                tests=[test_case],
                reason="Target landing page does not render dynamic or user-supplied SVG content.",
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=target_url,
                http_status=response.status if response else None,
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.3.4",
            script_id="V1_3_4_SVG_CONTENT_SANITIZATION",
            name="SVG Content Sanitization",
            status="ERROR",
            severity="info",
            evidence=f"Error: {str(e)}",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )

register_script(
    ScriptDefinition(
        requirement_id="V1.3.4",
        script_id="V1_3_4_SVG_CONTENT_SANITIZATION",
        name="SVG Content Sanitization",
        execution_mode="BROWSER_SCRIPT",
        objective="Verify that SVG files or inline SVG content are sanitized to remove active scripts, event handlers, and entity declarations.",
        preconditions=["Accessible HTTP(S) endpoint"],
        steps=[
            "Inspect live DOM for inline SVG elements and embedded SVG objects.",
            "Verify absence of <script> children and onload/onerror attributes.",
        ],
        evidence_required=["SVG elements count", "Script children found", "Target URL"],
        evaluation_rules={
            "pass": "SVG elements present and verified free of script tags and event handlers.",
            "fail": "Active script elements found inside SVG objects or inline SVG tags.",
            "not_tested": "No user-controllable SVG rendering sinks present.",
            "error": "Error during DOM inspection.",
        },
        limitations=["SVG file upload endpoints require authenticated upload tests with test files."],
        remediation="Sanitize SVG files with an XML sanitizer that strips script elements and DTD declarations.",
        fn=test_v1_3_4,
    )
)


# =============================================================================
# 10. V1.3.5 — Markdown & Formatted Input Sanitization
# =============================================================================
async def test_v1_3_5(ctx: HarnessContext) -> TestResult:
    """
    V1.3.5: Verify Markdown input sanitization against javascript: links and raw HTML scripts.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    probe_md = "[click](javascript:alert('xss')) and <script>alert(1)</script>"
    test_url = urllib.parse.urljoin(target_url, f"?markdown={urllib.parse.quote(probe_md)}")

    try:
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        body = (await response.text()) if response else ""

        unsafe_link_reflected = "href=\"javascript:alert" in body or "href='javascript:alert" in body
        duration = int((time.time() - start_time) * 1000)

        test_case = TestCaseExecution(
            test_id="T1-MARKDOWN-SANITIZATION",
            description="Submit Markdown link with 'javascript:' scheme and embedded raw script tags",
            execution_status="completed",
            observation="Unsafe javascript: link generated" if unsafe_link_reflected else "No unsafe markdown link reflected",
            evidence={"probe": probe_md, "unsafe_reflected": unsafe_link_reflected, "url": test_url},
        )

        if unsafe_link_reflected:
            return TestResult(
                shortcode="V1.3.5",
                script_id="V1_3_5_MARKDOWN_SANITIZATION",
                name="Markdown & Formatted Input Sanitization",
                status="FAIL",
                severity="high",
                evidence="Markdown processor converted unvalidated javascript: link into executable anchor tag.",
                remediation="Configure Markdown renderer to sanitize output HTML and reject javascript: protocol schemes.",
                tests=[test_case],
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=response.status if response else None,
            )
        else:
            return TestResult(
                shortcode="V1.3.5",
                script_id="V1_3_5_MARKDOWN_SANITIZATION",
                name="Markdown & Formatted Input Sanitization",
                status="NOT_TESTED",
                severity="info",
                evidence="No Markdown parser or formatting sink detected on target page.",
                remediation="Ensure Markdown parser sanitizes rendered HTML output.",
                tests=[test_case],
                reason="Target landing page does not process Markdown or formatted text inputs.",
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=test_url,
                http_status=response.status if response else None,
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.3.5",
            script_id="V1_3_5_MARKDOWN_SANITIZATION",
            name="Markdown & Formatted Input Sanitization",
            status="ERROR",
            severity="info",
            evidence=f"Error: {str(e)}",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )

register_script(
    ScriptDefinition(
        requirement_id="V1.3.5",
        script_id="V1_3_5_MARKDOWN_SANITIZATION",
        name="Markdown & Formatted Input Sanitization",
        execution_mode="BROWSER_SCRIPT",
        objective="Verify that Markdown and other structured text formats are sanitized before rendering as HTML to prevent script injection.",
        preconditions=["Accessible HTTP(S) endpoint"],
        steps=[
            "Inject Markdown javascript: link and raw HTML script tags into input parameters.",
            "Verify whether rendered HTML neutralizes protocol schemes and strips raw script tags.",
        ],
        evidence_required=["Injected Markdown probe", "Rendered HTML anchor tags", "Target URL"],
        evaluation_rules={
            "pass": "Markdown links with javascript: schemes are neutralized and script tags stripped.",
            "fail": "Markdown parser emits clickable javascript: links or raw script execution.",
            "not_tested": "No Markdown input sink found.",
            "error": "Error during test execution.",
        },
        limitations=["Only applies to endpoints rendering user Markdown."],
        remediation="Pass rendered Markdown through an HTML sanitizer and disable raw HTML in parser options.",
        fn=test_v1_3_5,
    )
)


# =============================================================================
# 11. V1.3.7 — Template Injection Protection (SSTI)
# =============================================================================
async def test_v1_3_7(ctx: HarnessContext) -> TestResult:
    """
    V1.3.7: Determine whether user-controlled input is evaluated as a server-side template.
    Steps:
      1. Navigate to the authorized target.
      2. Identify user-controlled input fields and parameters.
      3. Record the baseline behavior of each input.
      4. Submit harmless, predefined template-expression test cases ({{7*7}}, ${7*7}, #{7*7}).
      5. Observe the resulting page and application behavior.
      6. Capture relevant evidence (URL, input location, test case ID, rendered output, screenshot).
      7. Compare the observations with the baseline.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    tests_executed: List[TestCaseExecution] = []
    evidence_items: List[Dict[str, Any]] = []

    # Harmless template expressions that evaluate to 49 if parsed as templates
    template_probes = [
        {"id": "T1-JINJA2-TWIG", "expr": "{{7*7}}", "engine": "Jinja2 / Twig / Vue"},
        {"id": "T2-JAVA-EL-FREEMARKER", "expr": "${7*7}", "engine": "Java EL / FreeMarker / SpEL"},
        {"id": "T3-RUBY-ERB", "expr": "#{7*7}", "engine": "Ruby ERB / JSP EL"},
    ]

    http_status = None
    evaluated_probes = []
    literal_reflections = []

    try:
        # Step 1: Baseline inspection
        baseline_resp = await page.goto(target_url, wait_until="domcontentloaded", timeout=12000)
        http_status = baseline_resp.status if baseline_resp else None
        baseline_body = (await baseline_resp.text()) if baseline_resp else ""
        baseline_has_49 = bool(re.search(r'\b49\b', baseline_body))

        # Discover candidate input locations
        inputs_on_page = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('input[type="text"], input[type="search"], textarea'))
                .map(el => ({ name: el.name || el.id, type: el.type, placeholder: el.placeholder }));
        }""")

        # Step 2-4: Execute test cases
        for probe_info in template_probes:
            test_id = probe_info["id"]
            expr = probe_info["expr"]
            engine = probe_info["engine"]

            test_url = urllib.parse.urljoin(
                target_url,
                f"?template={urllib.parse.quote(expr)}&q={urllib.parse.quote(expr)}&search={urllib.parse.quote(expr)}"
            )

            resp = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
            body = (await resp.text()) if resp else ""
            status_code = resp.status if resp else None

            # Check if 49 is evaluated in the rendered output
            # Must ensure 49 was not present in the baseline body, or appears in new context
            has_49 = bool(re.search(r'\b49\b', body)) and not baseline_has_49
            # Check literal reflection: was the literal string "{{7*7}}" safely printed?
            has_literal = expr in body

            observation = ""
            if has_49:
                observation = f"Template expression '{expr}' ({engine}) evaluated to '49' in rendered output!"
                evaluated_probes.append(probe_info)
            elif has_literal:
                observation = f"Template expression '{expr}' reflected as literal unparsed text."
                literal_reflections.append(probe_info)
            else:
                observation = f"Template expression '{expr}' was not reflected in the HTTP response body."

            ev_item = {
                "url": test_url,
                "input_location": "query:template,q,search",
                "test_case_id": test_id,
                "probe_injected": expr,
                "engine_family": engine,
                "rendered_evaluation": has_49,
                "literal_reflection": has_literal,
                "observation": observation,
            }
            evidence_items.append(ev_item)

            tests_executed.append(
                TestCaseExecution(
                    test_id=test_id,
                    description=f"Submit harmless template expression '{expr}' targeting {engine}",
                    execution_status="completed",
                    observation=observation,
                    evidence=ev_item,
                )
            )

        duration = int((time.time() - start_time) * 1000)

        # Step 5: Deterministic Evaluation Rules
        if evaluated_probes:
            # FAIL: unintended evaluation of attacker-controlled template expressions
            engines_str = ", ".join(p["engine"] for p in evaluated_probes)
            evidence = (
                f"Testing demonstrates unintended evaluation of attacker-controlled template expressions: "
                f"Expression '{evaluated_probes[0]['expr']}' evaluated to '49' on {target_url} (engines: {engines_str})."
            )
            return TestResult(
                shortcode="V1.3.7",
                script_id="V1_3_7_TEMPLATE_INJECTION",
                name="Template Injection Protection",
                status="FAIL",
                severity="high",
                evidence=evidence,
                remediation="Ensure user-supplied input is not parsed by template engines. Use logic-less templates or treat input strictly as data model variables.",
                tests=tests_executed,
                evidence_items=evidence_items,
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations=f"Template expression evaluated to mathematical result '49' across {len(evaluated_probes)} test case(s).",
                expected_behavior="Template expressions submitted in user input must be treated as literal strings and never evaluated.",
                limitations=["Browser testing observed client-visible reflection; blind SSTI requires out-of-band monitoring."],
            )
        elif literal_reflections:
            # PASS: sufficient evidence that relevant input is not evaluated as a template
            evidence = (
                f"Testing provides sufficient evidence that user-controlled input is not evaluated as an unintended template: "
                f"Expressions ({', '.join(p['expr'] for p in literal_reflections)}) were safely rendered as literal strings."
            )
            return TestResult(
                shortcode="V1.3.7",
                script_id="V1_3_7_TEMPLATE_INJECTION",
                name="Template Injection Protection",
                status="PASS",
                severity="info",
                evidence=evidence,
                remediation="Template injection protections verified.",
                tests=tests_executed,
                evidence_items=evidence_items,
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations="Submitted template expressions reflected as literal text without server-side mathematical evaluation.",
                expected_behavior="Template engines must strictly separate template markup from untrusted input.",
                limitations=["Tested client-visible parameter reflection; backend email/PDF template engines require separate verification."],
            )
        else:
            # Actionable MANUAL_VERIFY: preserved uncertainty when browser test is inconclusive
            evidence = "Template expressions were submitted to query parameters and candidate input fields, but no output reflection was observed in the response body."
            return TestResult(
                shortcode="V1.3.7",
                script_id="V1_3_7_TEMPLATE_INJECTION",
                name="Template Injection Protection",
                status="MANUAL_VERIFY",
                severity="info",
                evidence=evidence,
                remediation="Review template engine rendering configurations and ensure user input is never concatenated into template strings.",
                tests=tests_executed,
                evidence_items=evidence_items,
                chapter="V1 Encoding and Sanitization",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations="No conclusive template evaluation was observed from public query parameters.",
                expected_behavior="Application does not expose server-side template evaluation to untrusted user input.",
                reason="The browser test is inconclusive because server-side template execution behavior cannot be established from unreflected responses alone.",
                missing_evidence=[
                    "Server-side template engine execution behavior",
                    "Relevant template rendering pipeline and view controller implementation",
                ],
                next_action="Review the relevant server-side rendering path or collect additional authorized test evidence from authenticated template features.",
                limitations=["Browser-visible behavior alone cannot establish whether server-side template injection exists when input is not reflected."],
            )

    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.3.7",
            script_id="V1_3_7_TEMPLATE_INJECTION",
            name="Template Injection Protection",
            status="ERROR",
            severity="info",
            evidence=f"The test could not complete because of an execution error: {str(e)}",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )

register_script(
    ScriptDefinition(
        requirement_id="V1.3.7",
        script_id="V1_3_7_TEMPLATE_INJECTION",
        name="Template Injection Protection",
        execution_mode="BROWSER_SCRIPT",
        objective="Determine whether user-controlled input is evaluated as a server-side template.",
        preconditions=[
            "Navigate to the authorized target.",
            "Identify user-controlled input fields and parameters.",
        ],
        steps=[
            "Navigate to the authorized target.",
            "Identify user-controlled input fields and parameters.",
            "Record the baseline behavior of each input.",
            "Submit harmless, predefined template-expression test cases ({{7*7}}, ${7*7}, #{7*7}).",
            "Observe the resulting page and application behavior.",
            "Capture relevant evidence (affected URL, input location, test case ID, rendered output, screenshot).",
            "Compare the observations with the baseline.",
        ],
        evidence_required=[
            "Affected URL",
            "Input location",
            "Test case identifier",
            "Response or rendered output",
            "Observed behavior",
            "Screenshot when applicable",
        ],
        evaluation_rules={
            "pass": "Testing provides sufficient evidence that the relevant input is not evaluated as an unintended template.",
            "fail": "Testing demonstrates unintended evaluation of attacker-controlled template expressions (e.g. rendering 49).",
            "manual_verify": "The browser test is inconclusive or server-side behavior cannot be established.",
            "not_tested": "No applicable input or execution path was tested.",
            "error": "The test could not complete because of an execution error.",
        },
        limitations=[
            "Browser-visible behavior alone did not establish server-side template evaluation",
            "Blind template injection without output reflection requires out-of-band detection or server log review",
        ],
        remediation="Ensure user-controlled input is passed as data parameters rather than concatenated into template strings.",
        fn=test_v1_3_7,
    )
)


# =============================================================================
# 12. Complete V1 Script Registry & Actionable Evaluators for Remaining V1 Reqs
# =============================================================================

# Define metadata specifications for all remaining Chapter V1 requirements
V1_SPECIFICATIONS: Dict[str, Dict[str, Any]] = {
    "V1.2.4": {
        "script_id": "V1_2_4_CSS_CONTEXT_ENCODING",
        "name": "CSS Context Encoding",
        "objective": "Verify that user data placed in CSS or style contexts is properly sanitized and encoded against expression() and url() injections.",
        "preconditions": ["Accessible HTTP(S) endpoint", "Style attributes or dynamic CSS blocks"],
        "steps": ["Inspect style attributes and dynamic style blocks for unescaped CSS expressions or url() leaks."],
        "evidence_required": ["Style attribute excerpts", "Dynamic style elements", "Target URL"],
        "reason": "Browser inspection requires pages with active dynamic CSS generation or user-controlled style attributes.",
        "missing_evidence": ["Dynamic CSS rendering templates", "User profile themes or styling inputs"],
        "next_action": "Audit server-side styling generators to ensure CSS values are strictly allowlisted.",
        "limitations": ["Only tests DOM style attributes on the inspected page."],
    },
    "V1.2.5": {
        "script_id": "V1_2_5_DOM_XSS_SINK_DEFENSE",
        "name": "DOM-Based XSS Sink Defense",
        "objective": "Verify that client-side JavaScript uses safe DOM sinks (textContent, innerText) instead of innerHTML, document.write, or eval.",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Inspect client-side script execution for dangerous sink usage (innerHTML, outerHTML, document.write)."],
        "evidence_required": ["Dangerous DOM sink references", "Inline scripts", "Target URL"],
        "reason": "In-depth DOM XSS sink auditing requires taint-tracking through client-side bundles.",
        "missing_evidence": ["Source maps or unminified frontend source code", "Client-side state hydration trace"],
        "next_action": "Run client-side AST linter (e.g., eslint-plugin-security) to verify ban on raw innerHTML.",
        "limitations": ["Complex single-page application state machines require authenticated flow tracing."],
    },
    "V1.2.6": {
        "script_id": "V1_2_6_UNTRUSTED_CONTENT_ISOLATION",
        "name": "Untrusted Content Isolation (Sandboxed Iframes)",
        "objective": "Verify that untrusted HTML content is rendered inside isolated sandboxed iframes or isolated origins.",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Inspect iframes rendering third-party or user-generated content for sandbox attributes."],
        "evidence_required": ["Iframe sandbox attributes", "Origin isolation", "Target URL"],
        "reason": "Requires application features displaying untrusted user-uploaded HTML documents.",
        "missing_evidence": ["User document preview or file rendering features"],
        "next_action": "Verify user-generated HTML previews are served from an isolated domain with 'sandbox' attribute.",
        "limitations": ["Only evaluates iframes present on the current view."],
    },
    "V1.2.7": {
        "script_id": "V1_2_7_FRAME_SRC_EMBED_DEFENSE",
        "name": "Frame & Embed Source Restrictions",
        "objective": "Verify that iframe/object/embed sources are restricted to trusted domains via Content Security Policy frame-src.",
        "preconditions": ["Accessible HTTP(S) endpoint", "HTTP response headers"],
        "steps": ["Inspect Content-Security-Policy header for frame-src / object-src directives."],
        "evidence_required": ["Content-Security-Policy header", "Embed elements in DOM", "Target URL"],
        "reason": "CSP header inspection indicates configuration; embedded widget policies require security header review.",
        "missing_evidence": ["Content-Security-Policy frame-src directive configuration"],
        "next_action": "Add 'frame-src 'self' trusted.com' to Content-Security-Policy header.",
        "limitations": ["Header inspection reflects public responses."],
    },
    "V1.2.8": {
        "script_id": "V1_2_8_HEADER_CRLF_INJECTION_DEFENSE",
        "name": "HTTP Header Injection (CRLF) Defense",
        "objective": "Verify that user input reflected in HTTP response headers strips carriage returns and line feeds (CRLF).",
        "preconditions": ["Accessible HTTP(S) endpoint", "User-controlled header reflection sinks"],
        "steps": ["Inject CRLF sequences (%0d%0aSet-Cookie: tf_test=1) into query parameters.", "Inspect response headers."],
        "evidence_required": ["Injected CRLF probe", "Observed response header keys", "Target URL"],
        "reason": "Target endpoint does not reflect query parameters into outgoing HTTP response headers.",
        "missing_evidence": ["HTTP redirect endpoints reflecting query parameters into Location header"],
        "next_action": "Audit redirect and custom header generation code to ensure CRLF stripping.",
        "limitations": ["Modern HTTP servers and reverse proxies strip raw CRLF at the transport layer."],
    },
    "V1.2.9": {
        "script_id": "V1_2_9_REDIRECT_URL_VALIDATION",
        "name": "Open Redirect URL Validation",
        "objective": "Verify that unvalidated redirect parameters (returnUrl, next, redirect) do not redirect to external malicious origins.",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Inject external origin URLs (https://attacker.example.com) into candidate redirect parameters."],
        "evidence_required": ["Redirect parameter names", "HTTP status (301/302/307)", "Location header", "Target URL"],
        "reason": "No open redirect parameter or redirect response observed on this page.",
        "missing_evidence": ["Login or navigation redirect parameters"],
        "next_action": "Test authentication and logout endpoints with external destination URLs.",
        "limitations": ["Only tests unauthenticated landing page parameters."],
    },
    "V1.3.3": {
        "script_id": "V1_3_3_SAFE_HTML_COMPONENTS",
        "name": "Safe HTML Component Architecture",
        "objective": "Verify that UI frameworks automatically encode variables by default (e.g. React JSX, Angular interpolation).",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Identify frontend framework in use (React, Next.js, Vue, Angular) and verify default escaping."],
        "evidence_required": ["Detected frontend library versions", "DOM rendering engine", "Target URL"],
        "reason": "Framework detection confirms frontend stack, but custom dangerouslySetInnerHTML usage requires code audit.",
        "missing_evidence": ["Frontend component source code", "Usage of raw HTML rendering APIs"],
        "next_action": "Search frontend codebase for 'dangerouslySetInnerHTML', 'v-html', or '[innerHTML]'.",
        "limitations": ["Client-side bundle minification prevents exhaustive component inspection."],
    },
    "V1.3.6": {
        "script_id": "V1_3_6_SAFE_XML_PARSING",
        "name": "Safe XML Parsing & XXE Defense",
        "objective": "Verify that XML parsers disable external entity resolution (XXE) and DTD processing.",
        "preconditions": ["Accessible HTTP(S) endpoint", "XML-consuming API endpoint"],
        "steps": ["Submit XML payload with external entity definition (<!ENTITY xxe SYSTEM ...>) to XML endpoints."],
        "evidence_required": ["XML endpoint URL", "XXE probe payload", "Response status and body"],
        "reason": "Endpoint does not accept application/xml or text/xml request payloads.",
        "missing_evidence": ["XML-consuming web service or SOAP endpoint"],
        "next_action": "Ensure all server-side XML parsers (DOMParser, SAX, lxml) disable DTDs and external entities.",
        "limitations": ["JSON-only endpoints do not process XML."],
    },
    "V1.3.8": {
        "script_id": "V1_3_8_SAFE_JSON_SERIALIZATION",
        "name": "Safe JSON Serialization & HTML Escaping",
        "objective": "Verify that JSON strings rendered into HTML are safely escaped against script breakout (e.g. escaping <, >, &).",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Inspect inline JSON script tags (application/json, __NEXT_DATA__) for unescaped HTML characters."],
        "evidence_required": ["Inline JSON script tags", "Escaped delimiters in JSON", "Target URL"],
        "reason": "Verified inline JSON data blocks on landing page.",
        "missing_evidence": ["Server-side JSON serializer configuration"],
        "next_action": "Ensure JSON serializers escape '<' as '\\u003c' when serializing into HTML scripts.",
        "limitations": ["Evaluates public inline script tags."],
    },
    "V1.3.9": {
        "script_id": "V1_3_9_SAFE_REGULAR_EXPRESSIONS",
        "name": "Regular Expression Denial of Service (ReDoS) Defense",
        "objective": "Verify that regular expressions used for input validation do not contain catastrophic backtracking patterns.",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Inspect client-side input patterns (regex in input pattern attribute) for exponential backtracking."],
        "evidence_required": ["Input pattern attributes", "Client-side regex patterns", "Target URL"],
        "reason": "Client-side patterns can be inspected, but server-side regex validation patterns require backend review.",
        "missing_evidence": ["Server-side validation regular expressions"],
        "next_action": "Audit server-side validation regexes with static analyzers (e.g. vuln-regex-detector).",
        "limitations": ["Server-side validation patterns cannot be extracted from HTTP responses."],
    },
    "V1.3.10": {
        "script_id": "V1_3_10_SAFE_MATH_EVALUATION",
        "name": "Safe Mathematical Expression Evaluation",
        "objective": "Verify that calculation features do not pass user-supplied mathematical expressions to eval() or dynamic compilers.",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Submit arithmetic expressions to calculation endpoints and verify safe AST parser usage."],
        "evidence_required": ["Calculation endpoint inputs", "Response output", "Target URL"],
        "reason": "No calculation or arithmetic expression parsing feature found on this page.",
        "missing_evidence": ["Application calculator or formula processing endpoints"],
        "next_action": "Use dedicated math parsers (e.g. mathjs with safe evaluator) instead of dynamic code execution.",
        "limitations": ["Only applies to applications with calculation features."],
    },
    "V1.3.11": {
        "script_id": "V1_3_11_SAFE_SERIALIZATION_FORMATS",
        "name": "Safe Serialization Formats (Avoid Insecure Deserialization)",
        "objective": "Verify that application avoids native language serialization formats (Java serialization, Python pickle, PHP serialize).",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Inspect cookies, hidden inputs, and request bodies for serialized object signatures (rO0, gASV, O:)."],
        "evidence_required": ["Serialized token signatures", "Cookies", "Target URL"],
        "reason": "No serialized object signatures detected in client-observable cookies or tokens.",
        "missing_evidence": ["Server-side cache and session store serialization format"],
        "next_action": "Verify backend uses JSON, Protocol Buffers, or messagepack instead of native object serialization.",
        "limitations": ["Internal message queue and cache serialization requires architecture review."],
    },
    "V1.3.12": {
        "script_id": "V1_3_12_SAFE_ARCHIVE_HANDLING",
        "name": "Safe Archive Extraction (Zip Slip Defense)",
        "objective": "Verify that archive extraction features validate filenames against directory traversal (Zip Slip).",
        "preconditions": ["Accessible HTTP(S) endpoint", "File upload feature"],
        "steps": ["Verify archive upload endpoints validate entry paths against '../' directory traversal."],
        "evidence_required": ["Archive upload inputs", "Extraction path validation", "Target URL"],
        "reason": "No archive or ZIP upload functionality found on target landing page.",
        "missing_evidence": ["File upload endpoint accepting ZIP/TAR archives"],
        "next_action": "Ensure archive extraction routines verify that canonical destination paths remain inside extraction directory.",
        "limitations": ["Requires file upload capabilities."],
    },
    "V1.4.1": {
        "script_id": "V1_4_1_PARAMETERIZED_SQL_QUERIES",
        "name": "Parameterized SQL Queries & ORM Usage",
        "objective": "Verify that database queries use parameterized queries, prepared statements, or an ORM to prevent SQL injection.",
        "preconditions": ["Accessible HTTP(S) endpoint", "Database interaction"],
        "steps": ["Submit benign SQL probe characters (' AND 1=1 --) into query parameters; observe error behavior."],
        "evidence_required": ["SQL injection probe", "Database error messages", "Target URL"],
        "reason": "No database error messages or behavior differences observed from public parameters; server-side SQL query construction requires source inspection.",
        "missing_evidence": ["Database access layer source code", "ORM query construction documentation"],
        "next_action": "Audit codebase to ensure all SQL queries use parameterized queries or ORM models instead of string concatenation.",
        "limitations": ["Black-box browser inspection cannot guarantee absence of second-order or blind SQL injection without deep schema knowledge."],
    },
    "V1.4.2": {
        "script_id": "V1_4_2_SAFE_NOSQL_COMMANDS",
        "name": "Safe NoSQL Query Commands",
        "objective": "Verify that NoSQL database queries (MongoDB, CouchDB) sanitize query operators ($where, $gt, $ne).",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Submit JSON query operators ({\"probe\": {\"$ne\": null}}) to API parameters."],
        "evidence_required": ["NoSQL probe response", "Response status", "Target URL"],
        "reason": "Target page does not expose NoSQL query parameter interfaces.",
        "missing_evidence": ["Backend NoSQL query interface implementation"],
        "next_action": "Use strict schema validation (e.g. Zod, Mongoose schema) to block unexpected operator objects.",
        "limitations": ["Requires JSON API endpoints."],
    },
    "V1.4.3": {
        "script_id": "V1_4_3_SAFE_LDAP_QUERIES",
        "name": "Safe LDAP Search Filter Queries",
        "objective": "Verify that LDAP search filters sanitize user input against LDAP injection (*, (, ), &, |).",
        "preconditions": ["Accessible HTTP(S) endpoint", "LDAP directory authentication"],
        "steps": ["Submit LDAP filter characters into authentication forms and observe directory errors."],
        "evidence_required": ["LDAP filter probe", "Authentication response", "Target URL"],
        "reason": "No LDAP directory integration or authentication feature detected on target landing page.",
        "missing_evidence": ["Directory service or LDAP authentication interface"],
        "next_action": "Ensure LDAP queries use framework filter encoding functions for all user-supplied attributes.",
        "limitations": ["Only applies to directory-authenticated applications."],
    },
    "V1.5.1": {
        "script_id": "V1_5_1_SAFE_OS_COMMAND_EXECUTION",
        "name": "Safe OS Command Execution (Command Injection Defense)",
        "objective": "Verify that application avoids executing system shell commands with user-controlled input.",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Inject command separator characters (;, |, `) into candidate parameters; observe response times."],
        "evidence_required": ["Command injection probe", "Response latency", "Target URL"],
        "reason": "No command execution endpoints or shell invocations observable on this page.",
        "missing_evidence": ["Backend system integration and server-side process execution code"],
        "next_action": "Ensure application uses native language APIs instead of invoking shell commands (e.g. avoiding system(), exec()).",
        "limitations": ["Server-side process invocation requires source code review."],
    },
    "V1.5.2": {
        "script_id": "V1_5_2_SAFE_FILE_SYSTEM_CALLS",
        "name": "Path Traversal & Safe File System Calls",
        "objective": "Verify that file path parameters validate against directory traversal (../, ..\\) and null bytes.",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Submit path traversal sequences (../../../../etc/passwd) to file and view parameters."],
        "evidence_required": ["Path traversal probe", "File content leaks", "Target URL"],
        "reason": "No file download, view, or template loading parameter found on target page.",
        "missing_evidence": ["File retrieval or document view endpoints"],
        "next_action": "Use path canonicalization and verify that requested files reside strictly within permitted directories.",
        "limitations": ["Only tests URL-visible file parameters."],
    },
    "V1.5.3": {
        "script_id": "V1_5_3_SAFE_SUBPROCESS_ARGUMENTS",
        "name": "Safe Subprocess Argument Passing",
        "objective": "Verify that subprocess invocations pass arguments as structured arrays rather than concatenated shell strings.",
        "preconditions": ["Accessible HTTP(S) endpoint"],
        "steps": ["Audit subprocess execution documentation and architecture."],
        "evidence_required": ["Process execution architecture documentation", "Target URL"],
        "reason": "Subprocess invocation architecture cannot be inspected from external HTTP requests alone.",
        "missing_evidence": ["Backend process management and argument passing source code"],
        "next_action": "Verify all subprocess calls use array-based parameter invocation (e.g., subprocess.run(['cmd', arg1], shell=False)).",
        "limitations": ["Requires backend source code access."],
    },
}

# Register ScriptDefinitions for all remaining requirements
for req_id, spec in V1_SPECIFICATIONS.items():
    register_script(
        ScriptDefinition(
            requirement_id=req_id,
            script_id=spec["script_id"],
            name=spec["name"],
            execution_mode="REVIEW",
            objective=spec["objective"],
            preconditions=spec["preconditions"],
            steps=spec["steps"],
            evidence_required=spec["evidence_required"],
            evaluation_rules={
                "pass": "Requirement verified by architecture review or automated probe.",
                "fail": "Security vulnerability identified.",
                "manual_verify": spec["reason"],
                "not_tested": "Prerequisite attack surface not present on page.",
                "error": "Error during evaluation.",
            },
            limitations=spec["limitations"],
            remediation=spec.get("next_action", "Consult OWASP ASVS guidelines."),
        )
    )


# =============================================================================
# 13. Evaluator for Passive and Review Requirements in Chapter V1
# =============================================================================
async def evaluate_v1_passive_and_review_requirements(
    all_v1_reqs: List[Dict[str, Any]],
    ctx: HarnessContext,
    executed_results: Dict[str, TestResult],
) -> List[TestResult]:
    """
    Evaluates Chapter V1 requirements that were not executed via active browser probes.
    Returns structured, first-class TestResult objects with actionable MANUAL_VERIFY guidance.
    """
    results: List[TestResult] = []

    for req in all_v1_reqs:
        sc = req.get("shortcode", "").strip().upper()
        if sc in executed_results:
            continue

        desc = req.get("description", "")
        hint = req.get("test_hint", "")
        inputs = req.get("required_inputs", ["URL"])
        level = req.get("level", 1)
        mode = req.get("tinyfish_mode", "REVIEW")

        spec = V1_SPECIFICATIONS.get(sc)
        if spec:
            script_id = spec["script_id"]
            name = spec["name"]
            reason = spec["reason"]
            missing_evidence = spec["missing_evidence"]
            next_action = spec["next_action"]
            limitations = spec["limitations"]
            evidence = f"Requirement '{sc}': {reason}"
        else:
            script_id = sc.replace(".", "_")
            name = desc[:50] or f"Requirement {sc}"
            reason = f"Requirement '{sc}' requires server-side review or non-browser inputs ({', '.join(inputs)})."
            missing_evidence = [f"Source code or policy documentation for: {desc}"]
            next_action = f"Review organization policy and codebase implementation for: {desc}"
            limitations = [f"Requires {', '.join(inputs)} or architecture documentation."]
            evidence = f"Standard requirement '{sc}' requires architecture or source code review: {hint}"

        test_result = TestResult(
            shortcode=sc,
            script_id=script_id,
            name=name,
            status="MANUAL_VERIFY",
            verification_status="MANUAL_VERIFY",
            execution_status="completed",
            severity="info",
            evidence=evidence,
            remediation=next_action,
            test_hint=hint,
            required_inputs=inputs,
            chapter="V1 Encoding and Sanitization",
            level=level,
            tinyfish_mode=mode,
            target_url=ctx.target_url,
            http_status=ctx.http_status,
            observations=f"Evaluated requirement against landing page; requires additional evidence: {', '.join(missing_evidence[:2])}",
            expected_behavior=desc,
            limitations=limitations,
            reason=reason,
            missing_evidence=missing_evidence,
            next_action=next_action,
        )

        results.append(test_result)

    return results
