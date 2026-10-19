import time
import re
import urllib.parse
from typing import List, Dict, Any
from harness.registry import register_test, HarnessContext, TestResult

CANARY_PROBE = 'tfcanary"\'><script>alert(1)</script>'
CANARY_SAFE_PREFIX = 'tfcanary'

@register_test("V1.2.1", "HTML & Attribute Output Encoding")
async def test_v1_2_1(ctx: HarnessContext) -> TestResult:
    """
    V1.2.1: Verify that output encoding for an HTTP response or HTML document
    is relevant for the context required (HTML elements, attributes, headers).
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    parsed = urllib.parse.urlparse(target_url)
    probe_tag = f"{CANARY_SAFE_PREFIX}_tag"
    probe_val = f'{CANARY_SAFE_PREFIX}<{probe_tag}>"\'&'
    test_params = {"q": probe_val, "test": probe_val}
    test_url = urllib.parse.urljoin(
        target_url,
        f"?{urllib.parse.urlencode(test_params)}"
    )

    http_status = None
    try:
        # Load probe URL and check reflection
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        http_status = response.status if response else None
        raw_http_body = (await response.text()) if response else ""
        dom_text = await page.content()

        # Check raw unencoded reflection in HTTP response vs encoded reflection
        raw_bracket = f"{CANARY_SAFE_PREFIX}<"
        encoded_bracket = f"{CANARY_SAFE_PREFIX}&lt;"

        # Check if injected tag altered DOM structure
        tag_in_dom = await page.evaluate(f"""() => {{
            return document.getElementsByTagName('{probe_tag}').length > 0;
        }}""")

        # Also inspect DOM attributes via evaluate
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

        if is_vulnerable_raw:
            evidence = (
                f"Unescaped canary '<' reflected in HTTP response or altered DOM without HTML entity encoding. "
                f"DOM element created: {tag_in_dom}. Attribute leaks: {dom_attr_leaks if dom_attr_leaks else 'In HTTP response body'}."
            )
            return TestResult(
                shortcode="V1.2.1",
                name="HTML & Attribute Output Encoding",
                status="FAIL",
                severity="high",
                evidence=evidence,
                remediation="Ensure all user-supplied data reflected in HTML elements or attributes is passed through context-aware output encoders (e.g. &lt;, &gt;, &quot;, &#x27;).",
                test_hint=ctx.metadata.get("test_hint", "Inject HTML/attr/CSS/header payloads; inspect resulting DOM and headers"),
                required_inputs=ctx.metadata.get("required_inputs", ["URL", "PAY"]),
                chapter=ctx.metadata.get("chapter", "V1 Encoding and Sanitization"),
                level=ctx.metadata.get("level", 1),
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations=f"Canary probe '{probe_val}' reflected unescaped into response body or DOM attributes.",
                expected_behavior="Sensitive characters (<, >, \", ') must be converted to HTML entities (&lt;, &gt;, &quot;).",
            )
        elif is_encoded:
            evidence = "Canary probe was safely encoded into HTML entities (&lt;, &gt;, &quot;) before DOM rendering."
            return TestResult(
                shortcode="V1.2.1",
                name="HTML & Attribute Output Encoding",
                status="PASS",
                severity="info",
                evidence=evidence,
                remediation="Output encoding is properly applied.",
                test_hint=ctx.metadata.get("test_hint", "Inject HTML/attr/CSS/header payloads; inspect resulting DOM and headers"),
                required_inputs=ctx.metadata.get("required_inputs", ["URL", "PAY"]),
                chapter=ctx.metadata.get("chapter", "V1 Encoding and Sanitization"),
                level=ctx.metadata.get("level", 1),
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations=f"Canary probe reflected safely as '{encoded_bracket}' with HTML entity escaping.",
                expected_behavior="User input reflected in HTML elements or attributes must be safely HTML entity encoded.",
            )
        else:
            # Never assign PASS without sufficient evidence when no reflection sink was observed!
            evidence = "Injected parameter not reflected in page body or attributes (no reflection sink found on target URL)."
            return TestResult(
                shortcode="V1.2.1",
                name="HTML & Attribute Output Encoding",
                status="NOT_TESTED",
                severity="info",
                evidence=evidence,
                remediation="Verify output encoding on application pages with active user input reflection sinks.",
                test_hint=ctx.metadata.get("test_hint", "Inject HTML/attr/CSS/header payloads; inspect resulting DOM and headers"),
                required_inputs=ctx.metadata.get("required_inputs", ["URL", "PAY"]),
                chapter=ctx.metadata.get("chapter", "V1 Encoding and Sanitization"),
                level=ctx.metadata.get("level", 1),
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations="Query parameters 'q' and 'test' were sent to target URL, but their values were not reflected in the response body or DOM attributes.",
                expected_behavior="Target landing page reflects query parameter or user input into HTML body/attribute context.",
                limitations="Could not locate an active reflection sink on the public landing page to verify dynamic output encoding.",
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.2.1",
            name="HTML & Attribute Output Encoding",
            status="ERROR",
            severity="info",
            evidence=f"Test probe encountered an error: {str(e)}",
            remediation="Verify URL connectivity and retry.",
            test_hint=ctx.metadata.get("test_hint", ""),
            required_inputs=ctx.metadata.get("required_inputs", []),
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            http_status=http_status,
            execution_error=str(e),
        )


@register_test("V1.2.2", "URL Parameter Encoding & Protocol Schemes")
async def test_v1_2_2(ctx: HarnessContext) -> TestResult:
    """
    V1.2.2: Verify that when dynamically building URLs, untrusted data is encoded
    and dangerous schemes like javascript: or data: are rejected.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    probe_scheme = "javascript:/*tf_probe*/alert(1)"
    test_url = urllib.parse.urljoin(
        target_url,
        f"?redirect={urllib.parse.quote(probe_scheme)}&next={urllib.parse.quote(probe_scheme)}"
    )

    http_status = None
    try:
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        http_status = response.status if response else None

        # Inspect DOM for dangerous scheme execution sinks in href, src, action
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

        # Check if the probe was reflected in hyperlinks
        probe_reflected = await page.evaluate(f"""() => {{
            const links = document.querySelectorAll('a[href], form[action]');
            for (const el of links) {{
                const val = el.getAttribute('href') || el.getAttribute('action') || '';
                if (val.includes('tf_probe')) return true;
            }}
            return false;
        }}""")

        duration = int((time.time() - start_time) * 1000)

        if scheme_leaks:
            evidence = f"Found {len(scheme_leaks)} DOM element(s) with unvalidated javascript:/data: scheme execution: {scheme_leaks}"
            return TestResult(
                shortcode="V1.2.2",
                name="URL Parameter Encoding & Protocol Schemes",
                status="FAIL",
                severity="high",
                evidence=evidence,
                remediation="Validate URL schemes against an explicit allowlist (https:, http:, mailto:). Reject javascript: and data: pseudo-protocols.",
                test_hint=ctx.metadata.get("test_hint", "Inject javascript:/data: into URL-building params; check encoding"),
                required_inputs=ctx.metadata.get("required_inputs", ["URL", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=1,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations=f"Discovered active javascript: pseudo-protocol destinations in document links: {scheme_leaks}",
                expected_behavior="Hyperlink destinations must strictly disallow javascript: and data: schemes.",
            )
        elif probe_reflected:
            evidence = "Injected redirect parameter was reflected in link attributes with safe URL encoding or protocol scheme enforcement."
            return TestResult(
                shortcode="V1.2.2",
                name="URL Parameter Encoding & Protocol Schemes",
                status="PASS",
                severity="info",
                evidence=evidence,
                remediation="URL scheme and parameter sanitization verified.",
                test_hint=ctx.metadata.get("test_hint", "Inject javascript:/data: into URL-building params; check encoding"),
                required_inputs=ctx.metadata.get("required_inputs", ["URL", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=1,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations="Injected parameter was handled and sanitized without permitting javascript: execution.",
                expected_behavior="URL parameters used in link destinations must be safely scheme-validated.",
            )
        else:
            evidence = "No unvalidated javascript: or data: schemes detected in DOM, and no URL parameter reflection sink was found on this landing page."
            return TestResult(
                shortcode="V1.2.2",
                name="URL Parameter Encoding & Protocol Schemes",
                status="NOT_TESTED",
                severity="info",
                evidence=evidence,
                remediation="Validate URL parameters on redirect or navigation endpoints.",
                test_hint=ctx.metadata.get("test_hint", "Inject javascript:/data: into URL-building params; check encoding"),
                required_inputs=ctx.metadata.get("required_inputs", ["URL", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=1,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations="No links with injected redirect parameter were reflected on target page.",
                expected_behavior="Target page reflects or uses destination URL parameter.",
                limitations="No dynamic URL reflection sink was present on the landing page to test URL encoding.",
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.2.2",
            name="URL Parameter Encoding & Protocol Schemes",
            status="ERROR",
            severity="info",
            evidence=f"Error executing URL encoding probe: {str(e)}",
            remediation="Ensure target server is reachable.",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            http_status=http_status,
            execution_error=str(e),
        )


@register_test("V1.2.3", "JavaScript Context Encoding & Script Breakouts")
async def test_v1_2_3(ctx: HarnessContext) -> TestResult:
    """
    V1.2.3: Verify that output encoding or escaping is used when dynamically building
    JavaScript or JSON context data.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    breakout_payload = '</script><tf_breakout_test>'
    test_url = urllib.parse.urljoin(
        target_url,
        f"?data={urllib.parse.quote(breakout_payload)}"
    )

    http_status = None
    try:
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        http_status = response.status if response else None

        # Inspect if breakout succeeded into a new DOM node
        breakout_detected = await page.evaluate("""() => {
            return document.getElementsByTagName('tf_breakout_test').length > 0;
        }""")

        # Also inspect inline script tags for raw quotes or unescaped JSON assignments
        dangerous_inline_scripts = await page.evaluate("""() => {
            const scripts = Array.from(document.querySelectorAll('script:not([src])'));
            const issues = [];
            for (const s of scripts) {
                const text = s.textContent || '';
                if (text.includes('tf_breakout_test') && !text.includes('\\\\/script>')) {
                    issues.push(text.slice(0, 100));
                }
            }
            return issues;
        }""")

        # Check if probe was reflected in any script
        probe_in_scripts = await page.evaluate("""() => {
            const scripts = Array.from(document.querySelectorAll('script:not([src])'));
            return scripts.some(s => (s.textContent || '').includes('tf_breakout_test'));
        }""")

        duration = int((time.time() - start_time) * 1000)

        if breakout_detected or dangerous_inline_scripts:
            evidence = "Script context breakout detected: Injected </script> parsed as DOM element or unescaped in script tag."
            return TestResult(
                shortcode="V1.2.3",
                name="JavaScript Context Encoding & Script Breakouts",
                status="FAIL",
                severity="high",
                evidence=evidence,
                remediation="Ensure user-supplied variables placed into script contexts are safely serialized using Unicode escapes (e.g. \\u003c instead of <) or embedded in JSON script blocks.",
                test_hint=ctx.metadata.get("test_hint", "Inject quote/script breakouts into JS and JSON contexts"),
                required_inputs=ctx.metadata.get("required_inputs", ["URL", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=1,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations="Breakout payload broke out of JavaScript context into DOM structure.",
                expected_behavior="Data embedded in script blocks must escape </script> sequences.",
            )
        elif probe_in_scripts:
            evidence = "Script breakout payload safely escaped inside inline JavaScript context."
            return TestResult(
                shortcode="V1.2.3",
                name="JavaScript Context Encoding & Script Breakouts",
                status="PASS",
                severity="info",
                evidence=evidence,
                remediation="JavaScript context output encoding verified.",
                test_hint=ctx.metadata.get("test_hint", "Inject quote/script breakouts into JS and JSON contexts"),
                required_inputs=ctx.metadata.get("required_inputs", ["URL", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=1,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations="Parameter reflected inside inline script with safe Unicode/slash escaping.",
                expected_behavior="Injected script breakout tags must be neutralized.",
            )
        else:
            evidence = "No reflection of injected parameters detected inside inline JavaScript contexts on target landing page."
            return TestResult(
                shortcode="V1.2.3",
                name="JavaScript Context Encoding & Script Breakouts",
                status="NOT_TESTED",
                severity="info",
                evidence=evidence,
                remediation="Test JS context encoding on endpoints that serialize state into window variables.",
                test_hint=ctx.metadata.get("test_hint", "Inject quote/script breakouts into JS and JSON contexts"),
                required_inputs=ctx.metadata.get("required_inputs", ["URL", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=1,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                http_status=http_status,
                observations="Probe parameter 'data' was not reflected into any inline script tags or JSON state.",
                expected_behavior="Page reflects user input into client-side JavaScript execution context.",
                limitations="No dynamic JS reflection sink was present on this page to evaluate script breakouts.",
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.2.3",
            name="JavaScript Context Encoding & Script Breakouts",
            status="ERROR",
            severity="info",
            evidence=f"Error running JS context probe: {str(e)}",
            remediation="Ensure target server is reachable.",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            http_status=http_status,
            execution_error=str(e),
        )


@register_test("V1.2.10", "Formula and CSV Injection Defense")
async def test_v1_2_10(ctx: HarnessContext) -> TestResult:
    """
    V1.2.10: Verify that the application is protected against CSV and Formula Injection.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    http_status = None
    try:
        export_audit = await page.evaluate("""() => {
            const exportElements = Array.from(document.querySelectorAll('a, button, input[type="submit"]'))
                .filter(el => {
                    const text = (el.textContent || el.value || el.getAttribute('download') || el.getAttribute('href') || '').toLowerCase();
                    return text.includes('csv') || text.includes('export') || text.includes('excel') || text.includes('xlsx');
                })
                .map(el => el.textContent.trim() || el.getAttribute('href') || 'Export Element');
            return {
                hasExport: exportElements.length > 0,
                exportElements: exportElements.slice(0, 5)
            };
        }""")

        duration = int((time.time() - start_time) * 1000)

        if export_audit.get("hasExport"):
            evidence = f"Found potential export trigger(s): {export_audit['exportElements']}. Formula injection verification recommended."
            return TestResult(
                shortcode="V1.2.10",
                name="Formula and CSV Injection Defense",
                status="MANUAL_VERIFY",
                severity="medium",
                evidence=evidence,
                remediation="Ensure all fields exported to CSV/Excel prepend a tab, space, or apostrophe (') to any cell beginning with '=', '+', '-', or '@'.",
                test_hint=ctx.metadata.get("test_hint", "Store =,+,-,@ values; export CSV/XLSX and inspect first characters"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=3,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                observations=f"Export triggers identified on page: {export_audit['exportElements']}.",
                expected_behavior="Exported spreadsheet files must neutralize leading formula control characters.",
                limitations="Actual CSV download generation requires authenticated form submissions.",
            )
        else:
            evidence = "No CSV or spreadsheet export triggers identified on inspected landing page surface."
            return TestResult(
                shortcode="V1.2.10",
                name="Formula and CSV Injection Defense",
                status="NOT_TESTED",
                severity="info",
                evidence=evidence,
                remediation="If CSV/spreadsheet export features exist in internal application workflows, verify formula neutralization.",
                test_hint=ctx.metadata.get("test_hint", "Store =,+,-,@ values; export CSV/XLSX and inspect first characters"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=3,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                observations="No export buttons, CSV links, or spreadsheet download actions detected on page.",
                expected_behavior="Target page contains spreadsheet export functionality.",
                limitations="CSV export feature not present on public landing page.",
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.2.10",
            name="Formula and CSV Injection Defense",
            status="ERROR",
            severity="info",
            evidence=f"Error executing CSV audit: {str(e)}",
            remediation="Ensure target server is reachable.",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )


@register_test("V1.3.1", "Rich-Text & HTML Input Sanitization")
async def test_v1_3_1(ctx: HarnessContext) -> TestResult:
    """
    V1.3.1: Verify that all untrusted HTML input from WYSIWYG editors is sanitized.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    try:
        editor_audit = await page.evaluate("""() => {
            const editors = document.querySelectorAll(
                '[contenteditable="true"], .ql-editor, .tox-edit-area, .note-editable, div[role="textbox"]'
            );
            return {
                foundCount: editors.length,
                tags: Array.from(editors).map(e => e.tagName)
            };
        }""")

        duration = int((time.time() - start_time) * 1000)

        if editor_audit.get("foundCount", 0) > 0:
            evidence = f"Detected {editor_audit['foundCount']} rich-text/WYSIWYG editor container(s) ({editor_audit['tags']}). Sanitization library (e.g. DOMPurify) required before rendering."
            return TestResult(
                shortcode="V1.3.1",
                name="Rich-Text & HTML Input Sanitization",
                status="MANUAL_VERIFY",
                severity="medium",
                evidence=evidence,
                remediation="Ensure all rich-text input is sanitized on both client and server sides with an allowlist sanitizer (such as DOMPurify) with USE_PROFILES: {html: true}.",
                test_hint=ctx.metadata.get("test_hint", "XSS payloads through rich-text/WYSIWYG editors"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=1,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                observations=f"Rich-text editor containers present on page: {editor_audit['tags']}.",
                expected_behavior="Rich-text content must be sanitized with strict HTML allowlists.",
                limitations="Manual verification required to inject and persist rich-text formatting payloads.",
            )
        else:
            evidence = "No active WYSIWYG or contenteditable rich-text elements found on target interface."
            return TestResult(
                shortcode="V1.3.1",
                name="Rich-Text & HTML Input Sanitization",
                status="NOT_TESTED",
                severity="info",
                evidence=evidence,
                remediation="Ensure rich-text sanitization is tested on administrative or comment posting pages with WYSIWYG editors.",
                test_hint=ctx.metadata.get("test_hint", "XSS payloads through rich-text/WYSIWYG editors"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=1,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                observations="No contenteditable elements, TinyMCE, Quill, or CKEditor instances detected.",
                expected_behavior="Page contains rich-text/WYSIWYG editor elements.",
                limitations="No rich-text input interface on public landing page.",
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.3.1",
            name="Rich-Text & HTML Input Sanitization",
            status="ERROR",
            severity="info",
            evidence=f"Error auditing rich-text editors: {str(e)}",
            remediation="Ensure target server is reachable.",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )


@register_test("V1.3.4", "SVG Content Sanitization")
async def test_v1_3_4(ctx: HarnessContext) -> TestResult:
    """
    V1.3.4: Verify user-supplied SVG content is validated or sanitized.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    try:
        svg_audit = await page.evaluate("""() => {
            const svgElements = document.querySelectorAll('svg');
            let dangerousSvg = 0;
            for (const s of svgElements) {
                if (s.querySelector('script') || s.querySelector('foreignObject')) {
                    dangerousSvg++;
                }
            }
            const fileInputs = Array.from(document.querySelectorAll('input[type="file"]'))
                .map(i => i.accept || 'any');
            return {
                totalSvg: svgElements.length,
                dangerousSvg: dangerousSvg,
                fileUploads: fileInputs
            };
        }""")

        duration = int((time.time() - start_time) * 1000)

        if svg_audit.get("dangerousSvg", 0) > 0:
            evidence = f"Detected {svg_audit['dangerousSvg']} SVG element(s) with embedded <script> or <foreignObject>."
            return TestResult(
                shortcode="V1.3.4",
                name="SVG Content Sanitization",
                status="FAIL",
                severity="high",
                evidence=evidence,
                remediation="Sanitize user-uploaded SVGs or serve them with 'Content-Security-Policy: default-src 'none'' and 'Content-Type: image/svg+xml' or convert to raster images (PNG/WebP).",
                test_hint=ctx.metadata.get("test_hint", "Upload SVG with script/foreignObject; open it directly"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "FILES"]),
                chapter="V1 Encoding and Sanitization",
                level=2,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                observations=f"Found scriptable tags in SVG elements on the page.",
                expected_behavior="SVG elements must strip script tags, handlers, and foreignObjects.",
            )
        elif svg_audit.get("fileUploads"):
            evidence = f"Found file upload inputs ({svg_audit['fileUploads']}). SVG uploads must be explicitly validated and sanitized."
            return TestResult(
                shortcode="V1.3.4",
                name="SVG Content Sanitization",
                status="MANUAL_VERIFY",
                severity="medium",
                evidence=evidence,
                remediation="Ensure file upload pipelines sanitize incoming SVG files and strip executable elements.",
                test_hint=ctx.metadata.get("test_hint", "Upload SVG with script/foreignObject; open it directly"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "FILES"]),
                chapter="V1 Encoding and Sanitization",
                level=2,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                observations=f"File upload inputs found on target page: {svg_audit['fileUploads']}.",
                expected_behavior="Uploaded SVG files must be sanitized before being stored or served.",
                limitations="Upload and rendering of a test SVG payload requires authenticated multipart submission.",
            )
        else:
            evidence = f"Inspected {svg_audit.get('totalSvg', 0)} static SVG element(s); no user-controllable SVG upload sinks present on landing page."
            return TestResult(
                shortcode="V1.3.4",
                name="SVG Content Sanitization",
                status="NOT_TESTED",
                severity="info",
                evidence=evidence,
                remediation="Audit file upload workflows that accept SVG avatars or graphics.",
                test_hint=ctx.metadata.get("test_hint", "Upload SVG with script/foreignObject; open it directly"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "FILES"]),
                chapter="V1 Encoding and Sanitization",
                level=2,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                observations=f"Page has {svg_audit.get('totalSvg', 0)} static SVG elements and no file upload fields.",
                expected_behavior="Target page supports user-supplied SVG uploads.",
                limitations="Requirement ASVS V1.3.4 requires user-supplied SVG upload endpoints.",
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.3.4",
            name="SVG Content Sanitization",
            status="ERROR",
            severity="info",
            evidence=f"Error inspecting SVG content: {str(e)}",
            remediation="Ensure target server is reachable.",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )


@register_test("V1.3.5", "Markdown & Formatted Input Sanitization")
async def test_v1_3_5(ctx: HarnessContext) -> TestResult:
    """
    V1.3.5: Verify that application sanitizes user-supplied scriptable elements in Markdown or BBCode.
    """
    start_time = time.time()
    page = ctx.page
    target_url = ctx.target_url

    try:
        md_audit = await page.evaluate("""() => {
            const hasMarked = typeof window.marked !== 'undefined';
            const hasShowdown = typeof window.showdown !== 'undefined';
            const hasMarkdownIt = typeof window.markdownit !== 'undefined';
            return {
                detectedParser: hasMarked ? 'marked' : hasShowdown ? 'showdown' : hasMarkdownIt ? 'markdown-it' : null
            };
        }""")

        duration = int((time.time() - start_time) * 1000)

        if md_audit.get("detectedParser"):
            evidence = f"Client-side Markdown parser '{md_audit['detectedParser']}' detected in global window context. Verify HTML sanitization option is enabled."
            return TestResult(
                shortcode="V1.3.5",
                name="Markdown & Formatted Input Sanitization",
                status="MANUAL_VERIFY",
                severity="medium",
                evidence=evidence,
                remediation="Configure the Markdown parser to disable raw HTML or pipe output through DOMPurify.",
                test_hint=ctx.metadata.get("test_hint", "Script payloads in Markdown/BBCode/CSS/XSL input"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=2,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                observations=f"Markdown rendering library '{md_audit['detectedParser']}' found in global window context.",
                expected_behavior="Client-side Markdown parser must sanitize raw HTML syntax and javascript: schemes.",
                limitations="Manual verification required with interactive Markdown editing fields.",
            )
        else:
            evidence = "No client-side Markdown or BBCode input sinks detected on public landing page."
            return TestResult(
                shortcode="V1.3.5",
                name="Markdown & Formatted Input Sanitization",
                status="NOT_TESTED",
                severity="info",
                evidence=evidence,
                remediation="Verify Markdown and BBCode sanitization on documentation, blog, or forum editors.",
                test_hint=ctx.metadata.get("test_hint", "Script payloads in Markdown/BBCode/CSS/XSL input"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=2,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
                target_url=target_url,
                observations="No Markdown parsing libraries (marked, showdown, markdown-it) detected in window context.",
                expected_behavior="Page contains Markdown/BBCode parsing features.",
                limitations="No Markdown parser attack surface detected on inspected landing page.",
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.3.5",
            name="Markdown & Formatted Input Sanitization",
            status="ERROR",
            severity="info",
            evidence=f"Error inspecting Markdown parsers: {str(e)}",
            remediation="Ensure target server is reachable.",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
            target_url=target_url,
            execution_error=str(e),
        )


async def evaluate_v1_passive_and_review_requirements(
    all_v1_reqs: List[Dict[str, Any]],
    ctx: HarnessContext,
    executed_results: Dict[str, TestResult],
) -> List[TestResult]:
    """
    Evaluates remaining Chapter V1 requirements using static DOM/code heuristics
    or assigns structured manual verification guidance.
    """
    page = ctx.page
    headers = {k.lower(): v for k, v in ctx.doc_headers.items()}
    results: List[TestResult] = []

    # Check for eval() usage in page scripts (V1.3.2)
    eval_check = False
    try:
        eval_check = await page.evaluate("""() => {
            const scripts = Array.from(document.querySelectorAll('script:not([src])'));
            return scripts.some(s => {
                const text = s.textContent || '';
                return /\\beval\\s*\\(/.test(text) || /new\\s+Function\\s*\\(/.test(text);
            });
        }""")
    except Exception:
        pass

    content_type = headers.get("content-type", "")
    has_utf8 = "charset" in content_type.lower()

    for req in all_v1_reqs:
        sc = req.get("shortcode", "")
        if sc in executed_results:
            continue  # Already executed as a deterministic browser script

        mode = req.get("tinyfish_mode", "HYBRID")
        hint = req.get("test_hint", "")
        inputs = req.get("required_inputs", [])
        desc = req.get("description", "")
        level = req.get("level", 1)

        # Dynamic heuristic overrides:
        if sc == "V1.3.2":
            if eval_check:
                res = TestResult(
                    shortcode=sc,
                    name=desc[:50] or "Avoid Dynamic Code Execution",
                    status="FAIL",
                    severity="high",
                    evidence="Inline script tag uses eval() or new Function() for dynamic code execution.",
                    remediation="Refactor code to avoid dynamic JavaScript code evaluation (eval / Function constructor).",
                    test_hint=hint,
                    required_inputs=inputs,
                    chapter="V1 Encoding and Sanitization",
                    level=level,
                    tinyfish_mode=mode,
                    target_url=ctx.target_url,
                    observations="Inline script contains eval() or new Function() call.",
                    expected_behavior="Application code must not invoke dynamic string evaluation.",
                )
            else:
                res = TestResult(
                    shortcode=sc,
                    name=desc[:50] or "Avoid Dynamic Code Execution",
                    status="PASS",
                    severity="info",
                    evidence="No dynamic eval() or Function constructor detected in inspected inline script tags.",
                    remediation="Maintain ban on dynamic code execution.",
                    test_hint=hint,
                    required_inputs=inputs,
                    chapter="V1 Encoding and Sanitization",
                    level=level,
                    tinyfish_mode=mode,
                    target_url=ctx.target_url,
                    observations="Inspected inline script elements; no dynamic code evaluation found.",
                    expected_behavior="Inline scripts must not execute eval() or new Function().",
                    limitations="Evaluated inline scripts; external JavaScript bundles require source code review.",
                )
        elif sc == "V1.1.1":
            # Explicit charset in Content-Type is relevant, but canonical decoding requires manual/backend review
            res = TestResult(
                shortcode=sc,
                name="Canonical Input Decoding & Charset",
                status="MANUAL_VERIFY",
                severity="info",
                evidence=f"Content-Type is '{content_type}'. Canonical single-pass input decoding must be verified in server-side request pipelines.",
                remediation="Specify explicit UTF-8 charset in Content-Type header and verify server decodes incoming payloads into canonical form exactly once.",
                test_hint=hint,
                required_inputs=inputs,
                chapter="V1 Encoding and Sanitization",
                level=level,
                tinyfish_mode=mode,
                target_url=ctx.target_url,
                observations=f"Content-Type: '{content_type}'.",
                expected_behavior="Server decodes all inputs to canonical representation exactly once before validation.",
                limitations="Server-side canonical decoding cannot be definitively proven by passive response inspection alone.",
            )
        else:
            # Standard structured manual verification item
            res = TestResult(
                shortcode=sc,
                name=desc[:60] if desc else f"Requirement {sc}",
                status="MANUAL_VERIFY",
                severity="info",
                evidence=f"Requirement requires non-browser inputs ({', '.join(inputs)}) or deep application flow: {hint}",
                remediation=f"Consult OWASP ASVS {sc} recommendations: {desc}",
                test_hint=hint,
                required_inputs=inputs,
                chapter="V1 Encoding and Sanitization",
                level=level,
                tinyfish_mode=mode,
                target_url=ctx.target_url,
                expected_behavior=desc,
                limitations=f"Requires {', '.join(inputs)} or architecture documentation.",
            )

        results.append(res)

    return results
