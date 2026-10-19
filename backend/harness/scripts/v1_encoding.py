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

    try:
        # Load probe URL and check reflection
        response = await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
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
            )
        else:
            evidence = "Injected parameter not reflected in page body or attributes (no reflection sink found on target URL)."
            return TestResult(
                shortcode="V1.2.1",
                name="HTML & Attribute Output Encoding",
                status="PASS",
                severity="info",
                evidence=evidence,
                remediation="No reflected output vulnerability detected on target landing page.",
                test_hint=ctx.metadata.get("test_hint", "Inject HTML/attr/CSS/header payloads; inspect resulting DOM and headers"),
                required_inputs=ctx.metadata.get("required_inputs", ["URL", "PAY"]),
                chapter=ctx.metadata.get("chapter", "V1 Encoding and Sanitization"),
                level=ctx.metadata.get("level", 1),
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
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

    try:
        await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)

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

        duration = int((time.time() - start_time) * 1000)

        if scheme_leaks:
            evidence = f"Found {len(scheme_leaks)} DOM elements with unvalidated javascript:/data: scheme execution: {scheme_leaks}"
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
            )
        else:
            evidence = "No unvalidated javascript: or data: schemes detected in DOM hyperlinks or action attributes."
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

    try:
        await page.goto(test_url, wait_until="domcontentloaded", timeout=12000)

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

        duration = int((time.time() - start_time) * 1000)

        if breakout_detected or dangerous_inline_scripts:
            evidence = f"Script context breakout detected: Injected </script> parsed as DOM element or unescaped in script tag."
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
            )
        else:
            evidence = "Script breakout payload safely handled; no unescaped JavaScript context reflections detected."
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
        )


@register_test("V1.2.10", "Formula and CSV Injection Defense")
async def test_v1_2_10(ctx: HarnessContext) -> TestResult:
    """
    V1.2.10: Verify that the application is protected against CSV and Formula Injection.
    """
    start_time = time.time()
    page = ctx.page

    try:
        # Check if the page has export triggers or tabular exports
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
            evidence = f"Export functionality detected: {export_audit.get('exportElements')}. Values starting with =,+,-,@ require prefix neutralization."
            return TestResult(
                shortcode="V1.2.10",
                name="Formula and CSV Injection Defense",
                status="MANUAL_VERIFY",
                severity="medium",
                evidence=evidence,
                remediation="Ensure CSV/spreadsheet generator prefixes formula characters (=, +, -, @, \\t, \\r) with a single quote (') to neutralize execution in Excel/Calc.",
                test_hint=ctx.metadata.get("test_hint", "Store =,+,-,@ values; export CSV/XLSX and inspect first characters"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=3,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
            )
        else:
            evidence = "No CSV or spreadsheet export triggers identified on inspected surface."
            return TestResult(
                shortcode="V1.2.10",
                name="Formula and CSV Injection Defense",
                status="PASS",
                severity="info",
                evidence=evidence,
                remediation="No immediate CSV export risk observed on current page.",
                test_hint=ctx.metadata.get("test_hint", "Store =,+,-,@ values; export CSV/XLSX and inspect first characters"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=3,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
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
        )


@register_test("V1.3.1", "Rich-Text & HTML Input Sanitization")
async def test_v1_3_1(ctx: HarnessContext) -> TestResult:
    """
    V1.3.1: Verify that all untrusted HTML input from WYSIWYG editors is sanitized.
    """
    start_time = time.time()
    page = ctx.page

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
            )
        else:
            evidence = "No active WYSIWYG or contenteditable rich-text elements found on target interface."
            return TestResult(
                shortcode="V1.3.1",
                name="Rich-Text & HTML Input Sanitization",
                status="PASS",
                severity="info",
                evidence=evidence,
                remediation="No rich-text editor attack surface detected on inspected page.",
                test_hint=ctx.metadata.get("test_hint", "XSS payloads through rich-text/WYSIWYG editors"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=1,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
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
        )


@register_test("V1.3.4", "SVG Content Sanitization")
async def test_v1_3_4(ctx: HarnessContext) -> TestResult:
    """
    V1.3.4: Verify user-supplied SVG content is validated or sanitized.
    """
    start_time = time.time()
    page = ctx.page

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
            )
        elif svg_audit.get("fileUploads"):
            evidence = f"Found file upload inputs ({svg_audit['fileUploads']}). SVG uploads must be explicitly validated."
            return TestResult(
                shortcode="V1.3.4",
                name="SVG Content Sanitization",
                status="MANUAL_VERIFY",
                severity="info",
                evidence=evidence,
                remediation="Ensure file upload pipelines sanitize incoming SVG files and strip executable elements.",
                test_hint=ctx.metadata.get("test_hint", "Upload SVG with script/foreignObject; open it directly"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "FILES"]),
                chapter="V1 Encoding and Sanitization",
                level=2,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
            )
        else:
            evidence = f"Inspected {svg_audit.get('totalSvg', 0)} inline SVG element(s); no embedded scripts or foreignObjects found."
            return TestResult(
                shortcode="V1.3.4",
                name="SVG Content Sanitization",
                status="PASS",
                severity="info",
                evidence=evidence,
                remediation="SVG elements are free of scriptable nodes.",
                test_hint=ctx.metadata.get("test_hint", "Upload SVG with script/foreignObject; open it directly"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "FILES"]),
                chapter="V1 Encoding and Sanitization",
                level=2,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
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
        )


@register_test("V1.3.5", "Markdown & Formatted Input Sanitization")
async def test_v1_3_5(ctx: HarnessContext) -> TestResult:
    """
    V1.3.5: Verify that application sanitizes user-supplied scriptable elements in Markdown or BBCode.
    """
    start_time = time.time()
    page = ctx.page

    try:
        # Check for client-side markdown parsers (marked, markdown-it, showdown)
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
            )
        else:
            evidence = "No unvalidated client-side Markdown/BBCode parsers identified on inspected page."
            return TestResult(
                shortcode="V1.3.5",
                name="Markdown & Formatted Input Sanitization",
                status="PASS",
                severity="info",
                evidence=evidence,
                remediation="No active client-side markdown script injection sinks detected.",
                test_hint=ctx.metadata.get("test_hint", "Script payloads in Markdown/BBCode/CSS/XSL input"),
                required_inputs=ctx.metadata.get("required_inputs", ["CRED", "PAY"]),
                chapter="V1 Encoding and Sanitization",
                level=2,
                tinyfish_mode="BROWSER_SCRIPT",
                duration_ms=duration,
            )
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return TestResult(
            shortcode="V1.3.5",
            name="Markdown & Formatted Input Sanitization",
            status="ERROR",
            severity="info",
            evidence=f"Error checking markdown sanitization: {str(e)}",
            remediation="Ensure target server is reachable.",
            chapter="V1 Encoding and Sanitization",
            duration_ms=duration,
        )


async def evaluate_v1_passive_and_review_requirements(
    all_v1_reqs: List[Dict[str, Any]],
    ctx: HarnessContext,
    executed_results: Dict[str, TestResult]
) -> List[TestResult]:
    """
    Evaluates all other V1 requirements (HYBRID and REVIEW) using observable browser heuristics
    and Tinyfah.json metadata.
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
                )
            else:
                res = TestResult(
                    shortcode=sc,
                    name=desc[:50] or "Avoid Dynamic Code Execution",
                    status="PASS",
                    severity="info",
                    evidence="No dynamic eval() or Function constructor detected in inspected inline scripts.",
                    remediation="Maintain ban on dynamic code execution.",
                    test_hint=hint,
                    required_inputs=inputs,
                    chapter="V1 Encoding and Sanitization",
                    level=level,
                    tinyfish_mode=mode,
                )
        elif sc == "V1.1.1":
            if has_utf8:
                res = TestResult(
                    shortcode=sc,
                    name="Canonical Input Decoding & Charset",
                    status="PASS",
                    severity="info",
                    evidence=f"Explicit Content-Type header with character set configured: '{content_type}'.",
                    remediation="Confirm server decodes incoming payloads into canonical form exactly once.",
                    test_hint=hint,
                    required_inputs=inputs,
                    chapter="V1 Encoding and Sanitization",
                    level=level,
                    tinyfish_mode=mode,
                )
            else:
                res = TestResult(
                    shortcode=sc,
                    name="Canonical Input Decoding & Charset",
                    status="MANUAL_VERIFY",
                    severity="low",
                    evidence=f"Content-Type '{content_type}' lacks explicit charset specification. Double-decode verification recommended.",
                    remediation="Specify explicit UTF-8 charset in Content-Type header and ensure single canonical decode pass.",
                    test_hint=hint,
                    required_inputs=inputs,
                    chapter="V1 Encoding and Sanitization",
                    level=level,
                    tinyfish_mode=mode,
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
            )

        results.append(res)

    return results
