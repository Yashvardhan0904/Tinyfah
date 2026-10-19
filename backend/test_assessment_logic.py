import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

# Add backend directory to sys.path
BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from checks import evaluate_asvs_requirements, deduplicate_findings, REQUIRED_HEADERS
from harness.registry import (
    TestResult,
    HarnessContext,
    TestCaseExecution,
    ScriptDefinition,
    get_script_definition,
    list_script_definitions,
)
from harness.reporter import calculate_score_and_grade, generate_site_report
from harness.scripts.v1_encoding import test_v1_3_7, evaluate_v1_passive_and_review_requirements
from scanner import validate_target_scope
from agent_harness import ASVSTestItem, FindingItem, GeminiSecurityReport


class TestAssessmentLogic(unittest.IsolatedAsyncioTestCase):

    # -------------------------------------------------------------------------
    # 1. Empty Scans
    # -------------------------------------------------------------------------
    def test_empty_scan_checks(self):
        """Empty requirement list must return score: None and grade: NOT_ASSESSED."""
        res = evaluate_asvs_requirements(
            requirements=[],
            headers={},
            cookies=[],
            dom_data={},
            cdp_issues=[],
            protocol="https:",
        )
        self.assertIsNone(res["score"])
        self.assertEqual(res["grade"], "NOT_ASSESSED")
        self.assertEqual(res["coverage_percentage"], 0.0)
        self.assertEqual(len(res["asvs_results"]), 0)
        self.assertEqual(len(res["findings"]), 0)

    async def test_empty_scan_reporter(self):
        """Reporter with empty test results must return score: None, grade: NOT_ASSESSED, status: not_assessed."""
        score, grade = calculate_score_and_grade([])
        self.assertIsNone(score)
        self.assertEqual(grade, "NOT_ASSESSED")

        report = await generate_site_report(
            target_url="https://example.com",
            results=[],
            raw_headers={},
            use_ai_synthesis=False,
        )
        self.assertIsNone(report["score"])
        self.assertEqual(report["grade"], "NOT_ASSESSED")
        self.assertEqual(report["scan_status"], "not_assessed")
        self.assertEqual(report["coverage_percentage"], 0.0)
        self.assertIsNone(report["pass_rate_percentage"])

    # -------------------------------------------------------------------------
    # 2. Valid PASS and FAIL Results
    # -------------------------------------------------------------------------
    def test_valid_pass_and_fail_checks(self):
        """Verify valid PASS for TLS on HTTPS and FAIL for missing Content-Type."""
        reqs = [
            {"requirement_id": "V12.1.1", "chapter_code": "V12", "description": "Verify TLS protocol versions"},
            {"requirement_id": "V4.1.1", "chapter_code": "V4", "description": "Verify Content-Type header"},
        ]
        # Case A: HTTPS with Content-Type -> both pass
        res_pass = evaluate_asvs_requirements(
            requirements=reqs,
            headers={"content-type": "text/html; charset=utf-8"},
            cookies=[],
            dom_data={},
            cdp_issues=[],
            protocol="https:",
        )
        self.assertEqual(res_pass["score"], 100)
        self.assertEqual(res_pass["grade"], "A")
        self.assertEqual(res_pass["asvs_results"][0]["status"], "PASS")
        self.assertEqual(res_pass["asvs_results"][1]["status"], "PASS")

        # Case B: HTTP without Content-Type -> both fail
        res_fail = evaluate_asvs_requirements(
            requirements=reqs,
            headers={},
            cookies=[],
            dom_data={},
            cdp_issues=[],
            protocol="http:",
        )
        self.assertEqual(res_fail["asvs_results"][0]["status"], "FAIL")
        self.assertEqual(res_fail["asvs_results"][1]["status"], "FAIL")
        self.assertLess(res_fail["score"], 70)
        self.assertIn("Insecure HTTP connection", res_fail["findings"][0]["detail"])

    # -------------------------------------------------------------------------
    # 3. Incorrect ASVS Mappings & HSTS vs TLS Distinction
    # -------------------------------------------------------------------------
    def test_hsts_vs_tls_mapping(self):
        """HSTS header check must map to V3.4.1 and must NOT cause TLS (V12.1.1) to fail."""
        self.assertEqual(REQUIRED_HEADERS["strict-transport-security"]["asvs"], "V3.4.1")

        reqs = [
            {"requirement_id": "V12.1.1", "chapter_code": "V12", "description": "Verify TLS protocol versions"},
            {"requirement_id": "V3.4.1", "chapter_code": "V3", "description": "Verify Strict-Transport-Security header"},
        ]

        # HTTPS site WITHOUT HSTS header
        res = evaluate_asvs_requirements(
            requirements=reqs,
            headers={"content-type": "text/html"},
            cookies=[],
            dom_data={},
            cdp_issues=[],
            protocol="https:",
        )

        v12_result = next(r for r in res["asvs_results"] if r["requirement_id"] == "V12.1.1")
        v3_result = next(r for r in res["asvs_results"] if r["requirement_id"] == "V3.4.1")

        # V12.1.1 (TLS) must PASS because connection is HTTPS
        self.assertEqual(v12_result["status"], "PASS")
        self.assertIn("TLS encryption active", v12_result["evidence"])

        # V3.4.1 (HSTS) must FAIL because header is missing
        self.assertEqual(v3_result["status"], "FAIL")
        self.assertIn("Strict-Transport-Security (HSTS) header is missing", v3_result["evidence"])

    def test_forms_not_confused_with_encoding(self):
        """Insecure forms must NOT fail or pass Chapter V1 encoding requirements."""
        reqs = [
            {"requirement_id": "V1.1.1", "chapter_code": "V1", "description": "Verify input encoding and sanitization"},
        ]
        # Insecure form present
        res = evaluate_asvs_requirements(
            requirements=reqs,
            headers={},
            cookies=[],
            dom_data={"insecureForms": ["http://insecure.test/login"]},
            cdp_issues=[],
            protocol="https:",
        )
        v1_result = res["asvs_results"][0]
        # Passive check cannot establish encoding compliance: must be NOT_TESTED, not PASS/FAIL
        self.assertEqual(v1_result["status"], "NOT_TESTED")
        # Insecure form finding should be mapped to transport (V12.2.1), not V1
        form_finding = next((f for f in res["findings"] if f.get("type") == "form"), None)
        self.assertIsNotNone(form_finding)
        self.assertIn("V12.2.1", form_finding.get("requirement_ids", []))

    # -------------------------------------------------------------------------
    # 4. Missing Evidence
    # -------------------------------------------------------------------------
    def test_never_pass_cookies_without_evidence(self):
        """When 0 cookies are observed, V7.1.1 must be NOT_TESTED, never PASS."""
        reqs = [{"requirement_id": "V7.1.1", "chapter_code": "V7", "description": "Session cookies"}]
        res = evaluate_asvs_requirements(
            requirements=reqs,
            headers={},
            cookies=[],  # No cookies set
            dom_data={},
            cdp_issues=[],
            protocol="https:",
        )
        self.assertEqual(res["asvs_results"][0]["status"], "NOT_TESTED")
        self.assertIn("No cookies were observed", res["asvs_results"][0]["evidence"])

    def test_v1_encoding_missing_reflection_sink(self):
        """When canary probe is not reflected in page, status must be NOT_TESTED, not PASS."""
        r = TestResult(
            shortcode="V1.2.1",
            name="HTML & Attribute Output Encoding",
            status="NOT_TESTED",
            severity="info",
            evidence="Injected parameter not reflected in page body or attributes (no reflection sink found on target URL).",
            remediation="Verify on pages with user reflection.",
            limitations="No reflection sink detected.",
        )
        self.assertEqual(r.status, "NOT_TESTED")
        self.assertNotEqual(r.status, "PASS")

    # -------------------------------------------------------------------------
    # 5. Gemini and Browser Failures
    # -------------------------------------------------------------------------
    async def test_gemini_failure_transparent_fallback(self):
        """When Gemini model invocation fails, fallback report must explicitly flag AI failure."""
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value={
            "title": "Test Page",
            "url": "https://example.com",
            "protocol": "https:",
            "formCount": 0,
            "externalScriptCount": 0,
            "metaTags": [],
        })
        mock_cdp = AsyncMock()
        mock_cdp.send = AsyncMock(return_value={"cookies": []})

        with patch("agent_harness.client") as mock_client:
            # Simulate Gemini throwing 404 / ClientError
            mock_client.aio.models.generate_content.side_effect = Exception("404 NOT_FOUND: model deprecated")

            from agent_harness import run_gemini_security_harness
            report = await run_gemini_security_harness(
                page=mock_page,
                cdp=mock_cdp,
                doc_headers={"content-type": "text/html; charset=utf-8"},
                cdp_issues=[],
                asvs_requirements=[
                    {"requirement_id": "V4.1.1", "chapter_code": "V4", "description": "Content-Type"}
                ],
            )

            self.assertFalse(report["is_ai_synthesized"])
            self.assertEqual(report["ai_assessment_status"], "FAILED")
            self.assertIn("404 NOT_FOUND", report["ai_error"])
            self.assertIn("AI reasoning/synthesis was unavailable", report["summary"])

    # -------------------------------------------------------------------------
    # 6. Duplicate Findings Deduplication
    # -------------------------------------------------------------------------
    def test_deduplicate_findings(self):
        """Identical findings must be deduplicated while preserving all evidence and valid ASVS mappings."""
        raw_findings = [
            {
                "type": "header",
                "detail": "Missing Content-Security-Policy (CSP)",
                "asvs": "V3.1.1",
                "evidence": "No CSP header present in response.",
                "severity": "medium",
            },
            {
                "type": "header",
                "detail": "Missing Content-Security-Policy (CSP)",
                "asvs": "V3.4.2",
                "evidence": "Directive script-src not defined.",
                "severity": "high",
            },
            {
                "type": "cookie",
                "detail": "Insecure cookie flags",
                "asvs": "V7.1.1",
                "evidence": "Cookie 'sess' missing HttpOnly.",
                "severity": "medium",
            },
        ]
        deduped = deduplicate_findings(raw_findings)
        self.assertEqual(len(deduped), 2)  # 1 CSP + 1 Cookie

        csp_finding = next(f for f in deduped if "Content-Security-Policy" in f["detail"])
        self.assertIn("V3.1.1", csp_finding["requirement_ids"])
        self.assertIn("V3.4.2", csp_finding["requirement_ids"])
        self.assertIn("No CSP header present in response.", csp_finding["evidence"])
        self.assertIn("Directive script-src not defined.", csp_finding["evidence"])

    # -------------------------------------------------------------------------
    # 7. Partial Scans and Scoring
    # -------------------------------------------------------------------------
    async def test_partial_scans_and_scoring(self):
        """Coverage and compliance must be separate. Errors and untested items must not count as PASS."""
        results = [
            TestResult(shortcode="V1.2.1", name="HTML Encoding", status="PASS", severity="info", evidence="Encoded"),
            TestResult(shortcode="V1.2.2", name="URL Encoding", status="FAIL", severity="high", evidence="Unencoded javascript:"),
            TestResult(shortcode="V1.2.3", name="JS Breakout", status="NOT_TESTED", severity="info", evidence="No sink"),
            TestResult(shortcode="V1.2.10", name="CSV Injection", status="ERROR", severity="info", evidence="Timeout after 25s"),
        ]
        # Total = 4, Evaluated = 2 (PASS, FAIL), Untested = 1, Error = 1
        # Coverage = 2/4 * 100 = 50.0%
        # High FAIL deduction = -25 -> Compliance Score = 75 (Grade B)
        # Scan status should be "partial" because an ERROR occurred
        report = await generate_site_report(
            target_url="http://example.com",
            results=results,
            raw_headers={},
            use_ai_synthesis=False,
        )

        self.assertEqual(report["metrics"]["total_requirements"], 4)
        self.assertEqual(report["metrics"]["total_evaluated"], 2)
        self.assertEqual(report["metrics"]["passed"], 1)
        self.assertEqual(report["metrics"]["failed"], 1)
        self.assertEqual(report["metrics"]["not_tested"], 1)
        self.assertEqual(report["metrics"]["errors"], 1)
        self.assertEqual(report["coverage_percentage"], 50.0)
        self.assertEqual(report["pass_rate_percentage"], 50.0)
        self.assertEqual(report["score"], 75)
        self.assertEqual(report["grade"], "B")
        self.assertEqual(report["scan_status"], "partial")

    # -------------------------------------------------------------------------
    # 8. Out-of-Scope Target Rejection
    # -------------------------------------------------------------------------
    def test_out_of_scope_target_rejection(self):
        """Validate target scope rejects non-HTTP schemes and metadata IPs."""
        # Allowed
        valid_http, _ = validate_target_scope("http://localhost:8001/test")
        self.assertTrue(valid_http)
        valid_https, _ = validate_target_scope("https://example.com/app")
        self.assertTrue(valid_https)

        # Disallowed schemes
        ftp_valid, err_ftp = validate_target_scope("ftp://ftp.example.com/file")
        self.assertFalse(ftp_valid)
        self.assertIn("Unsupported scheme 'ftp'", err_ftp)

        file_valid, err_file = validate_target_scope("file:///etc/passwd")
        self.assertFalse(file_valid)
        self.assertIn("Unsupported scheme 'file'", err_file)

        js_valid, err_js = validate_target_scope("javascript:alert(1)")
        self.assertFalse(js_valid)
        self.assertIn("Unsupported scheme", err_js)

        # Disallowed metadata IPs
        meta_valid, err_meta = validate_target_scope("http://169.254.169.254/latest/meta-data")
        self.assertFalse(meta_valid)
        self.assertIn("cloud metadata endpoint", err_meta)

        gcp_meta_valid, err_gcp = validate_target_scope("http://metadata.google.internal/computeMetadata/v1/")
        self.assertFalse(gcp_meta_valid)
        self.assertIn("cloud metadata endpoint", err_gcp)

        # Empty hostname
        empty_valid, err_empty = validate_target_scope("http://")
        self.assertFalse(empty_valid)
        self.assertIn("missing a valid hostname", err_empty)

    # -------------------------------------------------------------------------
    # 9. Screenshots Facility via Browser API CDP Session & Schema Consistency
    # -------------------------------------------------------------------------
    def test_screenshot_schemas_serialization(self):
        """TestResult, ASVSTestItem, FindingItem, and GeminiSecurityReport schemas must support screenshot."""
        sample_screenshot = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

        # TestResult dataclass & to_dict
        res = TestResult(
            shortcode="V1.2.1",
            name="Verify Context-Aware HTML Encoding",
            status="FAIL",
            severity="high",
            evidence="Canary probe <tinyfah-canary-v1> was reflected unencoded",
            screenshot=sample_screenshot,
        )
        res_dict = res.to_dict()
        self.assertIn("screenshot", res_dict)
        self.assertTrue(res_dict["screenshot"].endswith(".png"))
        self.assertTrue((Path(__file__).resolve().parent / "screenshots" / res_dict["screenshot"]).is_file())

        # ASVSTestItem Pydantic schema
        asvs_item = ASVSTestItem(
            requirement_id="V1.2.1",
            chapter_code="V1",
            chapter_name="Encoding and Sanitization",
            status="FAIL",
            severity="high",
            evidence="Probe reflected",
            remediation="HTML encode dynamic variables",
            screenshot=sample_screenshot,
        )
        self.assertEqual(asvs_item.screenshot, sample_screenshot)
        self.assertIn("screenshot", asvs_item.model_dump())

        # FindingItem Pydantic schema
        finding_item = FindingItem(
            severity="high",
            category="Encoding",
            title="Reflected XSS Vulnerability",
            evidence="Probe reflected unescaped",
            remediation="Sanitize input",
            screenshot=sample_screenshot,
        )
        self.assertEqual(finding_item.screenshot, sample_screenshot)
        self.assertIn("screenshot", finding_item.model_dump())

        # GeminiSecurityReport Pydantic schema
        report_item = GeminiSecurityReport(
            score=75,
            grade="B",
            summary="Audit completed",
            asvs_results=[asvs_item],
            findings=[finding_item],
            screenshot=sample_screenshot,
        )
        self.assertEqual(report_item.screenshot, sample_screenshot)
        self.assertIn("screenshot", report_item.model_dump())

    async def test_harness_context_capture_screenshot_cdp(self):
        """HarnessContext must use CDP session (Page.enable & Page.captureScreenshot), falling back to page.screenshot."""
        sample_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

        # Case A: Successful CDP capture
        mock_cdp = AsyncMock()
        mock_cdp.send.side_effect = lambda cmd, args=None: (
            {"data": sample_b64} if cmd == "Page.captureScreenshot" else {}
        )
        ctx = HarnessContext(
            page=None,
            cdp=mock_cdp,
            target_url="https://example.com",
            doc_headers={},
            cdp_issues=[],
        )
        screenshot_data = await ctx.capture_screenshot()
        self.assertTrue(screenshot_data.endswith(".png"))
        self.assertTrue((Path(__file__).resolve().parent / "screenshots" / screenshot_data).is_file())
        mock_cdp.send.assert_any_call("Page.enable")
        mock_cdp.send.assert_any_call("Page.captureScreenshot", {"format": "png"})

        # Case B: CDP failure falls back to page.screenshot
        mock_failing_cdp = AsyncMock()
        mock_failing_cdp.send.side_effect = RuntimeError("CDP command failed")
        mock_page = AsyncMock()
        mock_page.screenshot.return_value = b"\x89PNG\r\n\x1a\n\x00mockdata"
        ctx_fallback = HarnessContext(
            page=mock_page,
            cdp=mock_failing_cdp,
            target_url="https://example.com",
            doc_headers={},
            cdp_issues=[],
        )
        screenshot_fallback = await ctx_fallback.capture_screenshot()
        self.assertTrue(screenshot_fallback.endswith(".png"))
        self.assertTrue((Path(__file__).resolve().parent / "screenshots" / screenshot_fallback).is_file())
        mock_page.screenshot.assert_awaited_once_with(type="png")

    async def test_screenshot_propagation_in_reporter_and_deduplication(self):
        """Reporter and deduplication must preserve screenshots on findings and test results."""
        sample_screenshot = "shot_v1_2_1_mock123.png"

        # 1. Failed TestResult carries screenshot into raw_findings and findings list
        failed_res = TestResult(
            shortcode="V1.2.1",
            name="Context-Aware HTML Encoding",
            status="FAIL",
            severity="high",
            evidence="Reflected canary in <div id='out'>",
            screenshot=sample_screenshot,
        )
        passed_res = TestResult(
            shortcode="V1.2.2",
            name="Context-Aware JavaScript Encoding",
            status="PASS",
            severity="info",
            evidence="Script properly escaped",
            screenshot=sample_screenshot,
        )

        site_report = await generate_site_report(
            target_url="https://example.com",
            results=[failed_res, passed_res],
            raw_headers={},
            use_ai_synthesis=False,
        )
        self.assertEqual(len(site_report["findings"]), 1)
        self.assertEqual(site_report["findings"][0]["screenshot"], sample_screenshot)
        self.assertEqual(site_report["asvs_results"][0]["screenshot"], sample_screenshot)

        # 2. deduplicate_findings preserves screenshot across merged duplicates
        duplicate_findings = [
            {
                "type": "header",
                "severity": "medium",
                "detail": "Missing HSTS Header",
                "asvs": "V3.4.1",
                "evidence": "Strict-Transport-Security missing",
                "screenshot": None,
            },
            {
                "type": "header",
                "severity": "medium",
                "detail": "Missing HSTS Header",
                "asvs": "V3.4.1",
                "evidence": "Observed header keys: ...",
                "screenshot": sample_screenshot,
            },
        ]
        deduped = deduplicate_findings(duplicate_findings)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["screenshot"], sample_screenshot)

        # 3. evaluate_asvs_requirements propagates screenshot parameter
        eval_res = evaluate_asvs_requirements(
            requirements=[{"requirement_id": "V4.1.1", "chapter_code": "V4", "description": "Content-Type"}],
            headers={},
            cookies=[],
            dom_data={},
            cdp_issues=[],
            protocol="https:",
            screenshot=sample_screenshot,
        )
        self.assertEqual(eval_res["screenshot"], sample_screenshot)
        self.assertEqual(eval_res["asvs_results"][0]["screenshot"], sample_screenshot)
        self.assertEqual(eval_res["findings"][0]["screenshot"], sample_screenshot)

    # -------------------------------------------------------------------------
    # 10. Chapter V1 Script Registry, V1.3.7 Template Injection & First-Class Evidence
    # -------------------------------------------------------------------------
    def test_script_definition_and_first_class_evidence(self):
        """Verify V1 ScriptDefinitions and first-class TestResult evidence fields."""
        # 1. ScriptDefinition registration
        v137 = get_script_definition("V1.3.7")
        self.assertIsNotNone(v137)
        self.assertEqual(v137.script_id, "V1_3_7_TEMPLATE_INJECTION")
        self.assertEqual(v137.execution_mode, "BROWSER_SCRIPT")
        self.assertIn("pass", v137.evaluation_rules)
        self.assertIn("fail", v137.evaluation_rules)
        self.assertIn("manual_verify", v137.evaluation_rules)

        # 2. TestCaseExecution dataclass serialization
        tc = TestCaseExecution(
            test_id="T1-JINJA2",
            description="Submit {{7*7}} template probe",
            execution_status="completed",
            observation="Expression reflected literally without evaluation",
            evidence={"probe": "{{7*7}}", "evaluated": False},
        )
        tc_dict = tc.to_dict()
        self.assertEqual(tc_dict["test_id"], "T1-JINJA2")
        self.assertEqual(tc_dict["execution_status"], "completed")

        # 3. TestResult first-class evidence serialization
        res = TestResult(
            shortcode="V1.3.7",
            script_id="V1_3_7_TEMPLATE_INJECTION",
            name="Template Injection Protection",
            status="MANUAL_VERIFY",
            severity="info",
            evidence="Template expressions submitted, but server-side execution could not be established.",
            tests=[tc],
            evidence_items=[tc_dict["evidence"]],
            reason="The browser test could not establish server-side template evaluation.",
            missing_evidence=[
                "Server-side execution behavior",
                "Relevant template rendering implementation",
            ],
            next_action="Review server-side rendering path or collect authenticated evidence.",
            limitations=["Browser-visible behavior alone cannot establish server-side template evaluation."],
        )
        res_dict = res.to_dict()
        self.assertEqual(res_dict["script_id"], "V1_3_7_TEMPLATE_INJECTION")
        self.assertEqual(res_dict["verification_status"], "MANUAL_VERIFY")
        self.assertEqual(res_dict["execution_status"], "completed")
        self.assertEqual(len(res_dict["tests"]), 1)
        self.assertEqual(res_dict["tests"][0]["test_id"], "T1-JINJA2")
        self.assertEqual(res_dict["reason"], "The browser test could not establish server-side template evaluation.")
        self.assertEqual(len(res_dict["missing_evidence"]), 2)
        self.assertIn("Review server-side rendering", res_dict["next_action"])

    async def test_v1_3_7_ssti_evaluation_mock(self):
        """V1.3.7 test script must detect FAIL when 49 is evaluated, PASS on literal reflection, and MANUAL_VERIFY otherwise."""
        # Case A: Evaluated template expression (49 rendered) -> FAIL
        mock_page_vuln = AsyncMock()
        mock_resp_vuln = AsyncMock()
        mock_resp_vuln.status = 200
        mock_resp_vuln.text = AsyncMock(return_value="<html><body>Result: 49</body></html>")
        # Baseline returns no 49, probe returns 49
        mock_page_vuln.goto.side_effect = [
            AsyncMock(status=200, text=AsyncMock(return_value="<html><body>Baseline</body></html>")),
            mock_resp_vuln,
            mock_resp_vuln,
            mock_resp_vuln,
        ]
        mock_page_vuln.evaluate.return_value = [{"name": "q", "type": "text"}]

        ctx_vuln = HarnessContext(
            page=mock_page_vuln,
            cdp=None,
            target_url="https://example.com/app",
        )
        res_vuln = await test_v1_3_7(ctx_vuln)
        self.assertEqual(res_vuln.status, "FAIL")
        self.assertEqual(res_vuln.verification_status, "FAIL")
        self.assertEqual(res_vuln.script_id, "V1_3_7_TEMPLATE_INJECTION")
        self.assertIn("evaluated to '49'", res_vuln.evidence)

        # Case B: Literal unparsed reflection ({{7*7}} rendered) -> PASS
        mock_page_pass = AsyncMock()
        mock_resp_pass = AsyncMock()
        mock_resp_pass.status = 200
        mock_resp_pass.text = AsyncMock(return_value="<html><body>Query: {{7*7}}</body></html>")
        mock_page_pass.goto.side_effect = [
            AsyncMock(status=200, text=AsyncMock(return_value="<html><body>Baseline</body></html>")),
            mock_resp_pass,
            mock_resp_pass,
            mock_resp_pass,
        ]
        mock_page_pass.evaluate.return_value = [{"name": "q", "type": "text"}]

        ctx_pass = HarnessContext(
            page=mock_page_pass,
            cdp=None,
            target_url="https://example.com/app",
        )
        res_pass = await test_v1_3_7(ctx_pass)
        self.assertEqual(res_pass.status, "PASS")
        self.assertEqual(res_pass.verification_status, "PASS")
        self.assertIn("safely rendered as literal strings", res_pass.evidence)

        # Case C: No reflection -> MANUAL_VERIFY with actionable reason & next_action
        mock_page_manual = AsyncMock()
        mock_resp_manual = AsyncMock()
        mock_resp_manual.status = 200
        mock_resp_manual.text = AsyncMock(return_value="<html><body>Generic Page</body></html>")
        mock_page_manual.goto.side_effect = [
            AsyncMock(status=200, text=AsyncMock(return_value="<html><body>Generic Page</body></html>")),
            mock_resp_manual,
            mock_resp_manual,
            mock_resp_manual,
        ]
        mock_page_manual.evaluate.return_value = []

        ctx_manual = HarnessContext(
            page=mock_page_manual,
            cdp=None,
            target_url="https://example.com/app",
        )
        res_manual = await test_v1_3_7(ctx_manual)
        self.assertEqual(res_manual.status, "MANUAL_VERIFY")
        self.assertEqual(res_manual.verification_status, "MANUAL_VERIFY")
        self.assertIsNotNone(res_manual.reason)
        self.assertGreater(len(res_manual.missing_evidence), 0)
        self.assertIsNotNone(res_manual.next_action)

    async def test_actionable_manual_verify_coverage(self):
        """All non-observable Chapter V1 requirements must return actionable MANUAL_VERIFY with reasons and next actions."""
        from tinyfah_loader import get_chapter_requirements
        v1_reqs = get_chapter_requirements("V1")
        self.assertEqual(len(v1_reqs), 30)

        ctx = HarnessContext(
            page=None,
            cdp=None,
            target_url="https://example.com",
            http_status=200,
        )
        passive_res = await evaluate_v1_passive_and_review_requirements(
            all_v1_reqs=v1_reqs,
            ctx=ctx,
            executed_results={},
        )
        self.assertEqual(len(passive_res), 30)
        for r in passive_res:
            self.assertEqual(r.status, "MANUAL_VERIFY")
            self.assertEqual(r.execution_status, "completed")
            self.assertIsNotNone(r.reason, f"Missing reason on {r.shortcode}")
            self.assertGreater(len(r.missing_evidence), 0, f"Missing missing_evidence on {r.shortcode}")
            self.assertIsNotNone(r.next_action, f"Missing next_action on {r.shortcode}")


if __name__ == "__main__":
    unittest.main()
