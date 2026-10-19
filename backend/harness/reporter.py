"""
OWASP ASVS Verification & Compliance Reporter

SCORING AND COMPLIANCE FORMULA:
==============================
1. Assessment Coverage:
   - Total Requirements in Scope: N_total = len(results)
   - Evaluated Requirements: N_eval = count(status in ["PASS", "FAIL"])
   - Untested / Manual: N_untested = count(status in ["NOT_TESTED", "MANUAL_VERIFY", "SKIPPED"])
   - Execution Errors: N_error = count(status == "ERROR")
   - Assessment Coverage %: (N_eval / N_total * 100) if N_total > 0 else 0.0

2. Compliance Score:
   - If N_total == 0 or N_eval == 0:
     Score = None, Grade = "NOT_ASSESSED"
     (An empty or unevaluated scan never receives a score of 100 or Grade A)
   - If N_eval > 0:
     Base Score = 100
     Penalty deductions for verified FAIL findings:
       * High Severity: -25 points
       * Medium Severity: -15 points
       * Low Severity: -5 points
     Compliance Score = max(0, min(100, Base Score - sum(penalties)))

3. Grade Mapping:
   - Score >= 90: "A"
   - Score >= 75: "B"
   - Score >= 60: "C"
   - Score >= 45: "D"
   - Score < 45:  "F"
   - None / 0 evaluated: "NOT_ASSESSED"

4. Pass Rate %:
   - (N_pass / N_eval * 100) if N_eval > 0 else None

5. Scan Status:
   - "completed": All in-scope tests executed, N_eval > 0, N_error == 0
   - "partial": N_eval > 0, but N_error > 0 occurred during execution
   - "not_assessed": N_total == 0 or N_eval == 0
"""

import os
import json
from typing import List, Dict, Any, Optional, Tuple
from google import genai
from google.genai import types
from harness.registry import TestResult
from checks import deduplicate_findings

DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

def calculate_score_and_grade(results: List[TestResult]) -> Tuple[Optional[int], str]:
    """
    Calculates the compliance score (0-100) and letter grade (A-F).
    Returns (None, "NOT_ASSESSED") if results is empty or if no requirements were definitively evaluated.
    """
    if not results:
        return None, "NOT_ASSESSED"

    evaluated = [r for r in results if r.status in ["PASS", "FAIL"]]
    if not evaluated:
        return None, "NOT_ASSESSED"

    score = 100
    for r in evaluated:
        if r.status == "FAIL":
            if r.severity == "high":
                score -= 25
            elif r.severity == "medium":
                score -= 15
            elif r.severity == "low":
                score -= 5

    score = max(0, min(100, score))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 45:
        grade = "D"
    else:
        grade = "F"
    return score, grade

async def generate_site_report(
    target_url: str,
    results: List[TestResult],
    raw_headers: Dict[str, str],
    agent_trace: Optional[List[Dict[str, Any]]] = None,
    use_ai_synthesis: bool = True,
) -> Dict[str, Any]:
    score, grade = calculate_score_and_grade(results)

    passed = [r for r in results if r.status == "PASS"]
    failed = [r for r in results if r.status == "FAIL"]
    manual = [r for r in results if r.status == "MANUAL_VERIFY"]
    not_tested = [r for r in results if r.status == "NOT_TESTED"]
    errors = [r for r in results if r.status == "ERROR"]

    total_requirements = len(results)
    total_evaluated = len(passed) + len(failed)
    coverage_pct = round((total_evaluated / total_requirements * 100), 1) if total_requirements > 0 else 0.0
    pass_rate_pct = round((len(passed) / total_evaluated * 100), 1) if total_evaluated > 0 else None

    # Scan completion state
    if total_requirements == 0 or total_evaluated == 0:
        scan_status = "not_assessed"
    elif len(errors) > 0:
        scan_status = "partial"
    else:
        scan_status = "completed"

    # Collect raw findings from failed tests
    raw_findings = []
    for f in failed:
        raw_findings.append({
            "requirement_id": f.shortcode,
            "asvs": f.shortcode,
            "category": "Encoding & Sanitization",
            "type": "encoding",
            "severity": f.severity,
            "title": f.name,
            "detail": f.name,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "test_hint": f.test_hint,
            "required_inputs": f.required_inputs,
            "observations": f.observations or f.evidence,
            "expected_behavior": f.expected_behavior,
            "limitations": f.limitations,
            "screenshot": f.screenshot,
        })

    # Deduplicate findings while preserving all evidence and valid ASVS mappings
    findings = deduplicate_findings(raw_findings)

    summary_text = (
        f"Deterministic audit completed for {target_url} across {total_requirements} requirements in "
        f"Chapter V1 (Encoding and Sanitization). Found {len(passed)} PASS, {len(failed)} FAIL, "
        f"{len(manual)} MANUAL_VERIFY, {len(not_tested)} NOT_TESTED, and {len(errors)} ERROR. "
        f"Assessment Coverage: {coverage_pct}%."
    )

    # Gemini AI executive synthesis with transparent failure tracking
    ai_status = "SKIPPED"
    ai_error = None
    gemini_key = os.getenv("GEMINI_API_KEY")

    if use_ai_synthesis and gemini_key and total_evaluated > 0:
        ai_status = "RUNNING"
        try:
            client = genai.Client(api_key=gemini_key)
            prompt = (
                f"You are a web application security auditor. Given the following deterministic test results "
                f"for {target_url} against OWASP ASVS Chapter V1 (Encoding and Sanitization), write a concise 2-3 "
                f"sentence executive summary of the site's security posture and immediate remediation priorities:\n\n"
                f"Score: {score}/100 (Grade {grade})\n"
                f"Coverage: {coverage_pct}%\n"
                f"Failed Requirements: {json.dumps([f.to_dict() for f in failed], indent=2)}\n"
            )

            candidate_models = [DEFAULT_GEMINI_MODEL]
            ai_resp = None
            last_err = None
            for model_name in candidate_models:
                try:
                    ai_resp = await client.aio.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            max_output_tokens=300,
                        ),
                    )
                    if ai_resp and ai_resp.text:
                        summary_text = ai_resp.text.strip()
                        ai_status = "SUCCESS"
                        break
                except Exception as m_err:
                    last_err = m_err
                    continue

            if ai_status != "SUCCESS":
                ai_status = "FAILED"
                ai_error = str(last_err)
        except Exception as exc:
            ai_status = "FAILED"
            ai_error = str(exc)

    report = {
        "target_url": target_url,
        "chapter": "V1 Encoding and Sanitization",
        "score": score,
        "grade": grade,
        "scan_status": scan_status,
        "coverage_percentage": coverage_pct,
        "pass_rate_percentage": pass_rate_pct,
        "summary": summary_text,
        "ai_synthesis_status": ai_status,
        "ai_synthesis_error": ai_error,
        "metrics": {
            "total_requirements": total_requirements,
            "total_evaluated": total_evaluated,
            "passed": len(passed),
            "failed": len(failed),
            "manual_verify": len(manual),
            "not_tested": len(not_tested),
            "errors": len(errors),
        },
        "findings": findings,
        "asvs_results": [r.to_dict() for r in results],
        "agent_trace": agent_trace or [],
        "raw_headers": raw_headers,
    }

    return report
