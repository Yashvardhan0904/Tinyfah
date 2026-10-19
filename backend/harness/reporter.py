import os
import json
from typing import List, Dict, Any, Optional
from google import genai
from google.genai import types
from harness.registry import TestResult

def calculate_score_and_grade(results: List[TestResult]) -> tuple[int, str]:
    score = 100
    for r in results:
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
    errors = [r for r in results if r.status == "ERROR"]

    findings = []
    for f in failed:
        findings.append({
            "requirement_id": f.shortcode,
            "category": "Encoding & Sanitization",
            "severity": f.severity,
            "title": f.name,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "test_hint": f.test_hint,
            "required_inputs": f.required_inputs,
        })

    summary_text = (
        f"Deterministic audit completed for {target_url} across {len(results)} requirements in "
        f"Chapter V1 (Encoding and Sanitization). Found {len(passed)} PASS, {len(failed)} FAIL, "
        f"and {len(manual)} requiring manual verification."
    )

    # Optional Gemini AI executive synthesis
    gemini_key = os.getenv("GEMINI_API_KEY")
    if use_ai_synthesis and gemini_key and (failed or score < 90):
        try:
            client = genai.Client(api_key=gemini_key)
            model_id = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

            prompt = (
                f"You are a web application security auditor. Given the following deterministic test results "
                f"for {target_url} against OWASP ASVS Chapter V1 (Encoding and Sanitization), write a concise 2-3 "
                f"sentence executive summary of the site's security posture and immediate remediation priorities:\n\n"
                f"Score: {score}/100 (Grade {grade})\n"
                f"Failed Requirements: {json.dumps([f.to_dict() for f in failed], indent=2)}\n"
            )

            response = await client.aio.models.generate_content(
                model=model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    max_output_tokens=250,
                ),
            )
            if response.text:
                summary_text = response.text.strip()
        except Exception:
            pass  # Fallback to deterministic summary text

    report = {
        "target_url": target_url,
        "chapter": "V1 Encoding and Sanitization",
        "score": score,
        "grade": grade,
        "summary": summary_text,
        "metrics": {
            "total_evaluated": len(results),
            "passed": len(passed),
            "failed": len(failed),
            "manual_verify": len(manual),
            "errors": len(errors),
        },
        "findings": findings,
        "asvs_results": [r.to_dict() for r in results],
        "agent_trace": agent_trace or [],
        "raw_headers": raw_headers,
    }

    return report
