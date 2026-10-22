import json
from typing import Dict, Any
from google.genai import types

from app.graph.state import AuditGraphState
from app.config import GEMINI_MODEL
from app.services.agent import _get_client

async def synthesizer_node(state: AuditGraphState) -> Dict[str, Any]:
    """Generates the executive summary and synthesizes the finalized audit report."""
    target_url = state.get("target_url", "")
    score = state.get("score")
    grade = state.get("grade", "NOT_ASSESSED")
    findings = state.get("raw_findings", [])
    metrics = state.get("metrics", {})
    coverage_pct = state.get("coverage_percentage", 0.0)
    agent_trace = list(state.get("agent_trace", []))
    step = state.get("current_step", 1)

    failed_findings = [f for f in findings if f.get("severity") in ["high", "medium", "low"]]

    default_summary = (
        f"LangGraph multi-agent security verification completed for {target_url} across all 17 OWASP ASVS chapters "
        f"({metrics.get('total_requirements', 345)} requirements). "
        f"Score: {score}/100 (Grade {grade}), Coverage: {coverage_pct}%. "
        f"Identified {len(failed_findings)} verified finding(s) across transport, headers, input encoding, client DOM, auth, and API surfaces."
    )

    summary_text = default_summary
    ai_status = "SKIPPED"
    ai_error = None

    client = _get_client()
    if client and len(failed_findings) > 0:
        ai_status = "RUNNING"
        try:
            prompt = (
                f"You are a Senior Web Application Security Auditor. Given the following verified audit findings "
                f"for {target_url}, write a concise 2-3 sentence executive summary of the site's security posture "
                f"and top immediate remediation priorities across the OWASP ASVS 5.0.0 standard:\n\n"
                f"Score: {score}/100 (Grade {grade})\n"
                f"Coverage: {coverage_pct}%\n"
                f"Verified Findings: {json.dumps(failed_findings[:10], indent=2)}\n"
            )
            resp = await client.aio.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    max_output_tokens=300,
                ),
            )
            if resp and resp.text:
                summary_text = resp.text.strip()
                ai_status = "SUCCESS"
        except Exception as exc:
            ai_status = "FAILED"
            ai_error = str(exc)

    trace_entry = {
        "step": step,
        "tool": "report_synthesizer",
        "reason": "Synthesized executive security audit report and remediation guidelines across all 17 ASVS chapters",
        "observation_preview": summary_text,
        "status": "completed",
    }
    agent_trace.append(trace_entry)

    final_report = {
        "target_url": target_url,
        "workflow": "langgraph_multi_agent",
        "score": score,
        "grade": grade,
        "scan_status": state.get("scan_status", "completed"),
        "coverage_percentage": coverage_pct,
        "pass_rate_percentage": state.get("pass_rate_percentage"),
        "summary": summary_text,
        "ai_synthesis_status": ai_status,
        "ai_synthesis_error": ai_error,
        "metrics": metrics,
        "findings": findings,
        "asvs_results": state.get("asvs_results", []),
        "chapter_breakdown": state.get("chapter_breakdown", {}),
        "agent_trace": agent_trace,
        "raw_headers": state.get("doc_headers", {}),
        "screenshot": state.get("baseline_screenshot"),
    }

    return {
        "summary": summary_text,
        "ai_synthesis_status": ai_status,
        "ai_error": ai_error,
        "agent_trace": agent_trace,
        "final_report": final_report,
    }
