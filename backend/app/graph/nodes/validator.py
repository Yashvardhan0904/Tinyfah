from typing import Dict, Any, List
from app.graph.state import AuditGraphState
from app.services.checks import deduplicate_findings
from app.services.scoring import calculate_score_and_grade

async def evidence_validator_node(state: AuditGraphState) -> Dict[str, Any]:
    """Deterministic Evidence Gate: validates observations, deduplicates findings, and calculates compliance scores."""
    raw_findings = state.get("raw_findings", [])
    asvs_results = state.get("asvs_results", [])
    agent_trace = list(state.get("agent_trace", []))
    baseline_shot = state.get("baseline_screenshot")
    step = state.get("current_step", 1)

    # Attach baseline screenshot if finding or ASVS result lacks one
    if baseline_shot:
        for f in raw_findings:
            if not f.get("screenshot"):
                f["screenshot"] = baseline_shot
        for r in asvs_results:
            if not r.get("screenshot"):
                r["screenshot"] = baseline_shot

    # Deduplicate findings while preserving all evidence, severity, and ASVS IDs
    deduped_findings = deduplicate_findings(raw_findings)

    # Calculate compliance score and grade
    score, grade = calculate_score_and_grade(asvs_results)

    passed_count = sum(1 for r in asvs_results if r.get("status") == "PASS")
    failed_count = sum(1 for r in asvs_results if r.get("status") == "FAIL")
    manual_count = sum(1 for r in asvs_results if r.get("status") == "MANUAL_VERIFY")
    not_tested_count = sum(1 for r in asvs_results if r.get("status") == "NOT_TESTED")
    error_count = sum(1 for r in asvs_results if r.get("status") == "ERROR")

    total_requirements = len(asvs_results)
    total_evaluated = passed_count + failed_count
    coverage_pct = round((total_evaluated / total_requirements * 100), 1) if total_requirements > 0 else 0.0
    pass_rate_pct = round((passed_count / total_evaluated * 100), 1) if total_evaluated > 0 else None

    if total_evaluated == 0:
        scan_status = "not_assessed"
        score = None
        grade = "NOT_ASSESSED"
    elif error_count > 0:
        scan_status = "partial"
    else:
        scan_status = "completed"

    metrics = {
        "total_requirements": total_requirements,
        "total_evaluated": total_evaluated,
        "passed": passed_count,
        "failed": failed_count,
        "manual_verify": manual_count,
        "not_tested": not_tested_count,
        "errors": error_count,
    }

    chapter_breakdown = dict(state.get("chapter_breakdown", {}))
    if not chapter_breakdown and asvs_results:
        from app.graph.nodes.asvs_evaluator import CHAPTER_NAMES
        for code, name in CHAPTER_NAMES.items():
            chap_reqs = [r for r in asvs_results if r.get("chapter_code") == code]
            if not chap_reqs:
                continue
            p_count = sum(1 for r in chap_reqs if r.get("status") == "PASS")
            f_count = sum(1 for r in chap_reqs if r.get("status") == "FAIL")
            mv_count = sum(1 for r in chap_reqs if r.get("status") == "MANUAL_VERIFY")
            nt_count = sum(1 for r in chap_reqs if r.get("status") == "NOT_TESTED")
            ch_score, ch_grade = calculate_score_and_grade(chap_reqs)
            chapter_breakdown[code] = {
                "chapter_code": code,
                "chapter_name": name,
                "total": len(chap_reqs),
                "passed": p_count,
                "failed": f_count,
                "manual_verify": mv_count,
                "not_tested": nt_count,
                "score": ch_score,
                "grade": ch_grade,
                "status": "completed" if (p_count + f_count) > 0 else "manual_review",
            }

    trace_entry = {
        "step": step,
        "tool": "evidence_validator",
        "reason": "Applied deterministic evidence validation, deduplication, and ASVS scoring formulas",
        "observation_preview": (
            f"Validated {len(deduped_findings)} unique finding(s). "
            f"Compliance Score: {score if score is not None else 'N/A'}/100, Grade: {grade}, Coverage: {coverage_pct}%."
        ),
        "status": "completed",
    }
    agent_trace.append(trace_entry)

    return {
        "raw_findings": deduped_findings,
        "asvs_results": asvs_results,
        "chapter_breakdown": chapter_breakdown,
        "score": score,
        "grade": grade,
        "scan_status": scan_status,
        "coverage_percentage": coverage_pct,
        "pass_rate_percentage": pass_rate_pct,
        "metrics": metrics,
        "agent_trace": agent_trace,
        "current_step": step + 1,
    }
