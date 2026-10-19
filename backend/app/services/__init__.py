"""Domain services package."""
from typing import Any

__all__ = [
    "calculate_score_and_grade",
    "calculate_grade",
    "evaluate_asvs_requirements",
    "deduplicate_findings",
    "REQUIRED_HEADERS",
    "DOM_AUDIT_JS",
    "run_gemini_security_harness",
    "execute_cdp_tool",
    "SECURITY_TOOLS",
    "execute_scan_task",
    "update_scan_status",
    "save_live_trace",
]

def __getattr__(name: str) -> Any:
    if name in ("calculate_score_and_grade", "calculate_grade"):
        from app.services import scoring
        return getattr(scoring, name)
    if name in ("evaluate_asvs_requirements", "deduplicate_findings", "REQUIRED_HEADERS", "DOM_AUDIT_JS"):
        from app.services import checks
        return getattr(checks, name)
    if name in ("run_gemini_security_harness", "execute_cdp_tool", "SECURITY_TOOLS"):
        from app.services import agent
        return getattr(agent, name)
    if name in ("execute_scan_task", "update_scan_status", "save_live_trace"):
        from app.services import scanner
        return getattr(scanner, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
