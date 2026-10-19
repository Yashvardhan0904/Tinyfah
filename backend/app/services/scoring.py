from typing import Optional, Tuple, List, Any

PENALTY_MAP = {
    "high": 25,
    "medium": 15,
    "low": 5,
    "info": 0,
}

SEVERITY_ORDER = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

def calculate_grade(score: Optional[int]) -> str:
    """Maps a numerical score (0-100) to an ASVS letter grade (A-F)."""
    if score is None:
        return "NOT_ASSESSED"
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"

def calculate_score_and_grade(results: List[Any]) -> Tuple[Optional[int], str]:
    """
    Calculates the compliance score (0-100) and letter grade (A-F) from test results.
    Returns (None, "NOT_ASSESSED") if results is empty or if no items were evaluated.
    """
    if not results:
        return None, "NOT_ASSESSED"

    evaluated = [
        r for r in results
        if (isinstance(r, dict) and r.get("status") in ["PASS", "FAIL"])
        or (hasattr(r, "status") and getattr(r, "status") in ["PASS", "FAIL"])
    ]
    if not evaluated:
        return None, "NOT_ASSESSED"

    score = 100
    for r in evaluated:
        status = r.get("status") if isinstance(r, dict) else getattr(r, "status")
        if status == "FAIL":
            sev = (r.get("severity") if isinstance(r, dict) else getattr(r, "severity", "info")) or "info"
            score -= PENALTY_MAP.get(str(sev).lower(), 0)

    score = max(0, min(100, score))
    return score, calculate_grade(score)
