from typing import Optional, Tuple, List, Any

# Retained for backwards compatibility
PENALTY_MAP = {
    "high": 25,
    "medium": 15,
    "low": 5,
    "info": 0,
}

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

SEVERITY_WEIGHTS = {
    "critical": 5.0,
    "high": 4.0,
    "medium": 3.0,
    "low": 1.0,
    "info": 2.0,
}

LEVEL_WEIGHTS = {
    1: 3.0,
    2: 2.0,
    3: 1.0,
    "1": 3.0,
    "2": 2.0,
    "3": 1.0,
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

def get_item_weight(r: Any) -> float:
    """
    Determines the relative compliance weight of an evaluated requirement.
    Uses severity when specified (critical/high/medium/low), otherwise ASVS level (L1/L2/L3),
    defaulting to baseline weight (2.0).
    """
    if isinstance(r, dict):
        sev = str(r.get("severity") or "").strip().lower()
        lvl = r.get("level")
    else:
        sev = str(getattr(r, "severity", "") or "").strip().lower()
        lvl = getattr(r, "level", None)

    if sev in ["critical", "high", "medium", "low"]:
        return SEVERITY_WEIGHTS[sev]
    if lvl in LEVEL_WEIGHTS:
        return LEVEL_WEIGHTS[lvl]
    return SEVERITY_WEIGHTS.get(sev, 2.0)

def calculate_score_and_grade(results: List[Any]) -> Tuple[Optional[int], str]:
    """
    Calculates the compliance score (0-100) and letter grade (A-F) from test results
    using a severity/level-weighted compliance ratio:
      Score = (Sum of PASS weights / Sum of all evaluated weights) * 100
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

    total_weight = 0.0
    passed_weight = 0.0

    for r in evaluated:
        w = get_item_weight(r)
        total_weight += w
        status = r.get("status") if isinstance(r, dict) else getattr(r, "status")
        if status == "PASS":
            passed_weight += w

    if total_weight <= 0:
        return None, "NOT_ASSESSED"

    score = round((passed_weight / total_weight) * 100)
    score = max(0, min(100, int(score)))
    return score, calculate_grade(score)

