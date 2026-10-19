"""Security checks, finding deduplication, and ASVS requirements evaluator re-export."""
from app.services.checks import (
    DOM_AUDIT_JS,
    REQUIRED_HEADERS,
    _canonical_finding_key,
    deduplicate_findings,
    evaluate_asvs_requirements,
)
from app.services.scoring import SEVERITY_ORDER

__all__ = [
    "DOM_AUDIT_JS",
    "REQUIRED_HEADERS",
    "SEVERITY_ORDER",
    "_canonical_finding_key",
    "deduplicate_findings",
    "evaluate_asvs_requirements",
]
