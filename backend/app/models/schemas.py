from typing import List, Optional
from pydantic import BaseModel

class ASVSTestItem(BaseModel):
    requirement_id: str
    chapter_code: str
    chapter_name: str
    status: str       # "PASS" | "FAIL" | "MANUAL_VERIFY" | "NOT_TESTED" | "NOT_APPLICABLE" | "ERROR"
    severity: str     # "high" | "medium" | "low" | "info"
    evidence: str
    remediation: str
    screenshot: Optional[str] = None

class FindingItem(BaseModel):
    severity: str     # "high" | "medium" | "low"
    category: str     # e.g., "Headers", "Cookies", "SRI", "Forms", "ASVS"
    title: str
    evidence: str
    remediation: str
    screenshot: Optional[str] = None

class GeminiSecurityReport(BaseModel):
    score: Optional[int] = None       # 0 - 100, or None if not assessable
    grade: str = "NOT_ASSESSED"       # "A" | "B" | "C" | "D" | "F" | "NOT_ASSESSED"
    summary: str
    asvs_results: List[ASVSTestItem]
    findings: List[FindingItem]
    screenshot: Optional[str] = None
