from typing import TypedDict, List, Dict, Any, Optional

class AuditGraphState(TypedDict, total=False):
    target_url: str
    protocol: str
    http_status: Optional[int]
    doc_headers: Dict[str, str]
    cookies: List[Dict[str, Any]]
    cdp_issues: List[str]
    initial_recon: Dict[str, Any]

    # Browser references (for active node execution)
    page: Any
    cdp: Any
    console_logs: List[Dict[str, Any]]
    baseline_screenshot: Optional[str]

    # Multi-Agent Workflow State
    current_step: int
    agent_trace: List[Dict[str, Any]]
    raw_findings: List[Dict[str, Any]]
    asvs_results: List[Dict[str, Any]]
    next_agent: str
    completed_agents: List[str]
    tasks_planned: List[str]
    iteration_count: int
    max_iterations: int

    # Suite Configuration & Standards Scope
    suite_type: str
    chapter_breakdown: Dict[str, Dict[str, Any]]

    # Final Verification Outputs
    score: Optional[int]
    grade: str
    scan_status: str
    summary: str
    coverage_percentage: float
    pass_rate_percentage: Optional[float]
    ai_synthesis_status: str
    ai_error: Optional[str]
    metrics: Dict[str, Any]
    final_report: Dict[str, Any]
