from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


class ExploitState(TypedDict, total=False):
    run_id: str
    target_url: str
    mode: str
    approved_state_change: bool
    canary: str
    browser_mode: str
    snapshot: dict[str, Any]
    inventory: dict[str, Any]
    candidates: list[dict[str, Any]]
    current_index: int
    current_action: dict[str, Any]
    decision: str
    pending_approval: dict[str, Any] | None
    approved_action_id: str | None
    last_result: dict[str, Any]
    last_baseline: dict[str, Any]
    probes: Annotated[list[dict[str, Any]], operator.add]
    findings: Annotated[list[dict[str, Any]], operator.add]
    skipped: Annotated[list[dict[str, Any]], operator.add]
    notes: Annotated[list[str], operator.add]
    report: dict[str, Any]
    error: str | None
