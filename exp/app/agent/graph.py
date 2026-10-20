from __future__ import annotations

import json
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

import app.config as config
from app.agent.playbooks import build_candidates, canary_payload
from app.agent.state import ExploitState
from app.agent.verifiers import static_findings, verify
from app.core.audit import AuditLog
from app.core.policy import (
    ActionClass,
    PolicyViolation,
    Scope,
    classify_action,
    enforce_action,
)
from app.http.client import ScopeLockedClient
from app.services.recon import perform_recon

ReconFunc = Callable[[ExploitState], Awaitable[dict[str, Any]]]
PlanFunc = Callable[[ExploitState], Awaitable[list[dict[str, Any]]]]
ExecuteFunc = Callable[[ExploitState, dict[str, Any]], Awaitable[dict[str, Any]]]
VerifyFunc = Callable[[ExploitState, dict[str, Any], dict[str, Any]], dict[str, Any] | None]
AnalyzeFunc = Callable[[ExploitState], Awaitable[list[str]]]


async def default_recon(state: ExploitState) -> dict[str, Any]:
    result = await perform_recon(state["target_url"])
    return {
        "snapshot": result.get("snapshot", {}),
        "inventory": result.get("inventory", {}),
        "browser_mode": result.get("browser_mode", "unknown"),
        "screenshot": result.get("screenshot"),
    }


async def default_plan(state: ExploitState) -> list[dict[str, Any]]:
    return build_candidates(
        state.get("snapshot", {}),
        state.get("inventory", {}),
        target_url=state["target_url"],
        canary=state.get("canary", ""),
    )


async def default_execute(state: ExploitState, action: dict[str, Any]) -> dict[str, Any]:
    scope = Scope.from_hosts(config.ALLOWED_HOSTS)
    audit = AuditLog(state["run_id"])
    approved = action.get("action_class") == ActionClass.STATE_CHANGE.value
    async with ScopeLockedClient(scope, audit=audit, approved=approved) as client:
        if action.get("method") == "HEAD":
            response = await client.head(action["target"])
        else:
            response = await client.get(action["target"])
        return response.as_dict()


async def default_execute_control(state: ExploitState, action: dict[str, Any]) -> dict[str, Any]:
    control = dict(action)
    control["target"] = action["control_target"]
    control["method"] = "GET"
    control["action_class"] = ActionClass.PROBE.value
    return await default_execute(state, control)


def default_verify(
    state: ExploitState, action: dict[str, Any], response: dict[str, Any]
) -> dict[str, Any] | None:
    return verify(
        action,
        response,
        baseline=state.get("last_baseline") or None,
        snapshot=state.get("snapshot"),
        canary=state.get("canary"),
    )


async def default_analyze(state: ExploitState) -> list[str]:
    if not config.LLM_ANALYSIS_ENABLED:
        return []
    try:
        from app.agent.llm import build_chat_model_chain

        snapshot = state.get("snapshot", {})
        summary = {
            "url": snapshot.get("url"),
            "title": snapshot.get("title"),
            "forms": snapshot.get("formCount"),
            "links": snapshot.get("linkCount"),
            "admin_hints": state.get("inventory", {}).get("admin_hints", [])[:5],
        }
        prompt = (
            "You are an authorized security tester. In at most 3 short bullet points, "
            "list the most likely vulnerability classes for this page. Do not include "
            "exploit payloads.\n\n" + json.dumps(summary, default=str)
        )
        chain = build_chat_model_chain(audit=AuditLog(state["run_id"]))
        response = await chain.ainvoke(prompt)
        text = getattr(response, "content", str(response))
        return [line.strip("- ").strip() for line in str(text).splitlines() if line.strip()][:3]
    except Exception as exc:
        return [f"LLM analysis unavailable: {type(exc).__name__}"]


@dataclass
class GraphDeps:
    recon: ReconFunc = field(default=default_recon)
    plan: PlanFunc = field(default=default_plan)
    execute: ExecuteFunc = field(default=default_execute)
    execute_control: ExecuteFunc = field(default=default_execute_control)
    verify: VerifyFunc = field(default=default_verify)
    analyze: AnalyzeFunc = field(default=default_analyze)


def build_exploit_graph(deps: GraphDeps | None = None, checkpointer: Any = None):
    deps = deps or GraphDeps()

    async def recon_node(state: ExploitState) -> dict[str, Any]:
        try:
            result = await deps.recon(state)
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}
        snapshot = result.get("snapshot", {})
        return {
            "snapshot": snapshot,
            "inventory": result.get("inventory", {}),
            "browser_mode": result.get("browser_mode", "unknown"),
            "findings": static_findings(snapshot),
            "probes": [
                {
                    "phase": "recon",
                    "tool": "recon_snapshot",
                    "action_class": ActionClass.PROBE.value,
                    "payload": {"target_url": state["target_url"]},
                    "result": {
                        "browser_mode": result.get("browser_mode"),
                        "screenshot": result.get("screenshot"),
                    },
                }
            ],
        }

    async def analyze_node(state: ExploitState) -> dict[str, Any]:
        notes = await deps.analyze(state)
        return {"notes": notes}

    async def plan_node(state: ExploitState) -> dict[str, Any]:
        candidates = await deps.plan(state)
        return {
            "candidates": candidates,
            "current_index": 0,
            "notes": [f"planned {len(candidates)} actions"],
        }

    async def policy_check_node(state: ExploitState) -> dict[str, Any]:
        candidates = state.get("candidates", [])
        index = state.get("current_index", 0)
        if index >= len(candidates):
            return {"decision": "report"}
        spec = dict(candidates[index])
        action = classify_action(spec["method"], tool=spec["tool"], detail=spec["target"])
        spec["action_class"] = action.value
        try:
            enforce_action(
                action,
                approved=False,
                state_change_enabled=state.get("approved_state_change", False),
            )
        except PolicyViolation as exc:
            if action is ActionClass.STATE_CHANGE and state.get("approved_state_change"):
                return {"current_action": spec, "pending_approval": spec, "decision": "approval"}
            return {
                "current_action": spec,
                "decision": "skip",
                "skipped": [{"action": spec, "reason": str(exc)}],
            }
        return {"current_action": spec, "pending_approval": None, "decision": "execute"}

    async def approval_node(state: ExploitState) -> dict[str, Any]:
        spec = state["current_action"]
        approved = interrupt(
            {
                "action_id": spec["id"],
                "description": spec.get("description"),
                "target": spec.get("target"),
                "action_class": spec.get("action_class"),
                "reason": "State-changing action requires explicit human approval",
            }
        )
        if approved:
            return {"decision": "execute", "approved_action_id": spec["id"]}
        return {
            "decision": "skip",
            "approved_action_id": None,
            "pending_approval": None,
            "skipped": [{"action": spec, "reason": "approval denied"}],
        }

    async def execute_node(state: ExploitState) -> dict[str, Any]:
        spec = state["current_action"]
        approved = state.get("approved_action_id") == spec["id"]
        baseline: dict[str, Any] = {}
        try:
            result = await deps.execute(state, spec)
            if spec.get("control_target"):
                baseline = await deps.execute_control(state, spec)
        except PolicyViolation as exc:
            return {
                "last_result": {},
                "last_baseline": {},
                "decision": "skip",
                "skipped": [{"action": spec, "reason": str(exc)}],
            }
        except Exception as exc:
            return {
                "last_result": {},
                "last_baseline": {},
                "decision": "skip",
                "skipped": [{"action": spec, "reason": f"{type(exc).__name__}: {exc}"}],
            }
        return {
            "last_result": result,
            "last_baseline": baseline,
            "decision": "verify",
            "probes": [
                {
                    "phase": "exploit",
                    "tool": spec["tool"],
                    "action_class": spec.get("action_class"),
                    "approved": approved,
                    "payload": spec,
                    "result": {
                        "status": result.get("status"),
                        "url": result.get("url"),
                        "baseline_status": baseline.get("status"),
                        "truncated": result.get("truncated"),
                    },
                }
            ],
        }

    async def verify_node(state: ExploitState) -> dict[str, Any]:
        spec = state["current_action"]
        finding = deps.verify(state, spec, state.get("last_result") or {})
        if finding and finding.get("verified"):
            return {"findings": [finding]}
        return {}

    async def advance_node(state: ExploitState) -> dict[str, Any]:
        return {
            "current_index": state.get("current_index", 0) + 1,
            "last_result": {},
            "last_baseline": {},
            "approved_action_id": None,
            "pending_approval": None,
            "decision": "",
        }

    def report_node(state: ExploitState) -> dict[str, Any]:
        findings = state.get("findings", [])
        counts = Counter(finding.get("severity", "info") for finding in findings)
        return {
            "report": {
                "target_url": state["target_url"],
                "mode": state.get("mode", "explore"),
                "browser_mode": state.get("browser_mode"),
                "actions_planned": len(state.get("candidates", [])),
                "finding_count": len(findings),
                "severity_counts": dict(counts),
                "findings": findings,
                "skipped": state.get("skipped", []),
                "notes": state.get("notes", []),
                "error": state.get("error"),
            }
        }

    def route_after_recon(state: ExploitState) -> str:
        return "report" if state.get("error") else "analyze"

    def route_after_policy(state: ExploitState) -> str:
        return state.get("decision", "report")

    def route_after_approval(state: ExploitState) -> str:
        return "execute" if state.get("decision") == "execute" else "advance"

    def route_after_execute(state: ExploitState) -> str:
        return "verify" if state.get("decision") == "verify" else "advance"

    def route_after_advance(state: ExploitState) -> str:
        if state.get("current_index", 0) < len(state.get("candidates", [])):
            return "policy_check"
        return "report"

    graph = StateGraph(ExploitState)
    graph.add_node("recon", recon_node)
    graph.add_node("analyze", analyze_node)
    graph.add_node("plan", plan_node)
    graph.add_node("policy_check", policy_check_node)
    graph.add_node("approval", approval_node)
    graph.add_node("execute", execute_node)
    graph.add_node("verify", verify_node)
    graph.add_node("advance", advance_node)
    graph.add_node("report", report_node)

    graph.add_edge(START, "recon")
    graph.add_conditional_edges(
        "recon", route_after_recon, {"analyze": "analyze", "report": "report"}
    )
    graph.add_edge("analyze", "plan")
    graph.add_edge("plan", "policy_check")
    graph.add_conditional_edges(
        "policy_check",
        route_after_policy,
        {"approval": "approval", "execute": "execute", "skip": "advance", "report": "report"},
    )
    graph.add_conditional_edges(
        "approval", route_after_approval, {"execute": "execute", "advance": "advance"}
    )
    graph.add_conditional_edges(
        "execute", route_after_execute, {"verify": "verify", "advance": "advance"}
    )
    graph.add_edge("verify", "advance")
    graph.add_conditional_edges(
        "advance", route_after_advance, {"policy_check": "policy_check", "report": "report"}
    )
    graph.add_edge("report", END)

    return graph.compile(checkpointer=checkpointer)


def initial_state(
    run_id: str,
    target_url: str,
    *,
    mode: str = "explore",
    approved_state_change: bool | None = None,
) -> ExploitState:
    return ExploitState(
        run_id=run_id,
        target_url=target_url,
        mode=mode,
        approved_state_change=(
            config.ENABLE_STATE_CHANGE if approved_state_change is None else approved_state_change
        ),
        canary=canary_payload(run_id),
        probes=[],
        findings=[],
        skipped=[],
        notes=[],
        current_index=0,
    )
