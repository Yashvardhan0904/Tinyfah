from __future__ import annotations

from typing import Any

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.types import Command

from app.agent.graph import GraphDeps, build_exploit_graph, initial_state
from app.config import ALLOWED_HOSTS, DB_FILE, OWNER_TOKEN
from app.core.audit import AuditLog
from app.core.ownership import verify_ownership
from app.core.policy import Scope
from app.models.db import add_step, get_run, list_steps, update_run


def _fail(run_id: str, audit: AuditLog, error: str) -> dict[str, Any]:
    update_run(run_id, status="failed", error=error)
    audit.record("run_failed", error=error)
    return {"id": run_id, "status": "failed", "error": error}


def _persist_probes(run_id: str, probes: list[dict[str, Any]]) -> None:
    already = len(list_steps(run_id))
    for index, probe in enumerate(probes):
        if index < already:
            continue
        add_step(
            run_id,
            seq=index + 1,
            phase=str(probe.get("phase", "exploit")),
            tool=str(probe.get("tool", "unknown")),
            action_class=str(probe.get("action_class", "PROBE")),
            approved=bool(probe.get("approved", False)),
            payload=probe.get("payload"),
            result=probe.get("result"),
        )


def _finalize(
    run_id: str, values: dict[str, Any], audit: AuditLog, *, paused: bool
) -> dict[str, Any]:
    _persist_probes(run_id, values.get("probes", []))

    if values.get("error"):
        return _fail(run_id, audit, str(values["error"]))

    result = {
        "report": values.get("report"),
        "findings": values.get("findings", []),
        "pending_approval": values.get("pending_approval"),
        "browser_mode": values.get("browser_mode"),
    }

    if paused:
        update_run(run_id, status="awaiting_approval", result=result)
        audit.record("run_awaiting_approval", pending=values.get("pending_approval"))
        return {"id": run_id, "status": "awaiting_approval", "result": result}

    update_run(run_id, status="completed", result=result)
    audit.record(
        "run_completed",
        status="completed",
        finding_count=len(values.get("findings", [])),
    )
    return {"id": run_id, "status": "completed", "result": result}


async def run_explore(
    run_id: str,
    target_url: str,
    *,
    deps: GraphDeps | None = None,
    verified: bool = False,
) -> dict[str, Any]:
    audit = AuditLog(run_id)
    update_run(run_id, status="running")
    audit.record("run_started", target=target_url, mode="explore")

    scope = Scope.from_hosts(ALLOWED_HOSTS)
    try:
        target = scope.validate(target_url)
    except Exception as exc:
        return _fail(run_id, audit, str(exc))

    if not verified:
        ownership = await verify_ownership(target, OWNER_TOKEN, scope, audit=audit)
        audit.record("ownership_check", **ownership.as_dict())
        if not ownership.verified:
            return _fail(
                run_id,
                audit,
                f"Ownership verification failed: {ownership.reason or 'no proof found'}",
            )

    async with AsyncSqliteSaver.from_conn_string(str(DB_FILE)) as saver:
        graph = build_exploit_graph(deps=deps or GraphDeps(), checkpointer=saver)
        config = {"configurable": {"thread_id": run_id}}
        try:
            await graph.ainvoke(initial_state(run_id, target), config)
        except Exception as exc:
            return _fail(run_id, audit, f"{type(exc).__name__}: {exc}")
        snapshot = await graph.aget_state(config)
        return _finalize(run_id, snapshot.values, audit, paused=bool(snapshot.next))


async def resume_explore(
    run_id: str,
    approved: bool,
    *,
    deps: GraphDeps | None = None,
) -> dict[str, Any]:
    run = get_run(run_id)
    if not run:
        raise ValueError(f"Run '{run_id}' not found")

    audit = AuditLog(run_id)
    audit.record("approval_decision", approved=bool(approved))

    async with AsyncSqliteSaver.from_conn_string(str(DB_FILE)) as saver:
        graph = build_exploit_graph(deps=deps or GraphDeps(), checkpointer=saver)
        config = {"configurable": {"thread_id": run_id}}
        snapshot = await graph.aget_state(config)
        if not snapshot.next:
            return {"id": run_id, "status": run.status, "error": "run is not awaiting approval"}
        try:
            await graph.ainvoke(Command(resume=bool(approved)), config)
        except Exception as exc:
            return _fail(run_id, audit, f"{type(exc).__name__}: {exc}")
        snapshot = await graph.aget_state(config)
        return _finalize(run_id, snapshot.values, audit, paused=bool(snapshot.next))
