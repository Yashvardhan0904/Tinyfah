from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.agent.llm import LLMConfigurationError, describe_chain
from app.agent.runner import resume_explore, run_explore
from app.config import (
    ALLOWED_HOSTS,
    DRY_RUN,
    ENABLE_STATE_CHANGE,
    SCREENSHOTS_DIR,
    TINYFISH_API_KEY,
)
from app.core.audit import AuditLog, new_run_id
from app.core.policy import PolicyViolation, Scope
from app.models.db import (
    add_step,
    create_run,
    get_run,
    list_runs,
    list_steps,
    update_run,
)
from app.services.recon import perform_recon

app = FastAPI(title="Tinyfah Exploit", version="0.1.0")
app.mount("/screenshots", StaticFiles(directory=SCREENSHOTS_DIR), name="screenshots")


class RunRequest(BaseModel):
    target_url: str = Field(min_length=1)
    mode: Literal["recon", "explore"] = "recon"


class ApprovalRequest(BaseModel):
    approved: bool = False


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _serialize_run(run) -> dict:
    return {
        "id": run.id,
        "target_url": run.target_url,
        "status": run.status,
        "mode": run.mode,
        "error": run.error,
        "result": run.result,
        "created_at": _iso(run.created_at),
        "updated_at": _iso(run.updated_at),
    }


def _serialize_step(step) -> dict:
    return {
        "id": step.id,
        "run_id": step.run_id,
        "seq": step.seq,
        "phase": step.phase,
        "tool": step.tool,
        "action_class": step.action_class,
        "approved": step.approved,
        "payload": step.payload,
        "result": step.result,
        "created_at": _iso(step.created_at),
    }


def _llm_status() -> dict:
    try:
        return {"configured": True, "chain": describe_chain()}
    except LLMConfigurationError as exc:
        return {"configured": False, "error": str(exc)}


@app.get("/")
def root() -> dict:
    return {
        "service": "tinyfah-exploit",
        "version": app.version,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "tinyfah-exploit",
        "llm": _llm_status(),
        "tinyfish_configured": bool(TINYFISH_API_KEY),
        "allowed_hosts": list(ALLOWED_HOSTS),
        "dry_run": DRY_RUN,
        "state_change_enabled": ENABLE_STATE_CHANGE,
    }


@app.get("/providers")
def providers() -> dict:
    status = _llm_status()
    if not status["configured"]:
        raise HTTPException(status_code=503, detail=status["error"])
    return status


@app.get("/runs")
def runs_index(limit: int = 20) -> list[dict]:
    return [_serialize_run(run) for run in list_runs(limit=max(1, min(limit, 100)))]


@app.get("/runs/{run_id}")
def run_detail(run_id: str) -> dict:
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {
        **_serialize_run(run),
        "steps": [_serialize_step(step) for step in list_steps(run_id)],
    }


@app.get("/runs/{run_id}/audit")
def run_audit(run_id: str) -> list[dict]:
    if not get_run(run_id):
        raise HTTPException(status_code=404, detail="Run not found")
    return AuditLog(run_id).read()


@app.post("/runs", status_code=202)
async def start_run(payload: RunRequest, background_tasks: BackgroundTasks) -> dict:
    scope = Scope.from_hosts(ALLOWED_HOSTS)
    try:
        target = scope.validate(payload.target_url)
    except PolicyViolation as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    run_id = new_run_id()
    create_run(run_id, target, mode=payload.mode)
    AuditLog(run_id).record("run_queued", target=target, mode=payload.mode)

    if payload.mode == "explore":
        background_tasks.add_task(_execute_explore, run_id, target)
    else:
        background_tasks.add_task(_execute_recon, run_id, target)

    run = get_run(run_id)
    return _serialize_run(run)


@app.post("/runs/{run_id}/approve", status_code=202)
async def approve_run(
    run_id: str, payload: ApprovalRequest, background_tasks: BackgroundTasks
) -> dict:
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status != "awaiting_approval":
        raise HTTPException(status_code=409, detail=f"Run is not awaiting approval ({run.status})")

    background_tasks.add_task(_execute_resume, run_id, payload.approved)
    return {"id": run_id, "status": "resuming", "approved": payload.approved}


async def _execute_explore(run_id: str, target: str) -> None:
    try:
        await run_explore(run_id, target)
    except Exception as exc:
        update_run(run_id, status="failed", error=f"{type(exc).__name__}: {exc}")
        AuditLog(run_id).record("run_failed", error=f"{type(exc).__name__}: {exc}")


async def _execute_resume(run_id: str, approved: bool) -> None:
    try:
        await resume_explore(run_id, approved)
    except Exception as exc:
        update_run(run_id, status="failed", error=f"{type(exc).__name__}: {exc}")
        AuditLog(run_id).record("resume_failed", error=f"{type(exc).__name__}: {exc}")


async def _execute_recon(run_id: str, target: str) -> None:
    audit = AuditLog(run_id)
    update_run(run_id, status="running")
    audit.record("run_started", target=target, mode="recon")

    try:
        result = await perform_recon(target)
        add_step(
            run_id,
            seq=1,
            phase="recon",
            tool="recon_snapshot",
            action_class="PROBE",
            payload={"target_url": target},
            result={
                "browser_mode": result.get("browser_mode"),
                "screenshot": result.get("screenshot"),
                "form_count": result.get("snapshot", {}).get("formCount"),
                "link_count": result.get("snapshot", {}).get("linkCount"),
            },
        )
        update_run(run_id, status="completed", result=result)
        audit.record("run_completed", status="completed")
    except Exception as exc:
        update_run(run_id, status="failed", error=str(exc))
        audit.record("run_failed", error=str(exc))
