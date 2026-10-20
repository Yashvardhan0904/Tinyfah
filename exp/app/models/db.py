from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Column, event
from sqlmodel import Field, Session, SQLModel, create_engine, select

from app.config import DATABASE_URL, DB_FILE


def _now() -> datetime:
    return datetime.now(UTC)


class ExploitRun(SQLModel, table=True):
    __tablename__ = "exploit_runs"

    id: str = Field(primary_key=True)
    target_url: str
    status: str = Field(default="queued", index=True)
    mode: str = Field(default="dry_run")
    error: str | None = None
    result: dict | None = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_now, index=True)
    updated_at: datetime = Field(default_factory=_now)


class ExploitStep(SQLModel, table=True):
    __tablename__ = "exploit_steps"

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(index=True)
    seq: int
    phase: str
    tool: str
    action_class: str
    approved: bool = Field(default=False)
    payload: dict | None = Field(default=None, sa_column=Column(JSON))
    result: dict | None = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_now)


engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def init_db() -> None:
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    SQLModel.metadata.create_all(engine)


def create_run(run_id: str, target_url: str, mode: str = "dry_run") -> ExploitRun:
    init_db()
    run = ExploitRun(id=run_id, target_url=target_url, mode=mode, status="queued")
    with Session(engine) as session:
        session.add(run)
        session.commit()
        session.refresh(run)
        return run


def get_run(run_id: str) -> ExploitRun | None:
    init_db()
    with Session(engine) as session:
        return session.get(ExploitRun, run_id)


def list_runs(limit: int = 20) -> list[ExploitRun]:
    init_db()
    with Session(engine) as session:
        statement = select(ExploitRun).order_by(ExploitRun.created_at.desc()).limit(limit)
        return list(session.exec(statement).all())


def update_run(
    run_id: str,
    *,
    status: str | None = None,
    error: str | None = None,
    result: dict | None = None,
    mode: str | None = None,
) -> ExploitRun | None:
    init_db()
    with Session(engine) as session:
        run = session.get(ExploitRun, run_id)
        if not run:
            return None
        if status is not None:
            run.status = status
        if error is not None:
            run.error = error
        if result is not None:
            run.result = result
        if mode is not None:
            run.mode = mode
        run.updated_at = _now()
        session.add(run)
        session.commit()
        session.refresh(run)
        return run


def add_step(
    run_id: str,
    *,
    seq: int,
    phase: str,
    tool: str,
    action_class: str,
    payload: dict | None = None,
    result: dict | None = None,
    approved: bool = False,
) -> ExploitStep:
    init_db()
    step = ExploitStep(
        run_id=run_id,
        seq=seq,
        phase=phase,
        tool=tool,
        action_class=action_class,
        payload=payload,
        result=result,
        approved=approved,
    )
    with Session(engine) as session:
        session.add(step)
        session.commit()
        session.refresh(step)
        return step


def list_steps(run_id: str) -> list[ExploitStep]:
    init_db()
    with Session(engine) as session:
        statement = (
            select(ExploitStep)
            .where(ExploitStep.run_id == run_id)
            .order_by(ExploitStep.seq, ExploitStep.id)
        )
        return list(session.exec(statement).all())
