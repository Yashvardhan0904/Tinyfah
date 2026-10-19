from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import event
from sqlmodel import SQLModel, Field, create_engine, Session, Column, JSON

class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str
    status: str = Field(default="running")  # "running" | "completed" | "failed"
    score: Optional[int] = Field(default=None)
    grade: Optional[str] = Field(default=None)
    results: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    error: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

from pathlib import Path

DB_FILE = Path(__file__).resolve().parent / "scans.db"
sqlite_url = f"sqlite:///{DB_FILE}"
engine = create_engine(
    sqlite_url,
    connect_args={"check_same_thread": False, "timeout": 15}
)

# Enable WAL mode so Next.js polling reads never block background agent writes
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.close()

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
