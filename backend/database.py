from datetime import datetime, timezone
from typing import Optional, Dict, Any
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

sqlite_url = "sqlite:///./scans.db"
# check_same_thread=False is required so BackgroundTasks can write to SQLite
engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
