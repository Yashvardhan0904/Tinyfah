from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pydantic import BaseModel, HttpUrl
from sqlmodel import SQLModel, Field, Column, JSON

class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str
    status: str = Field(default="running")  # "queued" | "running" | "completed" | "failed" | "not_assessed"
    score: Optional[int] = Field(default=None)
    grade: Optional[str] = Field(default=None)
    results: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    error: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ScanRequest(BaseModel):
    url: HttpUrl
    suite: Optional[str] = "v1"  # "v1" | "chapter_v1" | "chapter_sample" | "first_five" | "full"
    test_id: Optional[str] = None           # e.g. "V1.2.1"
    focus_prompt: Optional[str] = None
