from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.config import AUDIT_DIR
from app.core.policy import SENSITIVE_HEADERS, SENSITIVE_QUERY_KEYS, redact_text, redact_url

MAX_FIELD_CHARS = 4000


def new_run_id() -> str:
    return uuid.uuid4().hex


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sanitize(value: Any, key: str | None = None) -> Any:
    lowered = (key or "").lower()
    if lowered in SENSITIVE_HEADERS or lowered in SENSITIVE_QUERY_KEYS:
        return "[redacted]"
    if isinstance(value, dict):
        return {str(k): _sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item) for item in value]
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        if value.startswith(("http://", "https://")):
            value = redact_url(value)
        value = redact_text(value)
        if len(value) > MAX_FIELD_CHARS:
            return value[:MAX_FIELD_CHARS] + "...[truncated]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(str(value))


class AuditLog:
    def __init__(self, run_id: str, directory: Path | None = None) -> None:
        self.run_id = run_id
        self.path = (directory or AUDIT_DIR) / f"{run_id}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        entry = {
            "ts": utc_now(),
            "run_id": self.run_id,
            "event": event,
            **_sanitize(fields),
        }
        line = json.dumps(entry, ensure_ascii=True, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        return entry

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
