from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx

from app.config import (
    ENABLE_STATE_CHANGE,
    MAX_REQUESTS_PER_RUN,
    MAX_RESPONSE_BYTES,
    MAX_RPS,
    REQUEST_TIMEOUT_SECONDS,
)
from app.core.audit import AuditLog
from app.core.policy import (
    ActionClass,
    PolicyViolation,
    RateLimiter,
    RequestBudget,
    Scope,
    assert_public_resolution,
    classify_action,
    enforce_action,
    redact_headers,
    redact_text,
)

USER_AGENT = "Tinyfah-Exploit/0.1 (authorized security testing)"


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str]
    body_excerpt: str
    truncated: bool
    elapsed_ms: int
    redirects: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "headers": redact_headers(self.headers),
            "body_excerpt": redact_text(self.body_excerpt),
            "truncated": self.truncated,
            "elapsed_ms": self.elapsed_ms,
            "redirects": self.redirects,
        }


class ScopeLockedClient:
    def __init__(
        self,
        scope: Scope,
        *,
        audit: AuditLog | None = None,
        approved: bool = False,
        allow_state_change: bool | None = None,
        max_requests: int = MAX_REQUESTS_PER_RUN,
        max_rps: float = MAX_RPS,
    ) -> None:
        self.scope = scope
        self.audit = audit
        self.approved = approved
        self.allow_state_change = (
            ENABLE_STATE_CHANGE if allow_state_change is None else allow_state_change
        )
        self.budget = RequestBudget(max_requests)
        self.limiter = RateLimiter(max_rps)
        self._resolved_hosts: set[str] = set()
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=REQUEST_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )

    async def __aenter__(self) -> ScopeLockedClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    def _record(self, event: str, **fields: Any) -> None:
        if self.audit:
            self.audit.record(event, **fields)

    async def _ensure_public(self, url: str) -> None:
        host = (urlsplit(url).hostname or "").lower()
        if host in self._resolved_hosts:
            return
        await assert_public_resolution(url)
        self._resolved_hosts.add(host)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        content: Any | None = None,
        approved: bool | None = None,
        max_redirects: int = 3,
    ) -> HttpResponse:
        verb = (method or "GET").upper()
        current = self.scope.validate(url)
        detail = current
        if params:
            detail = f"{current}?{urlencode(params, doseq=True)}"
        if isinstance(content, str):
            detail = f"{detail} {content[:1000]}"
        action = classify_action(verb, tool="http_request", detail=detail)
        is_approved = self.approved if approved is None else approved
        enforce_action(
            action,
            approved=is_approved,
            state_change_enabled=self.allow_state_change,
        )

        redirects: list[str] = []
        started = time.monotonic()
        status = 0
        response_headers: dict[str, str] = {}
        excerpt = ""
        truncated = False

        try:
            for hop in range(max_redirects + 1):
                await self._ensure_public(current)
                self.budget.consume()
                await self.limiter.acquire()
                self._record(
                    "http_request",
                    method=verb,
                    url=current,
                    action_class=action.value,
                    hop=hop,
                    request_headers=headers or {},
                )

                async with self._client.stream(
                    verb,
                    current,
                    headers=headers,
                    params=params,
                    content=content,
                ) as response:
                    status = response.status_code
                    response_headers = dict(response.headers)
                    location = response.headers.get("location")

                    if status in {301, 302, 303, 307, 308} and location:
                        body_chunks: list[bytes] = []
                    else:
                        body_chunks = []
                        total = 0
                        async for chunk in response.aiter_bytes():
                            if total >= MAX_RESPONSE_BYTES:
                                truncated = True
                                break
                            remaining = MAX_RESPONSE_BYTES - total
                            body_chunks.append(chunk[:remaining])
                            total += len(chunk[:remaining])
                            if len(chunk) > remaining:
                                truncated = True
                                break
                        excerpt = b"".join(body_chunks).decode("utf-8", errors="replace")

                if status in {301, 302, 303, 307, 308} and location:
                    if hop >= max_redirects:
                        break
                    next_url = self.scope.validate_redirect(current, location)
                    redirects.append(next_url)
                    self._record(
                        "http_redirect",
                        url=current,
                        location=next_url,
                        status=status,
                        action_class=action.value,
                    )
                    if status == 303 or (status in {301, 302} and verb == "POST"):
                        verb = "GET"
                        content = None
                    current = next_url
                    params = None
                    continue
                break

            elapsed_ms = int((time.monotonic() - started) * 1000)
            result = HttpResponse(
                url=current,
                status=status,
                headers=response_headers,
                body_excerpt=excerpt,
                truncated=truncated,
                elapsed_ms=elapsed_ms,
                redirects=redirects,
            )
            self._record("http_response", **result.as_dict(), action_class=action.value)
            return result
        except PolicyViolation:
            raise
        except Exception as exc:
            self._record(
                "http_error",
                url=current,
                method=verb,
                action_class=action.value,
                error=str(exc),
            )
            raise

    async def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.request("HEAD", url, **kwargs)


def require_read_only(action: ActionClass) -> None:
    if action not in {ActionClass.READ, ActionClass.PROBE}:
        raise PolicyViolation(f"Only read-only actions are permitted here, got {action.value}")
