from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.config import OWNERSHIP_TIMEOUT_SECONDS
from app.core.audit import AuditLog
from app.core.policy import Scope, assert_public_resolution

WELL_KNOWN_TEMPLATE = "/.well-known/tinyfah-{token}.txt"
META_NAME = "tinyfah-verify"
USER_AGENT = "Tinyfah-Exploit/0.1 (ownership verification)"

_META_RE = re.compile(
    r"""<meta[^>]+name\s*=\s*["']tinyfah-verify["'][^>]*>""",
    re.IGNORECASE,
)
_CONTENT_RE = re.compile(
    r"""content\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class OwnershipResult:
    verified: bool
    method: str | None = None
    reason: str | None = None

    def as_dict(self) -> dict:
        return {"verified": self.verified, "method": self.method, "reason": self.reason}


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


async def verify_ownership(
    target_url: str,
    token: str,
    scope: Scope,
    *,
    audit: AuditLog | None = None,
    client: httpx.AsyncClient | None = None,
) -> OwnershipResult:
    token = (token or "").strip()
    if not token:
        return OwnershipResult(False, None, "EXPLOIT_OWNER_TOKEN is not set")

    canonical = scope.validate(target_url)
    await assert_public_resolution(canonical)

    origin = _origin(canonical)
    well_known = origin + WELL_KNOWN_TEMPLATE.format(token=token)

    owns_client = client is None
    client = client or httpx.AsyncClient(
        timeout=OWNERSHIP_TIMEOUT_SECONDS,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    )
    try:
        result = await _check_well_known(client, scope, well_known, token, audit)
        if result.verified:
            return result
        return await _check_meta(client, scope, canonical, token, audit)
    finally:
        if owns_client:
            await client.aclose()


async def _check_well_known(
    client: httpx.AsyncClient,
    scope: Scope,
    url: str,
    token: str,
    audit: AuditLog | None,
) -> OwnershipResult:
    try:
        response = await client.get(scope.validate(url))
    except Exception as exc:
        if audit:
            audit.record("ownership_probe", method="well_known", url=url, error=str(exc))
        return OwnershipResult(False, None, f"well-known request failed: {exc}")
    body = response.text or ""
    if response.status_code == 200 and body.strip() == token:
        if audit:
            audit.record("ownership_probe", method="well_known", url=url, status=200, verified=True)
        return OwnershipResult(True, "well_known")
    if audit:
        audit.record("ownership_probe", method="well_known", url=url, status=response.status_code)
    return OwnershipResult(False, None, "well-known proof token not found")


async def _check_meta(
    client: httpx.AsyncClient,
    scope: Scope,
    url: str,
    token: str,
    audit: AuditLog | None,
) -> OwnershipResult:
    try:
        response = await client.get(scope.validate(url))
    except Exception as exc:
        if audit:
            audit.record("ownership_probe", method="meta_tag", url=url, error=str(exc))
        return OwnershipResult(False, None, f"meta probe request failed: {exc}")
    if response.status_code != 200:
        if audit:
            audit.record("ownership_probe", method="meta_tag", url=url, status=response.status_code)
        return OwnershipResult(False, None, f"meta probe returned HTTP {response.status_code}")
    for match in _META_RE.finditer(response.text or ""):
        for content in _CONTENT_RE.findall(match.group(0)):
            if content.strip() == token:
                if audit:
                    audit.record(
                        "ownership_probe", method="meta_tag", url=url, status=200, verified=True
                    )
                return OwnershipResult(True, "meta_tag")
    if audit:
        audit.record("ownership_probe", method="meta_tag", url=url, status=200, verified=False)
    return OwnershipResult(False, None, "HTML meta proof token not found")
