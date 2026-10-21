from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from app.core.panel import ADMIN_MARKERS, LOGIN_MARKERS
from app.core.policy import SENSITIVE_QUERY_KEYS, redact_url

LOGIN_REDIRECT_MARKERS = ("login", "signin", "auth", "sso")


@dataclass
class VerificationInput:
    action: dict[str, Any]
    response: dict[str, Any] | None = None
    baseline: dict[str, Any] | None = None
    snapshot: dict[str, Any] | None = None
    canary: str | None = None


@dataclass(frozen=True)
class Evidence:
    verifier: str
    severity: str
    title: str
    detail: str
    action_id: str
    target_url: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verifier": self.verifier,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "action_id": self.action_id,
            "target_url": self.target_url,
            "evidence": self.evidence,
            "verified": True,
        }


def _body(response: dict[str, Any] | None) -> str:
    return (response or {}).get("body_excerpt") or ""


def _status(response: dict[str, Any] | None) -> int:
    return int((response or {}).get("status") or 0)


def _has_marker(body: str, markers: tuple[str, ...]) -> str | None:
    lowered = body.lower()
    for marker in markers:
        if marker in lowered:
            return marker
    return None


def _redirects_to_login(response: dict[str, Any]) -> bool:
    location = str((response.get("headers") or {}).get("location", "")).lower()
    return any(marker in location for marker in LOGIN_REDIRECT_MARKERS)


def _evidence(
    inp: VerificationInput, severity: str, title: str, detail: str, **extra: Any
) -> dict[str, Any]:
    return Evidence(
        verifier=inp.action["verifier"],
        severity=severity,
        title=title,
        detail=detail,
        action_id=inp.action["id"],
        target_url=inp.action.get("target", ""),
        evidence={**extra, "status": _status(inp.response)},
    ).as_dict()


_ARTIFACT_RULES: tuple[tuple[str, Callable[[str], bool]], ...] = (
    ("/.env", lambda body: "=" in body and "<html" not in body.lower()),
    ("/.git/config", lambda body: "[core]" in body or "repositoryformatversion" in body),
    ("/openapi.json", lambda body: '"openapi"' in body or '"paths"' in body),
    ("/swagger.json", lambda body: '"swagger"' in body or '"paths"' in body),
    ("/api/openapi.json", lambda body: '"openapi"' in body or '"paths"' in body),
    ("/actuator", lambda body: '"_links"' in body or '"status"' in body),
    ("/server-status", lambda body: "apache server status" in body.lower()),
    ("/.well-known/security.txt", lambda body: "contact:" in body.lower()),
)


def verify_exposed_artifact(inp: VerificationInput) -> dict[str, Any] | None:
    response = inp.response or {}
    if _status(response) not in {200, 206}:
        return None
    path = urlsplit(inp.action.get("target", "")).path
    body = _body(response)
    for suffix, rule in _ARTIFACT_RULES:
        if path.endswith(suffix) and rule(body):
            severity = "high" if suffix in {"/.env", "/.git/config"} else "medium"
            return _evidence(
                inp,
                severity,
                f"Exposed artifact: {suffix}",
                "Path is readable and returned content matching the artifact signature.",
                path=path,
            )
    return None


def verify_graphql_introspection(inp: VerificationInput) -> dict[str, Any] | None:
    response = inp.response or {}
    if _status(response) != 200:
        return None
    body = _body(response)
    if "__typename" in body or '"data"' in body:
        return _evidence(
            inp,
            "medium",
            "GraphQL introspection reachable",
            "A __typename query succeeded, so schema introspection may be enabled.",
            path=urlsplit(inp.action.get("target", "")).path,
        )
    return None


def _admin_body_without_login(response: dict[str, Any]) -> str | None:
    body = _body(response)
    admin = _has_marker(body, ADMIN_MARKERS)
    login = _has_marker(body, LOGIN_MARKERS)
    if admin and not login:
        return admin
    return None


def verify_access_control_bypass(inp: VerificationInput) -> dict[str, Any] | None:
    response = inp.response or {}
    if _status(response) != 200 or _redirects_to_login(response):
        return None
    marker = _has_marker(_body(response), ADMIN_MARKERS)
    if not marker:
        return None
    baseline_body = _body(inp.baseline or {})
    if baseline_body:
        if marker in baseline_body.lower():
            return None
    elif _has_marker(_body(response), LOGIN_MARKERS):
        return None
    return _evidence(
        inp,
        "high",
        "Possible access-control bypass",
        "A parameterized request returned privileged content that the control request did not.",
        matched_marker=marker,
        query=urlsplit(inp.action.get("target", "")).query,
        baseline_status=_status(inp.baseline or {}),
    )


def verify_unauthenticated_admin_access(inp: VerificationInput) -> dict[str, Any] | None:
    response = inp.response or {}
    if _status(response) != 200 or _redirects_to_login(response):
        return None
    marker = _admin_body_without_login(response)
    if not marker:
        return None
    return _evidence(
        inp,
        "high",
        "Unauthenticated admin surface",
        "An administrative path returned privileged content to an unauthenticated client.",
        matched_marker=marker,
        path=urlsplit(inp.action.get("target", "")).path,
    )


def verify_reflected_canary(inp: VerificationInput) -> dict[str, Any] | None:
    response = inp.response or {}
    if _status(response) != 200 or not inp.canary:
        return None
    body = _body(response)
    if inp.canary not in body:
        return None
    escaped = inp.canary.replace("<", "&lt;").replace(">", "&gt;")
    if escaped in body:
        return None
    return _evidence(
        inp,
        "medium",
        "Unescaped reflected input",
        "The canary payload was reflected without HTML escaping; verify context manually.",
        canary=inp.canary,
    )


def verify_sql_injection_login(inp: VerificationInput) -> dict[str, Any] | None:
    response = inp.response or {}
    if not response.get("authenticated"):
        return None
    screenshot = response.get("screenshot")
    return _evidence(
        inp,
        "critical",
        "SQL injection authentication bypass",
        "Injected login credentials were accepted and privileged content was reachable.",
        form_action=inp.action.get("login", {}).get("action", inp.action.get("target", "")),
        final_url=response.get("url"),
        matched_marker=response.get("matched_marker"),
        browser_mode=response.get("browser_mode"),
        screenshot=screenshot,
    )


VERIFIERS: dict[str, Callable[[VerificationInput], dict[str, Any] | None]] = {
    "exposed_artifact": verify_exposed_artifact,
    "graphql_introspection": verify_graphql_introspection,
    "access_control_bypass": verify_access_control_bypass,
    "unauthenticated_admin_access": verify_unauthenticated_admin_access,
    "reflected_canary": verify_reflected_canary,
    "sql_injection_login": verify_sql_injection_login,
}


def verify(action: dict[str, Any], response: dict[str, Any] | None, **kwargs: Any):
    verifier = VERIFIERS.get(action.get("verifier", ""))
    if not verifier:
        return None
    return verifier(VerificationInput(action=action, response=response, **kwargs))


def transport_weakness_findings(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    insecure: list[str] = []
    for link in snapshot.get("links", []):
        href = str(link.get("href", ""))
        if href.startswith("http://"):
            insecure.append(href)
    for form in snapshot.get("forms", []):
        action = str(form.get("action", ""))
        if action.startswith("http://"):
            insecure.append(action)
    if not insecure:
        return []
    unique = sorted(set(insecure))[:10]
    return [
        Evidence(
            verifier="transport_weakness",
            severity="low",
            title="Insecure HTTP references on an HTTPS page",
            detail="Links or form actions point to plaintext http:// endpoints.",
            action_id="static-transport",
            target_url=snapshot.get("url", ""),
            evidence={"insecure_targets": unique, "count": len(unique)},
        ).as_dict()
    ]


def credential_in_url_findings(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    leaks: list[str] = []
    for link in snapshot.get("links", []):
        href = str(link.get("href", ""))
        if not href.startswith("http"):
            continue
        for key, value in parse_qsl(urlsplit(href).query, keep_blank_values=True):
            if key.lower() in SENSITIVE_QUERY_KEYS and value:
                leaks.append(redact_url(href))
                break
    if not leaks:
        return []
    unique = sorted(set(leaks))[:10]
    return [
        Evidence(
            verifier="credential_in_url",
            severity="medium",
            title="Credential-like values in URL query strings",
            detail="Sensitive parameters in page links can leak via logs or referrers.",
            action_id="static-credential-url",
            target_url=snapshot.get("url", ""),
            evidence={"urls": unique, "count": len(unique)},
        ).as_dict()
    ]


def admin_surface_findings(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    hints = snapshot.get("adminHints", [])
    if not hints:
        return []
    targets = sorted({str(item.get("href", "")) for item in hints if item.get("href")})[:10]
    if not targets:
        return []
    return [
        Evidence(
            verifier="admin_surface",
            severity="info",
            title="Administrative surface discovered",
            detail="Recon found links or parameters that reference admin functionality.",
            action_id="static-admin-surface",
            target_url=snapshot.get("url", ""),
            evidence={"targets": targets},
        ).as_dict()
    ]


def static_findings(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    return (
        transport_weakness_findings(snapshot)
        + credential_in_url_findings(snapshot)
        + admin_surface_findings(snapshot)
    )
