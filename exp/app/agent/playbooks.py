from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from app.config import CANARY_MARKER, EXPLORE_MAX_ACTIONS

ARTIFACT_PATHS: tuple[str, ...] = (
    "/.env",
    "/.git/config",
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/actuator",
    "/server-status",
    "/.well-known/security.txt",
    "/robots.txt",
)

ADMIN_PATHS: tuple[str, ...] = ("/admin", "/dashboard", "/debug")

ADMIN_QUERY_KEYS = {
    "role",
    "is_admin",
    "admin",
    "debug",
    "access",
    "superuser",
    "user_id",
    "account_id",
    "id",
    "user",
    "account",
    "privilege",
}

REFLECTION_PARAMS: tuple[str, ...] = ("q", "search", "query", "name", "message")


def _origin(snapshot: dict, fallback: str) -> str:
    origin = str(snapshot.get("origin") or "").strip()
    if origin:
        return origin
    parts = urlsplit(fallback)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _action_id(payload: str) -> str:
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def _without_admin_params(href: str) -> str | None:
    parts = urlsplit(href)
    kept = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key.lower() not in ADMIN_QUERY_KEYS
    ]
    control = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), ""))
    return control if control != href else None


def _action(
    playbook: str,
    method: str,
    target: str,
    verifier: str,
    description: str,
    *,
    params: dict | None = None,
    control_target: str | None = None,
) -> dict:
    params = params or {}
    payload = f"{method} {target} {sorted(params.items())}"
    target_with_params = target
    if params:
        target_with_params = f"{target}?{urlencode(params)}"
    action = {
        "id": _action_id(payload),
        "playbook": playbook,
        "description": description,
        "method": method,
        "target": target_with_params,
        "params": {},
        "tool": "http_head" if method == "HEAD" else "http_get",
        "verifier": verifier,
        "action_class": "PROBE",
    }
    if control_target and control_target != target_with_params:
        action["control_target"] = control_target
    return action


def canary_payload(run_id: str) -> str:
    digest = (run_id or "run")[:8]
    return f"<{CANARY_MARKER.lower()}-{digest}>"


def _reflection_candidates(origin: str, snapshot: dict, canary: str) -> list[dict]:
    candidates: list[dict] = []
    for form in snapshot.get("forms", []):
        if str(form.get("method", "")).upper() != "GET":
            continue
        action = str(form.get("action") or origin)
        for element in form.get("inputs", []):
            name = str(element.get("name") or "").strip()
            element_type = str(element.get("type") or "").lower()
            if not name or element_type in {"password", "file", "submit", "hidden"}:
                continue
            candidates.append(
                _action(
                    "reflected_input",
                    "GET",
                    action,
                    "reflected_canary",
                    f"Probe parameter '{name}' for unescaped reflection",
                    params={name: canary},
                )
            )
    if not candidates:
        for name in REFLECTION_PARAMS:
            candidates.append(
                _action(
                    "reflected_input",
                    "GET",
                    origin + "/",
                    "reflected_canary",
                    f"Probe parameter '{name}' for unescaped reflection",
                    params={name: canary},
                )
            )
    return candidates


def _access_control_candidates(origin: str, snapshot: dict, inventory: dict) -> list[dict]:
    candidates: list[dict] = []
    for hint in inventory.get("admin_hints", []):
        href = str(hint.get("href") or "")
        if href.startswith("http"):
            candidates.append(
                _action(
                    "access_control",
                    "GET",
                    href,
                    "access_control_bypass",
                    f"Probe discovered admin hint: {hint.get('text') or href}",
                    control_target=_without_admin_params(href),
                )
            )
    for link in snapshot.get("links", []):
        href = str(link.get("href") or "")
        if not href.startswith("http"):
            continue
        keys = {key.lower() for key, _ in parse_qsl(urlsplit(href).query, keep_blank_values=True)}
        if keys & ADMIN_QUERY_KEYS:
            candidates.append(
                _action(
                    "access_control",
                    "GET",
                    href,
                    "access_control_bypass",
                    "Probe parameterized link for access-control weakness",
                    control_target=_without_admin_params(href),
                )
            )
    for path in ADMIN_PATHS:
        candidates.append(
            _action(
                "access_control",
                "GET",
                urljoin(origin + "/", path.lstrip("/")),
                "unauthenticated_admin_access",
                f"Probe {path} for unauthenticated access",
                control_target=origin + "/",
            )
        )
    return candidates


def build_candidates(
    snapshot: dict,
    inventory: dict,
    *,
    target_url: str,
    canary: str,
    max_actions: int = EXPLORE_MAX_ACTIONS,
) -> list[dict]:
    origin = _origin(snapshot, target_url)
    candidates: list[dict] = []

    for path in ARTIFACT_PATHS:
        candidates.append(
            _action(
                "exposed_artifacts",
                "GET",
                urljoin(origin + "/", path.lstrip("/")),
                "exposed_artifact",
                f"Check for exposed artifact {path}",
            )
        )

    candidates.append(
        _action(
            "graphql_introspection",
            "GET",
            urljoin(origin + "/", "graphql"),
            "graphql_introspection",
            "Probe GraphQL introspection with a __typename query",
            params={"query": "{__typename}"},
        )
    )

    candidates.extend(_access_control_candidates(origin, snapshot, inventory))
    candidates.extend(_reflection_candidates(origin, snapshot, canary))

    deduped: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        key = (candidate["method"], candidate["target"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)

    return deduped[:max_actions]
