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

SQLI_USERNAME_PAYLOADS: tuple[str, ...] = (
    "' OR '1'='1' -- ",
    "' OR 1=1 -- ",
    "admin' -- ",
    "' OR '1'='1'#",
)

SQLI_PASSWORD_PAYLOAD = "tinyfah-probe"

LOGIN_USERNAME_HINTS: tuple[str, ...] = (
    "username",
    "user",
    "email",
    "login",
    "userid",
    "user_id",
    "account",
    "name",
)

NON_LOGIN_INPUT_TYPES = {"hidden", "submit", "button", "checkbox", "radio", "file", "image"}

LOGIN_LINK_HINTS: tuple[str, ...] = (
    "login",
    "log-in",
    "signin",
    "sign-in",
    "sign_in",
    "auth",
)


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


def _login_fields(form: dict) -> tuple[str, str] | None:
    inputs = [
        element
        for element in form.get("inputs", [])
        if str(element.get("name") or "").strip()
    ]
    password = next(
        (element for element in inputs if str(element.get("type") or "").lower() == "password"),
        None,
    )
    if not password:
        return None

    candidates = [
        element
        for element in inputs
        if str(element.get("type") or "").lower() not in NON_LOGIN_INPUT_TYPES
        and str(element.get("type") or "").lower() != "password"
    ]
    for element in candidates:
        name = str(element.get("name") or "").strip().lower()
        if any(hint in name for hint in LOGIN_USERNAME_HINTS):
            return str(element["name"]), str(password["name"])

    if candidates:
        return str(candidates[0]["name"]), str(password["name"])
    return None


def _sqli_admin_target(origin: str, inventory: dict) -> str:
    origin_host = urlsplit(origin).netloc.lower()
    same_origin: list[str] = []
    for hint in inventory.get("admin_hints", []):
        href = str(hint.get("href") or "")
        if href.startswith("http") and urlsplit(href).netloc.lower() == origin_host:
            same_origin.append(href)

    for href in same_origin:
        path = urlsplit(href).path.lower()
        if any(path == candidate or path.startswith(candidate + "/") for candidate in ADMIN_PATHS):
            return href

    if same_origin:
        return same_origin[0]
    return urljoin(origin + "/", ADMIN_PATHS[0].lstrip("/"))


def _sqli_action(
    *,
    page_url: str,
    action: str,
    method: str,
    username_field: str,
    password_field: str,
    payload: str,
    admin_target: str,
) -> dict:
    login = {
        "page_url": page_url,
        "action": action,
        "method": method,
        "username_field": username_field,
        "password_field": password_field,
        "username_payload": payload,
        "password_payload": SQLI_PASSWORD_PAYLOAD,
        "admin_target": admin_target,
    }
    field_label = username_field or "auto-detected username"
    return {
        "id": _action_id(f"sqli {method} {action} {payload} {username_field}"),
        "playbook": "sql_injection_auth_bypass",
        "description": (
            f"Attempt SQL injection login bypass on '{field_label}' at {action}"
        ),
        "method": method,
        "target": action,
        "page_url": page_url,
        "params": {},
        "tool": "browser_sql_login",
        "verifier": "sql_injection_login",
        "action_class": "STATE_CHANGE",
        "login": login,
    }


def _sqli_candidates(origin: str, snapshot: dict, inventory: dict) -> list[dict]:
    page_url = str(snapshot.get("url") or origin)
    admin_target = _sqli_admin_target(origin, inventory)
    candidates: list[dict] = []

    for form in snapshot.get("forms", []):
        fields = _login_fields(form)
        if not fields:
            continue
        username_field, password_field = fields
        action = str(form.get("action") or page_url)
        method = str(form.get("method") or "POST").upper()
        if method not in {"GET", "POST"}:
            method = "POST"
        candidates.extend(
            _sqli_action(
                page_url=page_url,
                action=action,
                method=method,
                username_field=username_field,
                password_field=password_field,
                payload=payload,
                admin_target=admin_target,
            )
            for payload in SQLI_USERNAME_PAYLOADS
        )

    if candidates:
        return candidates

    seen: set[str] = set()
    for link in snapshot.get("links", []):
        href = str(link.get("href") or "")
        if not href.startswith("http") or href in seen:
            continue
        haystack = f"{href} {link.get('text') or ''}".lower()
        if "logout" in haystack or not any(hint in haystack for hint in LOGIN_LINK_HINTS):
            continue
        seen.add(href)
        candidates.extend(
            _sqli_action(
                page_url=href,
                action=href,
                method="POST",
                username_field="",
                password_field="",
                payload=payload,
                admin_target=admin_target,
            )
            for payload in SQLI_USERNAME_PAYLOADS
        )
        if len(seen) >= 2:
            break

    return candidates


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
    include_sqli: bool = False,
) -> list[dict]:
    origin = _origin(snapshot, target_url)
    candidates: list[dict] = []

    if include_sqli:
        candidates.extend(_sqli_candidates(origin, snapshot, inventory))

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
    seen: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        login = candidate.get("login") or {}
        key = (
            candidate["method"],
            candidate["target"],
            str(login.get("username_payload") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)

    return deduped[:max_actions]
