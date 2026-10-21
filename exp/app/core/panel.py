from __future__ import annotations

from urllib.parse import urlsplit

ADMIN_MARKERS = (
    "admin panel",
    "administrator",
    "is_admin",
    'role="admin"',
    "role: admin",
    "superuser",
    "dashboard",
    "privileged",
    "switch to admin",
)

LOGIN_MARKERS = (
    "sign in",
    "signin",
    "log in",
    "please login",
    "password",
    "unauthorized",
    "access denied",
    "forbidden",
    "authentication required",
)

ADMIN_PATH_HINTS = (
    "/admin",
    "/dashboard",
    "/panel",
    "/manage",
    "/console",
)

PASSWORD_FIELD_MARKERS = ('type="password"', "type='password'")


def contains_password_field(body: str) -> bool:
    lowered = (body or "").lower()
    return any(marker in lowered for marker in PASSWORD_FIELD_MARKERS)


def admin_path(url: str) -> str | None:
    path = (urlsplit(url).path or "").lower()
    for hint in ADMIN_PATH_HINTS:
        if hint in path:
            return hint
    return None


def detect_admin_panel(body: str, url: str) -> str | None:
    lowered = (body or "").lower()
    marker = next((item for item in ADMIN_MARKERS if item in lowered), None)
    path_hit = admin_path(url)
    if not marker and not path_hit:
        return None
    if contains_password_field(body):
        return None
    return marker or f"admin path {path_hit}"
