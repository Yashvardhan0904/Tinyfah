from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import parse_qsl, unquote_plus, urlencode, urljoin, urlsplit, urlunsplit

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254",
}

BLOCKED_SUFFIXES = (".local", ".internal", ".localhost", ".home.arpa")

DANGEROUS_PATTERNS = (
    "drop table",
    "delete from",
    "truncate table",
    "rm -rf",
    "mkfs",
    "shutdown",
    "reverse shell",
    "nc -e",
    "chmod 777",
    "format c:",
    "xp_cmdshell",
    "into outfile",
    "load_file(",
    "pg_read_file",
)

STATE_CHANGE_TOKENS = (
    "login",
    "logout",
    "submit",
    "create",
    "update",
    "delete",
    "upload",
    "register",
    "approve",
    "assign",
    "grant",
    "revoke",
    "change_password",
    "reset_password",
)

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
    "x-csrf-token",
    "x-xsrf-token",
}

SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "code",
    "jwt",
    "key",
    "password",
    "passwd",
    "secret",
    "session",
    "sessionid",
    "sig",
    "signature",
    "token",
}

SECRET_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[a-z0-9._\-]{8,}"),
    re.compile(r"(?i)(api[_-]?key[=:]\s*)[a-z0-9._\-]{8,}"),
    re.compile(
        r"(?i)((?:password|passwd|secret|token|session|jwt|signature|sig)\s*[=:]\s*)[^\s&;\"']+"
    ),
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{5,}"),
)


class PolicyViolation(ValueError):
    pass


class ActionClass(StrEnum):
    READ = "READ"
    PROBE = "PROBE"
    STATE_CHANGE = "STATE_CHANGE"
    DESTRUCTIVE = "DESTRUCTIVE"


HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")


def normalize_host(host: str) -> str:
    value = (host or "").strip().lower().rstrip(".")
    if not value:
        raise PolicyViolation("Target host is empty")
    wildcard = value.startswith("*.")
    candidate = value[2:] if wildcard else value
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise PolicyViolation(f"Invalid hostname: {host}") from exc
    if not HOSTNAME_RE.fullmatch(candidate):
        raise PolicyViolation(f"Invalid hostname: {host}")
    return f"*.{candidate}" if wildcard else candidate


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_forbidden_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def assert_public_resolution(url: str) -> None:
    host = urlsplit(url).hostname
    if not host:
        raise PolicyViolation("Target URL is missing a hostname")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise PolicyViolation(f"DNS resolution failed for '{host}'") from exc
    if not infos:
        raise PolicyViolation(f"DNS resolution returned no addresses for '{host}'")
    for info in infos:
        address = str(info[4][0]).split("%", 1)[0]
        if _is_forbidden_ip(address):
            raise PolicyViolation(
                f"Target host '{host}' resolves to non-public address '{address}'"
            )


def host_allowed(host: str, allowed_hosts: Iterable[str]) -> bool:
    normalized = normalize_host(host)
    entries = tuple(allowed_hosts)
    if not entries:
        return False
    for entry in entries:
        pattern = normalize_host(entry)
        if pattern.startswith("*."):
            base = pattern[2:]
            if normalized.endswith("." + base) and normalized != base:
                return True
        elif normalized == pattern:
            return True
    return False


@dataclass(frozen=True)
class Scope:
    allowed_hosts: tuple[str, ...]
    require_https: bool = True

    @classmethod
    def from_hosts(cls, hosts: Iterable[str], require_https: bool = True) -> Scope:
        return cls(tuple(normalize_host(h) for h in hosts if h), require_https=require_https)

    def validate(self, url: str) -> str:
        if not isinstance(url, str) or not url.strip():
            raise PolicyViolation("Target URL is empty")
        try:
            parts = urlsplit(url.strip())
            port = parts.port
        except ValueError as exc:
            raise PolicyViolation(f"Malformed target URL: {url}") from exc

        scheme = (parts.scheme or "").lower()
        if scheme not in {"http", "https"}:
            raise PolicyViolation(f"Unsupported scheme: {scheme or '(none)'}")
        if self.require_https and scheme != "https":
            raise PolicyViolation("Only https:// targets are permitted")

        if parts.username or parts.password:
            raise PolicyViolation("Credentials in URLs are not permitted")

        host = normalize_host(parts.hostname or "")
        if host in BLOCKED_HOSTS or host.endswith(BLOCKED_SUFFIXES):
            raise PolicyViolation(f"Target host '{host}' is blocked")
        if _is_ip_literal(host):
            raise PolicyViolation(f"IP-literal targets are not permitted: {host}")
        if _is_forbidden_ip(host):
            raise PolicyViolation(f"Target IP '{host}' is out of scope")
        if not host_allowed(host, self.allowed_hosts):
            raise PolicyViolation(f"Target host '{host}' is not in EXPLOIT_ALLOWED_HOSTS")
        if "." not in host:
            raise PolicyViolation(f"Single-label host '{host}' is not permitted")
        if port is not None and not (1 <= port <= 65535):
            raise PolicyViolation(f"Invalid port: {port}")

        return urlunsplit(
            (
                scheme,
                host if port in (None, 443) else f"{host}:{port}",
                parts.path or "/",
                parts.query,
                "",
            )
        )

    def validate_redirect(self, base_url: str, location: str) -> str:
        if not location:
            raise PolicyViolation("Redirect without Location header")
        candidate = urljoin(base_url, location)
        return self.validate(candidate)

    def allows(self, url: str) -> bool:
        try:
            self.validate(url)
            return True
        except PolicyViolation:
            return False


def classify_action(method: str = "GET", tool: str = "", detail: str = "") -> ActionClass:
    haystack = unquote_plus(f"{method} {tool} {detail}").lower()
    if any(pattern in haystack for pattern in DANGEROUS_PATTERNS):
        return ActionClass.DESTRUCTIVE
    if (method or "GET").upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        return ActionClass.STATE_CHANGE
    if any(token in haystack for token in STATE_CHANGE_TOKENS):
        return ActionClass.STATE_CHANGE
    if (method or "GET").upper() == "HEAD":
        return ActionClass.READ
    if (method or "GET").upper() == "OPTIONS":
        return ActionClass.PROBE
    return ActionClass.PROBE


def enforce_action(
    action: ActionClass,
    *,
    approved: bool = False,
    state_change_enabled: bool = False,
) -> None:
    if action is ActionClass.DESTRUCTIVE:
        raise PolicyViolation("Destructive actions are permanently blocked")
    if action is ActionClass.STATE_CHANGE:
        if not state_change_enabled:
            raise PolicyViolation(
                "State-changing actions are disabled (EXPLOIT_ENABLE_STATE_CHANGE=false)"
            )
        if not approved:
            raise PolicyViolation("State-changing action requires explicit human approval")


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        key: ("[redacted]" if key.lower() in SENSITIVE_HEADERS else str(value))
        for key, value in headers.items()
    }


def redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        query = [
            (key, "[redacted]" if key.lower() in SENSITIVE_QUERY_KEYS else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
        )
    except Exception:
        return "[unparseable-url]"


def redact_text(text: str) -> str:
    value = str(text)
    for pattern in SECRET_PATTERNS:
        if pattern.groups:
            value = pattern.sub(r"\1[redacted]", value)
        else:
            value = pattern.sub("[redacted]", value)
    return value


class RateLimiter:
    def __init__(self, max_rps: float) -> None:
        self._interval = (1.0 / max_rps) if max_rps > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_at = 0.0

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            scheduled = max(now, self._next_at)
            self._next_at = scheduled + self._interval
            wait_for = scheduled - now
        if wait_for > 0:
            await asyncio.sleep(wait_for)


class RequestBudget:
    def __init__(self, limit: int) -> None:
        self._limit = max(0, int(limit))
        self._used = 0

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int:
        return max(0, self._limit - self._used)

    def consume(self) -> None:
        if self._used >= self._limit:
            raise PolicyViolation(f"Request budget exhausted ({self._limit})")
        self._used += 1
