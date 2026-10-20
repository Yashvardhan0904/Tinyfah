import pytest

from app.core import policy
from app.core.policy import (
    ActionClass,
    PolicyViolation,
    RequestBudget,
    Scope,
    assert_public_resolution,
    classify_action,
    enforce_action,
    host_allowed,
    redact_headers,
    redact_text,
    redact_url,
)


def test_scope_accepts_allowlisted_https_host():
    scope = Scope.from_hosts(["staging.example.com"])
    assert scope.validate("https://staging.example.com/login?next=%2F") == (
        "https://staging.example.com/login?next=%2F"
    )


def test_scope_rejects_http():
    scope = Scope.from_hosts(["staging.example.com"])
    with pytest.raises(PolicyViolation):
        scope.validate("http://staging.example.com")


def test_scope_rejects_empty_allowlist():
    scope = Scope.from_hosts([])
    with pytest.raises(PolicyViolation):
        scope.validate("https://staging.example.com")


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/",
        "https://127.0.0.1/",
        "https://10.0.0.5/",
        "https://169.254.169.254/latest/meta-data",
        "https://metadata.google.internal/",
        "https://staging.example.com.evil.test/",
        "https://user:pass@staging.example.com/",
        "https://evil.test/",
        "https://staging example.com/",
        "https://staging_example.com/",
    ],
)
def test_scope_rejects_unsafe_targets(url):
    scope = Scope.from_hosts(["staging.example.com"])
    with pytest.raises(PolicyViolation):
        scope.validate(url)


def test_wildcard_allowlist_matches_subdomains_only():
    scope = Scope.from_hosts(["*.example.com"])
    assert scope.validate("https://app.example.com/")
    with pytest.raises(PolicyViolation):
        scope.validate("https://example.com/")
    with pytest.raises(PolicyViolation):
        scope.validate("https://example.com.evil.test/")


def test_redirect_validation():
    scope = Scope.from_hosts(["staging.example.com"])
    assert (
        scope.validate_redirect("https://staging.example.com/a", "/admin")
        == "https://staging.example.com/admin"
    )
    with pytest.raises(PolicyViolation):
        scope.validate_redirect("https://staging.example.com/a", "https://evil.test/")


def test_host_allowed_exact_and_wildcard():
    assert host_allowed("staging.example.com", ["staging.example.com"])
    assert host_allowed("app.example.com", ["*.example.com"])
    assert not host_allowed("example.com", ["*.example.com"])


def test_classify_actions():
    assert classify_action("GET") is ActionClass.PROBE
    assert classify_action("HEAD") is ActionClass.READ
    assert classify_action("POST") is ActionClass.STATE_CHANGE
    assert classify_action("GET", tool="submit_login") is ActionClass.STATE_CHANGE
    assert classify_action("GET", detail="DROP TABLE users") is ActionClass.DESTRUCTIVE


def test_enforce_action():
    enforce_action(ActionClass.READ)
    with pytest.raises(PolicyViolation):
        enforce_action(ActionClass.DESTRUCTIVE)
    with pytest.raises(PolicyViolation):
        enforce_action(ActionClass.STATE_CHANGE, approved=True, state_change_enabled=False)
    with pytest.raises(PolicyViolation):
        enforce_action(ActionClass.STATE_CHANGE, approved=False, state_change_enabled=True)
    enforce_action(ActionClass.STATE_CHANGE, approved=True, state_change_enabled=True)


def test_redaction():
    headers = redact_headers({"Authorization": "Bearer secret", "Content-Type": "text/html"})
    assert headers["Authorization"] == "[redacted]"
    assert headers["Content-Type"] == "text/html"

    redacted = redact_url("https://staging.example.com/reset?token=abc123&id=5")
    assert "token=%5Bredacted%5D" in redacted
    assert "id=5" in redacted

    assert "secret-token" not in redact_text("Authorization: Bearer secret-token")


def test_request_budget():
    budget = RequestBudget(2)
    budget.consume()
    budget.consume()
    assert budget.remaining == 0
    with pytest.raises(PolicyViolation):
        budget.consume()


class _FakeLoop:
    def __init__(self, address: str) -> None:
        self.address = address

    async def getaddrinfo(self, *_args, **_kwargs):
        return [(2, 1, 6, "", (self.address, 0))]


async def test_public_resolution_rejects_private_address(monkeypatch):
    monkeypatch.setattr(policy.asyncio, "get_running_loop", lambda: _FakeLoop("10.0.0.5"))
    with pytest.raises(PolicyViolation):
        await assert_public_resolution("https://staging.example.com/")


async def test_public_resolution_accepts_public_address(monkeypatch):
    monkeypatch.setattr(policy.asyncio, "get_running_loop", lambda: _FakeLoop("93.184.216.34"))
    await assert_public_resolution("https://staging.example.com/")
