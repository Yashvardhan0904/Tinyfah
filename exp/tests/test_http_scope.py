import pytest

from app.core.policy import PolicyViolation, Scope
from app.http.client import ScopeLockedClient


async def test_client_rejects_off_scope_before_network():
    scope = Scope.from_hosts(["staging.example.com"])
    async with ScopeLockedClient(scope) as client:
        with pytest.raises(PolicyViolation):
            await client.get("https://evil.test/")
        with pytest.raises(PolicyViolation):
            await client.get("http://staging.example.com/")
        with pytest.raises(PolicyViolation):
            await client.get("https://127.0.0.1/")


async def test_client_blocks_state_change_without_approval():
    scope = Scope.from_hosts(["staging.example.com"])
    async with ScopeLockedClient(scope, allow_state_change=True) as client:
        with pytest.raises(PolicyViolation):
            await client.request("POST", "https://staging.example.com/login", content="x=1")


async def test_client_blocks_destructive():
    scope = Scope.from_hosts(["staging.example.com"])
    async with ScopeLockedClient(scope) as client:
        with pytest.raises(PolicyViolation):
            await client.request(
                "GET",
                "https://staging.example.com/",
                params={"q": "DROP TABLE users"},
            )
