import httpx

from app.core import ownership
from app.core.ownership import verify_ownership
from app.core.policy import Scope


async def _noop_resolution(_url: str) -> None:
    return None


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_well_known_proof_verifies(monkeypatch):
    monkeypatch.setattr(ownership, "assert_public_resolution", _noop_resolution)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/tinyfah-secret-token.txt"
        return httpx.Response(200, text="secret-token")

    client = _client(handler)
    try:
        result = await verify_ownership(
            "https://staging.example.com/dashboard",
            "secret-token",
            Scope.from_hosts(["staging.example.com"]),
            client=client,
        )
    finally:
        await client.aclose()

    assert result.verified is True
    assert result.method == "well_known"


async def test_meta_tag_proof_verifies(monkeypatch):
    monkeypatch.setattr(ownership, "assert_public_resolution", _noop_resolution)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/.well-known/"):
            return httpx.Response(404, text="missing")
        return httpx.Response(
            200,
            text='<html><head><meta name="tinyfah-verify" content="secret-token"></head></html>',
        )

    client = _client(handler)
    try:
        result = await verify_ownership(
            "https://staging.example.com/",
            "secret-token",
            Scope.from_hosts(["staging.example.com"]),
            client=client,
        )
    finally:
        await client.aclose()

    assert result.verified is True
    assert result.method == "meta_tag"


async def test_missing_proof_is_not_verified(monkeypatch):
    monkeypatch.setattr(ownership, "assert_public_resolution", _noop_resolution)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>nothing here</html>")

    client = _client(handler)
    try:
        result = await verify_ownership(
            "https://staging.example.com/",
            "secret-token",
            Scope.from_hosts(["staging.example.com"]),
            client=client,
        )
    finally:
        await client.aclose()

    assert result.verified is False


async def test_empty_token_is_not_verified():
    result = await verify_ownership(
        "https://staging.example.com/",
        "",
        Scope.from_hosts(["staging.example.com"]),
    )
    assert result.verified is False
    assert "EXPLOIT_OWNER_TOKEN" in (result.reason or "")
