from app.browser.tinyfish import _install_scope_guard
from app.core.policy import Scope


class _FakeContext:
    def __init__(self) -> None:
        self.routes: list[tuple[str, object]] = []

    async def route(self, pattern: str, handler: object) -> None:
        self.routes.append((pattern, handler))


async def test_scope_guard_registers_route_handler():
    context = _FakeContext()
    scope = Scope.from_hosts(["staging.example.com"])

    await _install_scope_guard(context, scope)

    assert len(context.routes) == 1
    assert context.routes[0][0] == "**/*"
