from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass

import httpx
from playwright.async_api import (
    Browser,
    BrowserContext,
    CDPSession,
    Page,
    Playwright,
    Request,
    Route,
    async_playwright,
)

from app.config import (
    LOCAL_BROWSER_FALLBACK,
    MAX_CONCURRENT_SESSIONS,
    TINYFISH_API_KEY,
    TINYFISH_URL,
)
from app.core.policy import PolicyViolation, Scope, assert_public_resolution

_session_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SESSIONS)


@dataclass
class BrowserSession:
    playwright: Playwright
    browser: Browser
    context: BrowserContext
    page: Page
    cdp: CDPSession | None
    session_id: str | None
    mode: str

    async def close(self) -> None:
        with suppress(Exception):
            await self.browser.close()
        with suppress(Exception):
            await self.playwright.stop()
        if self.session_id:
            with suppress(Exception):
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.delete(
                        f"{TINYFISH_URL}/{self.session_id}",
                        headers={
                            "X-API-Key": TINYFISH_API_KEY,
                            "Content-Type": "application/json",
                        },
                    )


def _install_scope_guard(context: BrowserContext, scope: Scope) -> None:
    async def guard(route: Route, request: Request) -> None:
        if request.is_navigation_request() or request.resource_type in {"xhr", "fetch"}:
            try:
                scope.validate(request.url)
            except PolicyViolation:
                await route.abort("blockedbyclient")
                return
        await route.continue_()

    context.route("**/*", guard)


async def _create_tinyfish_session(target_url: str) -> tuple[str, str]:
    async with httpx.AsyncClient(timeout=65.0) as client:
        response = await client.post(
            TINYFISH_URL,
            headers={
                "X-API-Key": TINYFISH_API_KEY,
                "Content-Type": "application/json",
            },
            json={"url": target_url},
        )
        response.raise_for_status()
        data = response.json()
    session_id = data.get("session_id")
    cdp_url = data.get("cdp_url")
    if not session_id or not cdp_url:
        raise RuntimeError("TinyFish session response missing session_id or cdp_url")
    return session_id, cdp_url


@asynccontextmanager
async def browser_session(
    target_url: str,
    scope: Scope,
    *,
    api_key: str | None = None,
) -> AsyncIterator[BrowserSession]:
    canonical = scope.validate(target_url)
    await assert_public_resolution(canonical)
    key = api_key if api_key is not None else TINYFISH_API_KEY

    async with _session_semaphore:
        playwright = await async_playwright().start()
        browser: Browser | None = None
        context: BrowserContext | None = None
        session_id: str | None = None
        mode = "local"

        try:
            if key.startswith("sk-tinyfish"):
                try:
                    session_id, cdp_url = await _create_tinyfish_session(canonical)
                    browser = await playwright.chromium.connect_over_cdp(cdp_url)
                    mode = "tinyfish"
                except Exception:
                    if not LOCAL_BROWSER_FALLBACK:
                        raise
                    browser = None
                    session_id = None

            if browser is None:
                browser = await playwright.chromium.launch(headless=True)
                mode = "local"

            context = browser.contexts[0] if browser.contexts else await browser.new_context()
            while len(context.pages) > 1:
                try:
                    await context.pages[-1].close()
                except Exception:
                    break
            page = context.pages[0] if context.pages else await context.new_page()

            with suppress(Exception):
                await context.clear_cookies()

            _install_scope_guard(context, scope)

            cdp: CDPSession | None = None
            try:
                cdp = await context.new_cdp_session(page)
                await cdp.send("Page.enable")
                await cdp.send("Network.enable")
            except Exception:
                cdp = None

            await page.goto(canonical, wait_until="domcontentloaded", timeout=20000)

            session = BrowserSession(
                playwright=playwright,
                browser=browser,
                context=context,
                page=page,
                cdp=cdp,
                session_id=session_id,
                mode=mode,
            )
            yield session
        finally:
            if browser is not None:
                with suppress(Exception):
                    await browser.close()
            if playwright is not None:
                with suppress(Exception):
                    await playwright.stop()
            if session_id:
                with suppress(Exception):
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        await client.delete(
                            f"{TINYFISH_URL}/{session_id}",
                            headers={
                                "X-API-Key": key,
                                "Content-Type": "application/json",
                            },
                        )
