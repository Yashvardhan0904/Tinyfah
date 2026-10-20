from __future__ import annotations

from app.browser.tinyfish import browser_session
from app.browser.tools import collect_endpoint_inventory, recon_snapshot, screenshot
from app.config import ALLOWED_HOSTS
from app.core.policy import Scope


async def perform_recon(target_url: str) -> dict:
    scope = Scope.from_hosts(ALLOWED_HOSTS)
    canonical = scope.validate(target_url)

    async with browser_session(canonical, scope) as session:
        snapshot = await recon_snapshot(session.page)
        inventory = await collect_endpoint_inventory(snapshot)
        shot = await screenshot(session.page, "recon", prefix="recon")

    return {
        "mode": "recon",
        "target_url": canonical,
        "browser_mode": session.mode,
        "snapshot": snapshot,
        "inventory": inventory,
        "screenshot": shot,
    }
