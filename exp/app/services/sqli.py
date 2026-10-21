from __future__ import annotations

from contextlib import suppress
from typing import Any

from app.browser.tinyfish import browser_session
from app.browser.tools import navigate, page_excerpt, screenshot, submit_login_form
from app.config import ALLOWED_HOSTS
from app.core.audit import AuditLog
from app.core.panel import admin_path, detect_admin_panel
from app.core.policy import Scope


async def attempt_sql_injection_login(
    run_id: str,
    target_url: str,
    action: dict[str, Any],
) -> dict[str, Any]:
    login = action.get("login") or {}
    page_url = str(login.get("page_url") or target_url)
    admin_target = login.get("admin_target")
    audit = AuditLog(run_id)
    audit.record(
        "sql_login_attempt",
        target=page_url,
        form_action=login.get("action"),
        username_field=login.get("username_field"),
        username_payload=login.get("username_payload"),
    )

    scope = Scope.from_hosts(ALLOWED_HOSTS)
    async with browser_session(page_url, scope) as session:
        submitted = await submit_login_form(session.page, login)
        excerpt = await page_excerpt(session.page)
        body = str(excerpt.get("body_excerpt") or "")
        final_url = str(excerpt.get("url") or session.page.url)
        matched = detect_admin_panel(body, final_url)

        if matched and admin_target and not admin_path(final_url):
            with suppress(Exception):
                await navigate(session.page, str(admin_target), scope)
                await session.page.wait_for_timeout(500)
                admin_excerpt = await page_excerpt(session.page)
                admin_body = str(admin_excerpt.get("body_excerpt") or "")
                admin_url = str(admin_excerpt.get("url") or session.page.url)
                admin_matched = detect_admin_panel(admin_body, admin_url)
                if admin_matched:
                    body = admin_body
                    final_url = admin_url
                    matched = admin_matched
                    excerpt = admin_excerpt

        shot: str | None = None
        if matched:
            shot = await screenshot(session.page, "admin-panel", prefix="sqli")
            audit.record(
                "sql_login_success",
                final_url=final_url,
                matched_marker=matched,
                screenshot=shot,
            )
        else:
            audit.record(
                "sql_login_failed",
                final_url=final_url,
                submitted=submitted.get("submitted"),
                reason=submitted.get("reason"),
            )

        return {
            "url": final_url,
            "status": 200,
            "headers": {},
            "body_excerpt": body,
            "truncated": bool(excerpt.get("truncated")),
            "submitted": bool(submitted.get("submitted")),
            "submit_error": submitted.get("reason"),
            "authenticated": bool(matched),
            "matched_marker": matched,
            "screenshot": shot,
            "browser_mode": session.mode,
            "payload": login.get("username_payload"),
        }
