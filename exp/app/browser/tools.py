from __future__ import annotations

import re
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from playwright.async_api import Page

from app.config import MAX_RESPONSE_BYTES, SCREENSHOTS_DIR
from app.core.policy import Scope

_SAFE_NAME = re.compile(r"[^a-zA-Z0-9_.-]+")

RECON_SCRIPT = """
() => {
    const shorten = (value, limit) => (value || "").toString().slice(0, limit);
    const forms = Array.from(document.forms).slice(0, 25).map((form) => ({
        action: shorten(form.action, 300),
        method: (form.method || "get").toUpperCase(),
        inputs: Array.from(form.elements)
            .filter((element) => ["INPUT", "TEXTAREA", "SELECT"].includes(element.tagName))
            .slice(0, 30)
            .map((element) => ({
                name: shorten(element.name, 120),
                type: shorten(element.type || element.tagName, 40),
                autocomplete: shorten(element.autocomplete, 60)
            }))
    }));
    const links = Array.from(document.querySelectorAll("a[href]"))
        .slice(0, 200)
        .map((anchor) => ({
            href: shorten(anchor.href, 400),
            text: shorten(anchor.innerText || anchor.textContent, 120)
        }));
    const scripts = Array.from(document.scripts)
        .filter((script) => script.src)
        .slice(0, 50)
        .map((script) => shorten(script.src, 400));
    const meta = Array.from(document.querySelectorAll("meta[http-equiv], meta[name]"))
        .slice(0, 40)
        .map((tag) => ({
            name: shorten(tag.getAttribute("name") || tag.getAttribute("http-equiv"), 80),
            content: shorten(tag.getAttribute("content"), 200)
        }));
    const cookieNames = document.cookie
        .split(";")
        .map((part) => part.split("=")[0].trim())
        .filter(Boolean)
        .slice(0, 50);
    return {
        title: shorten(document.title, 200),
        url: location.href,
        origin: location.origin,
        protocol: location.protocol,
        readyState: document.readyState,
        formCount: document.forms.length,
        linkCount: document.querySelectorAll("a[href]").length,
        scriptCount: document.scripts.length,
        forms: forms,
        links: links,
        scripts: scripts,
        meta: meta,
        localStorageKeys: Object.keys(window.localStorage).slice(0, 50),
        sessionStorageKeys: Object.keys(window.sessionStorage).slice(0, 50),
        cookieNames: cookieNames,
        hasPasswordField: Boolean(document.querySelector('input[type="password"]')),
        adminHints: links
            .filter((link) =>
                /admin|dashboard|debug|internal|manage|config/i.test(link.href + " " + link.text)
            )
            .slice(0, 25)
    };
}
"""


LOGIN_SUBMIT_SCRIPT = """
(spec) => {
    const forms = Array.from(document.forms);
    const form =
        forms.find((candidate) => candidate.querySelector('input[type="password"]')) ||
        forms.find((candidate) => (candidate.action || "") === spec.action);
    if (!form) {
        return { ok: false, reason: "login form not found" };
    }

    const resolve = (name) => {
        if (!name) return null;
        const item = form.elements.namedItem(name);
        if (!item) return null;
        return item instanceof RadioNodeList ? item[0] : item;
    };
    const setValue = (element, value) => {
        if (!element) return false;
        element.focus();
        element.value = value;
        element.dispatchEvent(new Event("input", { bubbles: true }));
        element.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
    };

    const hints = ["username", "user", "email", "login", "userid", "user_id", "account", "name"];
    const textInputs = Array.from(form.elements).filter((element) =>
        ["text", "email"].includes((element.type || "").toLowerCase())
    );
    const fallbackUser =
        textInputs.find((element) =>
            hints.some((hint) => (element.name || "").toLowerCase().includes(hint))
        ) || textInputs[0];
    const userElement = resolve(spec.usernameField) || fallbackUser;
    const passwordElement =
        resolve(spec.passwordField) || form.querySelector('input[type="password"]');

    if (!setValue(userElement, spec.usernamePayload)) {
        return { ok: false, reason: "username field not found" };
    }
    if (!setValue(passwordElement, spec.passwordPayload)) {
        return { ok: false, reason: "password field not found" };
    }

    if (typeof form.requestSubmit === "function") {
        form.requestSubmit();
    } else {
        form.submit();
    }
    return { ok: true };
}
"""


def _safe_filename(name: str) -> str:
    cleaned = _SAFE_NAME.sub("-", name).strip("-")[:80]
    return cleaned or "snapshot"


async def recon_snapshot(page: Page) -> dict:
    return await page.evaluate(RECON_SCRIPT)


async def navigate(page: Page, url: str, scope: Scope) -> dict:
    canonical = scope.validate(url)
    response = await page.goto(canonical, wait_until="domcontentloaded", timeout=20000)
    return {
        "url": page.url,
        "status": response.status if response else None,
        "navigation_allowed": True,
    }


async def submit_login_form(page: Page, login: dict) -> dict:
    before = page.url
    result = await page.evaluate(LOGIN_SUBMIT_SCRIPT, login)
    if not result.get("ok"):
        return {"submitted": False, "reason": result.get("reason"), "url": page.url}

    with suppress(Exception):
        await page.wait_for_url(lambda url: url != before, timeout=6000)
    await page.wait_for_timeout(1000)
    return {"submitted": True, "url": page.url}


async def page_excerpt(page: Page) -> dict:
    content = await page.content()
    truncated = len(content.encode("utf-8", errors="replace")) > MAX_RESPONSE_BYTES
    return {
        "url": page.url,
        "body_excerpt": content[:MAX_RESPONSE_BYTES],
        "truncated": truncated,
    }


async def screenshot(page: Page, name: str, prefix: str = "recon") -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{timestamp}_{prefix}_{_safe_filename(name)}_{uuid.uuid4().hex[:8]}.png"
    path = SCREENSHOTS_DIR / filename
    await page.screenshot(path=str(path), full_page=False)
    return filename


def screenshot_path(filename: str) -> Path:
    return SCREENSHOTS_DIR / filename


async def collect_endpoint_inventory(snapshot: dict) -> dict:
    links = snapshot.get("links", [])
    forms = snapshot.get("forms", [])
    paths = sorted(
        {item.get("href", "") for item in links if item.get("href", "").startswith("http")}
        | {item.get("action", "") for item in forms if item.get("action", "").startswith("http")}
    )
    return {
        "paths": paths[:200],
        "forms": forms,
        "admin_hints": snapshot.get("adminHints", []),
        "has_password_field": snapshot.get("hasPasswordField", False),
    }
