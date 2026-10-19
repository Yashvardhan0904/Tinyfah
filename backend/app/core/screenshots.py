import os
import base64
import hashlib
from pathlib import Path
from typing import Optional, Union, Dict, Any, List
from app.config import SCREENSHOTS_DIR

SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

def save_screenshot(
    data: Union[str, bytes],
    filename: Optional[str] = None,
    prefix: str = "shot",
) -> Optional[str]:
    """
    Saves screenshot bytes or base64 data to SCREENSHOTS_DIR and returns only the filename.
    If data is already a screenshot filename pointing to an existing file or matching a filename pattern,
    it returns that filename directly without re-saving.
    """
    if not data:
        return None

    # Return directly if already an existing filename or recognized extension
    if isinstance(data, str) and not data.startswith("data:image/") and len(data) < 255:
        if (SCREENSHOTS_DIR / data).exists() or data.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            return Path(data).name

    try:
        ext = "png"
        if isinstance(data, bytes):
            raw_bytes = data
        elif isinstance(data, str):
            clean_str = data.strip()
            if clean_str.startswith("data:image/"):
                header, b64_part = clean_str.split(",", 1)
                if "jpeg" in header or "jpg" in header:
                    ext = "jpg"
                elif "webp" in header:
                    ext = "webp"
                clean_str = b64_part

            pad = len(clean_str) % 4
            if pad:
                clean_str += "=" * (4 - pad)
            raw_bytes = base64.b64decode(clean_str)
        else:
            return None

        if not raw_bytes:
            return None

        content_hash = hashlib.sha256(raw_bytes).hexdigest()[:16]

        if filename:
            safe_name = Path(filename).name.replace(":", "_").replace("/", "_")
            if not safe_name.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                safe_name = f"{safe_name}.{ext}"
            target_filename = safe_name
        else:
            safe_prefix = prefix.replace(":", "_").replace("/", "_")
            target_filename = f"{safe_prefix}_{content_hash}.{ext}"

        file_path = SCREENSHOTS_DIR / target_filename
        if not file_path.exists():
            with open(file_path, "wb") as f:
                f.write(raw_bytes)

        return target_filename
    except Exception:
        return None

def get_screenshot_path(filename: str) -> Path:
    """Returns absolute Path to the screenshot file, preventing directory traversal."""
    return SCREENSHOTS_DIR / Path(filename).name

async def capture_hud_screenshot(
    page: Any,
    cdp: Any,
    target_url: str = "",
    doc_headers: Optional[Dict[str, str]] = None,
    http_status: Optional[int] = None,
    console_logs: Optional[List[Dict[str, Any]]] = None,
    test_info: Optional[Dict[str, Any]] = None,
    prefix: str = "shot",
    format_choice: str = "png",
    quality: int = 80,
) -> Optional[str]:
    """
    Injects the Chrome DevTools HUD dock onto the page, takes a screenshot via CDP
    (falling back to page.screenshot), removes the dock, and returns the saved filename.
    """
    if format_choice not in ["png", "jpeg"]:
        format_choice = "png"

    dock_injected = False
    if page:
        try:
            from harness.console_hud import build_console_logs, INJECT_CONSOLE_JS
            t_url = target_url or getattr(page, "url", "https://target")
            logs = build_console_logs(
                target_url=t_url,
                doc_headers=doc_headers or {},
                http_status=http_status,
                captured_logs=console_logs or [],
                current_test=test_info,
            )
            await page.evaluate(INJECT_CONSOLE_JS, {
                "logs": logs,
                "target_url": t_url,
                "current_test": test_info.get("name") if test_info else "",
            })
            dock_injected = True
            await page.wait_for_timeout(100)
        except Exception:
            pass

    try:
        if cdp:
            try:
                await cdp.send("Page.enable")
                send_args: Dict[str, Any] = {"format": format_choice}
                if format_choice == "jpeg":
                    send_args["quality"] = quality
                cdp_res = await cdp.send("Page.captureScreenshot", send_args)
                if cdp_res and "data" in cdp_res:
                    return save_screenshot(cdp_res["data"], prefix=prefix)
            except Exception:
                pass

        if page:
            try:
                raw_bytes = await page.screenshot(type=format_choice)
                return save_screenshot(raw_bytes, prefix=prefix)
            except Exception:
                pass
    finally:
        if dock_injected and page:
            try:
                from harness.console_hud import REMOVE_CONSOLE_JS
                await page.evaluate(REMOVE_CONSOLE_JS)
            except Exception:
                pass

    return None
