import os
import base64
import hashlib
from pathlib import Path
from typing import Optional, Union

SCREENSHOTS_DIR = Path(__file__).resolve().parent / "screenshots"
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

    # If it is already a filename (e.g. shot_abc123.png) and not a data URI or long base64 string
    if isinstance(data, str) and not data.startswith("data:image/") and len(data) < 255:
        if (SCREENSHOTS_DIR / data).exists() or data.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            return Path(data).name

    try:
        raw_bytes: bytes
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
                else:
                    ext = "png"
                clean_str = b64_part

            # Pad base64 if needed
            pad = len(clean_str) % 4
            if pad:
                clean_str += "=" * (4 - pad)
            raw_bytes = base64.b64decode(clean_str)
        else:
            return None

        if not raw_bytes:
            return None

        # Content hash for deduplication and consistent naming
        content_hash = hashlib.sha256(raw_bytes).hexdigest()[:16]

        if filename:
            # Sanitize custom filename
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
    safe_name = Path(filename).name
    return SCREENSHOTS_DIR / safe_name
