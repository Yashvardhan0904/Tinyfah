"""Screenshots module re-exporting screenshot utilities and directories."""
from app.config import SCREENSHOTS_DIR
from app.core.screenshots import (
    save_screenshot,
    get_screenshot_path,
    capture_hud_screenshot,
)

__all__ = [
    "SCREENSHOTS_DIR",
    "save_screenshot",
    "get_screenshot_path",
    "capture_hud_screenshot",
]
