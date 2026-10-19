import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable, Awaitable

@dataclass
class HarnessContext:
    page: Any
    cdp: Any
    target_url: str
    doc_headers: Dict[str, str] = field(default_factory=dict)
    cdp_issues: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    http_status: Optional[int] = None

    async def capture_screenshot(self, format: str = "png") -> Optional[str]:
        """
        Captures a screenshot of the current page state using CDP Page.captureScreenshot.
        Returns base64 data URI (data:image/png;base64,...), falling back to Playwright if needed.
        """
        if self.cdp:
            try:
                await self.cdp.send("Page.enable")
                res = await self.cdp.send("Page.captureScreenshot", {"format": format})
                if res and "data" in res:
                    return f"data:image/{format};base64,{res['data']}"
            except Exception:
                pass
        if self.page:
            try:
                import base64
                img_bytes = await self.page.screenshot(type=format)
                b64_str = base64.b64encode(img_bytes).decode("utf-8")
                return f"data:image/{format};base64,{b64_str}"
            except Exception:
                pass
        return None

@dataclass
class TestResult:
    shortcode: str
    name: str
    status: str       # "PASS" | "FAIL" | "MANUAL_VERIFY" | "NOT_TESTED" | "ERROR"
    severity: str     # "high" | "medium" | "low" | "info"
    evidence: str
    remediation: str = ""
    test_hint: str = ""
    required_inputs: List[str] = field(default_factory=list)
    chapter: str = ""
    level: int = 1
    tinyfish_mode: str = "BROWSER_SCRIPT"
    duration_ms: int = 0
    target_url: str = ""
    http_status: Optional[int] = None
    observations: str = ""
    expected_behavior: str = ""
    limitations: str = ""
    execution_error: Optional[str] = None
    screenshot: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "shortcode": self.shortcode,
            "requirement_id": self.shortcode,
            "name": self.name,
            "status": self.status,
            "severity": self.severity,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "test_hint": self.test_hint,
            "required_inputs": self.required_inputs,
            "chapter": self.chapter,
            "chapter_name": self.chapter,
            "level": self.level,
            "tinyfish_mode": self.tinyfish_mode,
            "duration_ms": self.duration_ms,
            "target_url": self.target_url,
            "http_status": self.http_status,
            "observations": self.observations or self.evidence,
            "expected_behavior": self.expected_behavior,
            "limitations": self.limitations,
            "execution_error": self.execution_error,
            "screenshot": self.screenshot,
        }

TestFunction = Callable[[HarnessContext], Awaitable[TestResult]]

_TEST_REGISTRY: Dict[str, Dict[str, Any]] = {}

def register_test(shortcode: str, name: str, description: Optional[str] = None):
    """
    Decorator to register a deterministic test script for a specific ASVS / Tinyfah requirement.
    Usage:
        @register_test("V1.2.1", "HTML & Attribute Output Encoding")
        async def test_v1_2_1(ctx: HarnessContext) -> TestResult:
            ...
    """
    def decorator(fn: TestFunction):
        sc_upper = shortcode.strip().upper()
        _TEST_REGISTRY[sc_upper] = {
            "shortcode": sc_upper,
            "name": name,
            "description": description or name,
            "fn": fn,
        }
        return fn
    return decorator

def get_registered_test(shortcode: str) -> Optional[Dict[str, Any]]:
    return _TEST_REGISTRY.get(shortcode.strip().upper())

def list_registered_tests() -> Dict[str, Dict[str, Any]]:
    return dict(_TEST_REGISTRY)
