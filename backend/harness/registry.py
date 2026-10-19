import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable, Awaitable, Union

@dataclass
class HarnessContext:
    page: Any
    cdp: Any
    target_url: str
    doc_headers: Dict[str, str] = field(default_factory=dict)
    cdp_issues: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    http_status: Optional[int] = None
    console_logs: List[Dict[str, Any]] = field(default_factory=list)

    async def capture_screenshot(
        self,
        format: str = "png",
        prefix: Optional[str] = None,
        test_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Captures a screenshot of the page with a Chrome DevTools Console dock
        displaying live browser logs, security audits, and test execution evidence.
        Saves the image to the screenshots directory, and returns only its filename.
        """
        from screenshots import save_screenshot
        safe_prefix = prefix or (self.metadata.get("shortcode") if self.metadata else None) or "shot"

        dock_injected = False
        if self.page:
            try:
                from harness.console_hud import build_console_logs, INJECT_CONSOLE_JS, REMOVE_CONSOLE_JS
                t_info = test_info or self.metadata
                logs = build_console_logs(
                    target_url=self.target_url,
                    doc_headers=self.doc_headers,
                    http_status=self.http_status,
                    captured_logs=self.console_logs,
                    current_test=t_info,
                )
                await self.page.evaluate(INJECT_CONSOLE_JS, {
                    "logs": logs,
                    "target_url": self.target_url,
                    "current_test": t_info.get("name") if t_info else "",
                })
                dock_injected = True
                await self.page.wait_for_timeout(100)
            except Exception:
                pass

        try:
            if self.cdp:
                try:
                    await self.cdp.send("Page.enable")
                    res = await self.cdp.send("Page.captureScreenshot", {"format": format})
                    if res and "data" in res:
                        return save_screenshot(res["data"], prefix=safe_prefix)
                except Exception:
                    pass
            if self.page:
                try:
                    img_bytes = await self.page.screenshot(type=format)
                    return save_screenshot(img_bytes, prefix=safe_prefix)
                except Exception:
                    pass
        finally:
            if dock_injected and self.page:
                try:
                    from harness.console_hud import REMOVE_CONSOLE_JS
                    await self.page.evaluate(REMOVE_CONSOLE_JS)
                except Exception:
                    pass

        return None

@dataclass
class TestCaseExecution:
    test_id: str
    description: str
    execution_status: str = "completed"  # "completed" | "failed" | "unsupported" | "skipped"
    observation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "description": self.description,
            "execution_status": self.execution_status,
            "observation": self.observation,
            "evidence": self.evidence,
        }

@dataclass
class ScriptDefinition:
    requirement_id: str
    script_id: str
    name: str
    chapter: str = "V1 Encoding and Sanitization"
    execution_mode: str = "BROWSER_SCRIPT"  # "BROWSER_SCRIPT" | "HYBRID" | "REVIEW"
    objective: str = ""
    preconditions: List[str] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    evidence_required: List[str] = field(default_factory=list)
    evaluation_rules: Dict[str, str] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    remediation: str = ""
    fn: Optional[Callable[[HarnessContext], Awaitable["TestResult"]]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "script_id": self.script_id,
            "name": self.name,
            "chapter": self.chapter,
            "execution_mode": self.execution_mode,
            "objective": self.objective,
            "preconditions": self.preconditions,
            "steps": self.steps,
            "evidence_required": self.evidence_required,
            "evaluation": self.evaluation_rules,
            "limitations": self.limitations,
            "remediation": self.remediation,
        }

@dataclass
class TestResult:
    shortcode: str
    name: str
    status: str       # "PASS" | "FAIL" | "MANUAL_VERIFY" | "NOT_TESTED" | "ERROR"
    severity: str     # "high" | "medium" | "low" | "info"
    evidence: str
    script_id: str = ""
    execution_status: str = "completed"   # "completed" | "failed" | "unsupported" | "skipped"
    verification_status: str = ""         # Matches status ("PASS" | "FAIL" | "MANUAL_VERIFY" | "NOT_TESTED" | "ERROR")
    remediation: str = ""
    test_hint: str = ""
    required_inputs: List[str] = field(default_factory=list)
    chapter: str = "V1 Encoding and Sanitization"
    level: int = 1
    tinyfish_mode: str = "BROWSER_SCRIPT"
    duration_ms: int = 0
    target_url: str = ""
    http_status: Optional[int] = None
    tests: List[Union[TestCaseExecution, Dict[str, Any]]] = field(default_factory=list)
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    observations: str = ""
    expected_behavior: str = ""
    limitations: Union[List[str], str] = field(default_factory=list)
    reason: Optional[str] = None
    missing_evidence: List[str] = field(default_factory=list)
    next_action: Optional[str] = None
    execution_error: Optional[str] = None
    screenshot: Optional[str] = None

    def __post_init__(self):
        if not self.verification_status:
            self.verification_status = self.status
        if not self.status:
            self.status = self.verification_status
        if not self.script_id:
            self.script_id = self.shortcode.replace(".", "_")

    def to_dict(self) -> Dict[str, Any]:
        tests_serialized = []
        for t in self.tests:
            if hasattr(t, "to_dict"):
                tests_serialized.append(t.to_dict())
            elif isinstance(t, dict):
                tests_serialized.append(t)

        limitations_serialized = (
            self.limitations
            if isinstance(self.limitations, list)
            else [self.limitations] if self.limitations else []
        )

        return {
            "shortcode": self.shortcode,
            "requirement_id": self.shortcode,
            "script_id": self.script_id,
            "name": self.name,
            "status": self.status,
            "verification_status": self.verification_status,
            "execution_status": self.execution_status,
            "severity": self.severity,
            "evidence": self.evidence,
            "tests": tests_serialized,
            "evidence_items": self.evidence_items,
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
            "limitations": limitations_serialized,
            "reason": self.reason,
            "missing_evidence": self.missing_evidence,
            "next_action": self.next_action,
            "execution_error": self.execution_error,
            "screenshot": (
                __import__("screenshots").save_screenshot(self.screenshot, prefix=f"shot_{self.shortcode}")
                if (self.screenshot and self.screenshot.startswith("data:"))
                else self.screenshot
            ),
        }

TestFunction = Callable[[HarnessContext], Awaitable[TestResult]]

_TEST_REGISTRY: Dict[str, Dict[str, Any]] = {}
_SCRIPT_DEFINITIONS: Dict[str, ScriptDefinition] = {}

def register_script(script_def: ScriptDefinition):
    """Registers a formal ScriptDefinition mapping an ASVS requirement to its test script."""
    sc_upper = script_def.requirement_id.strip().upper()
    _SCRIPT_DEFINITIONS[sc_upper] = script_def
    _SCRIPT_DEFINITIONS[script_def.script_id] = script_def
    if script_def.fn:
        _TEST_REGISTRY[sc_upper] = {
            "shortcode": sc_upper,
            "name": script_def.name,
            "description": script_def.objective or script_def.name,
            "fn": script_def.fn,
            "definition": script_def,
        }

def get_script_definition(identifier: str) -> Optional[ScriptDefinition]:
    """Look up a ScriptDefinition by shortcode (e.g. 'V1.3.7') or script_id (e.g. 'V1_3_7_TEMPLATE_INJECTION')."""
    return _SCRIPT_DEFINITIONS.get(identifier.strip().upper()) or _SCRIPT_DEFINITIONS.get(identifier.strip())

def list_script_definitions() -> Dict[str, ScriptDefinition]:
    """Returns mapping of all registered ScriptDefinitions by shortcode."""
    return {k: v for k, v in _SCRIPT_DEFINITIONS.items() if "." in k}

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
