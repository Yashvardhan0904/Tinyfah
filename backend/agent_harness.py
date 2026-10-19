import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from google import genai
from google.genai import types
from playwright.async_api import Page, CDPSession
from checks import evaluate_asvs_requirements, deduplicate_findings
from dotenv import load_dotenv

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(env_path)
load_dotenv()

# Picks up GEMINI_API_KEY from the environment
gemini_key = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=gemini_key) if gemini_key else None
MODEL_ID = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

# --- 1. Pydantic Schemas for Structured Output ---
class ASVSTestItem(BaseModel):
    requirement_id: str
    chapter_code: str
    chapter_name: str
    status: str       # "PASS" | "FAIL" | "MANUAL_VERIFY" | "NOT_TESTED" | "NOT_APPLICABLE" | "ERROR"
    severity: str     # "high" | "medium" | "low" | "info"
    evidence: str
    remediation: str
    screenshot: Optional[str] = None

class FindingItem(BaseModel):
    severity: str     # "high" | "medium" | "low"
    category: str     # e.g., "Headers", "Cookies", "SRI", "Forms", "ASVS"
    title: str
    evidence: str
    remediation: str
    screenshot: Optional[str] = None

class GeminiSecurityReport(BaseModel):
    score: Optional[int] = None       # 0 - 100, or None if not assessable
    grade: str = "NOT_ASSESSED"       # "A" | "B" | "C" | "D" | "F" | "NOT_ASSESSED"
    summary: str
    asvs_results: List[ASVSTestItem]
    findings: List[FindingItem]
    screenshot: Optional[str] = None


# --- 2. Passive CDP & DOM Diagnostic Tools ---
async def execute_cdp_tool(name: str, args: dict, page: Page, cdp: CDPSession) -> dict:
    if name == "inspect_cookies_and_storage":
        cookies = (await cdp.send("Network.getAllCookies")).get("cookies", [])
        cookie_audit = [
            {
                "name": c.get("name"),
                "secure": c.get("secure"),
                "httpOnly": c.get("httpOnly"),
                "sameSite": c.get("sameSite", "None"),
            }
            for c in cookies
        ]
        storage = await page.evaluate("""() => ({
            localStorageKeyCount: Object.keys(window.localStorage).length,
            sessionStorageKeyCount: Object.keys(window.sessionStorage).length
        })""")
        return {"cookies": cookie_audit, "storage": storage}

    elif name == "inspect_forms_and_sri":
        return await page.evaluate("""() => ({
            forms: Array.from(document.forms).map(f => ({
                action: f.action,
                method: f.method,
                isHttpAction: f.action ? f.action.startsWith('http://') : false,
                inputs: Array.from(f.elements)
                    .filter(e => e.tagName === 'INPUT')
                    .map(e => ({ name: e.name, type: e.type, autocomplete: e.autocomplete }))
            })),
            missingSriAssets: Array.from(document.querySelectorAll('script[src], link[rel="stylesheet"][href]'))
                .filter(el => {
                    const url = el.src || el.href;
                    return url && !url.startsWith(location.origin) && !el.integrity;
                })
                .map(el => el.src || el.href)
                .slice(0, 15)
        })""")

    elif name == "inspect_frontend_libraries_and_links":
        return await page.evaluate("""() => ({
            detectedLibraries: {
                jquery: window.jQuery ? window.jQuery.fn.jquery : null,
                angular: window.angular && window.angular.version ? window.angular.version.full : null,
                react: window.React ? window.React.version : null,
                vue: window.Vue ? window.Vue.version : null
            },
            unsafeTargetBlankLinks: Array.from(document.querySelectorAll('a[target="_blank"]'))
                .filter(a => !a.rel.includes('noopener') && !a.rel.includes('noreferrer'))
                .map(a => a.href)
                .slice(0, 10)
        })""")

    elif name == "run_custom_dom_js":
        js_expr = args.get("js_expression", "() => ({})")
        try:
            output = await page.evaluate(js_expr)
            return {"status": "ok", "output": output}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    elif name == "inspect_tls_and_mixed_content":
        mixed_content = await page.evaluate("""() => ({
            insecureImages: Array.from(document.images)
                .filter(img => img.src.startsWith('http://'))
                .map(img => img.src)
                .slice(0, 10),
            insecureIframes: Array.from(document.querySelectorAll('iframe[src^="http://"]'))
                .map(f => f.src)
        })""")
        return mixed_content

    elif name == "capture_page_screenshot":
        format_choice = args.get("format", "png")
        if format_choice not in ["png", "jpeg"]:
            format_choice = "png"
        from screenshots import save_screenshot
        dock_injected = False
        if page:
            try:
                from harness.console_hud import build_console_logs, INJECT_CONSOLE_JS
                t_url = getattr(page, "url", "https://target")
                logs = build_console_logs(
                    target_url=t_url,
                    current_test={"shortcode": "AGENT", "name": "Agent Interactive Snapshot", "status": "INFO", "evidence": "DevTools snapshot"},
                )
                await page.evaluate(INJECT_CONSOLE_JS, {
                    "logs": logs,
                    "target_url": t_url,
                    "current_test": "Agent Interactive Snapshot",
                })
                dock_injected = True
                await page.wait_for_timeout(100)
            except Exception:
                pass
        try:
            if cdp:
                try:
                    await cdp.send("Page.enable")
                    send_args = {"format": format_choice}
                    if format_choice == "jpeg":
                        send_args["quality"] = int(args.get("quality", 80))
                    cdp_res = await cdp.send("Page.captureScreenshot", send_args)
                    if cdp_res and "data" in cdp_res:
                        fname = save_screenshot(cdp_res["data"], prefix="tool_shot")
                        return {"status": "ok", "screenshot": fname}
                except Exception:
                    pass

            if page:
                raw_bytes = await page.screenshot(type=format_choice)
                fname = save_screenshot(raw_bytes, prefix="tool_shot")
                return {"status": "ok", "screenshot": fname}
        finally:
            if dock_injected and page:
                try:
                    from harness.console_hud import REMOVE_CONSOLE_JS
                    await page.evaluate(REMOVE_CONSOLE_JS)
                except Exception:
                    pass

        return {"status": "error", "error": "Failed to capture screenshot"}

    return {"error": f"Unknown tool: {name}"}


# --- 3. Gemini Function Declarations ---
SECURITY_TOOLS = types.Tool(
    function_declarations=[
        types.FunctionDeclaration(
            name="run_custom_dom_js",
            description="Executes a custom read-only JavaScript arrow function in the page via page.evaluate() to inspect specific DOM nodes or window globals discovered in previous steps.",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "reason": types.Schema(type="STRING", description="Why you are running this custom script"),
                    "js_expression": types.Schema(type="STRING", description="Read-only JS arrow function, e.g. () => Object.keys(window.__NEXT_DATA__ || {})"),
                },
                required=["reason", "js_expression"],
            ),
        ),
        types.FunctionDeclaration(
            name="inspect_cookies_and_storage",
            description="Audits browser cookies via CDP for missing HttpOnly, Secure, and SameSite flags (OWASP ASVS V7).",
            parameters=types.Schema(
                type="OBJECT",
                properties={"reason": types.Schema(type="STRING", description="Why this check is needed based on recon")},
                required=["reason"],
            ),
        ),
        types.FunctionDeclaration(
            name="inspect_forms_and_sri",
            description="Checks HTML forms for insecure HTTP actions/autocomplete attributes and third-party scripts missing Subresource Integrity (SRI) (OWASP ASVS V1 & V3).",
            parameters=types.Schema(
                type="OBJECT",
                properties={"reason": types.Schema(type="STRING", description="Why this check is needed based on recon")},
                required=["reason"],
            ),
        ),
        types.FunctionDeclaration(
            name="inspect_frontend_libraries_and_links",
            description="Detects exposed client-side library versions (jQuery, React, Angular, Vue) and target='_blank' links missing rel='noopener' (OWASP ASVS V3 & V15).",
            parameters=types.Schema(
                type="OBJECT",
                properties={"reason": types.Schema(type="STRING", description="Why this check is needed based on recon")},
                required=["reason"],
            ),
        ),
        types.FunctionDeclaration(
            name="inspect_tls_and_mixed_content",
            description="Checks the DOM for passive/active mixed content (HTTP images or iframes loaded on an HTTPS page) (OWASP ASVS V12).",
            parameters=types.Schema(
                type="OBJECT",
                properties={"reason": types.Schema(type="STRING", description="Why this check is needed based on recon")},
                required=["reason"],
            ),
        ),
        types.FunctionDeclaration(
            name="capture_page_screenshot",
            description="Captures a visual screenshot of the current page state via Chrome DevTools Protocol (Page.captureScreenshot) to serve as concrete evidence for security findings.",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "reason": types.Schema(type="STRING", description="Why the visual evidence is being captured"),
                    "format": types.Schema(type="STRING", description="Image format: 'png' or 'jpeg' (default 'png')"),
                },
                required=["reason"],
            ),
        ),
    ]
)


# --- 4. The OWASP ASVS Verification Harness ---
async def run_gemini_security_harness(
    page: Page,
    cdp: CDPSession,
    doc_headers: dict,
    cdp_issues: list,
    asvs_requirements: Optional[List[Dict[str, Any]]] = None,
    on_step_callback=None,
) -> dict:
    if not asvs_requirements:
        from asvs_loader import get_one_test_per_chapter
        asvs_requirements = get_one_test_per_chapter()

    # Enable CDP Page domain
    try:
        await cdp.send("Page.enable")
    except Exception:
        pass

    # Baseline screenshot via CDP session with DevTools Console HUD
    baseline_screenshot = None
    console_logs: List[Dict[str, Any]] = []
    try:
        from harness.console_hud import attach_console_listeners
        attach_console_listeners(page, cdp, console_logs)
    except Exception:
        pass

    dock_injected = False
    if page:
        try:
            from harness.console_hud import build_console_logs, INJECT_CONSOLE_JS
            logs = build_console_logs(
                target_url=target_url,
                doc_headers=doc_headers,
                captured_logs=console_logs,
                current_test={"shortcode": "AUDIT", "name": "Baseline Security Audit", "status": "PASS", "evidence": f"Navigated to {target_url}"},
            )
            await page.evaluate(INJECT_CONSOLE_JS, {
                "logs": logs,
                "target_url": target_url,
                "current_test": "Baseline Security Audit",
            })
            dock_injected = True
            await page.wait_for_timeout(100)
        except Exception:
            pass

    try:
        from screenshots import save_screenshot
        shot_res = await cdp.send("Page.captureScreenshot", {"format": "png"})
        if shot_res and "data" in shot_res:
            baseline_screenshot = save_screenshot(shot_res["data"], prefix="baseline")
    except Exception:
        try:
            from screenshots import save_screenshot
            raw_bytes = await page.screenshot(type="png")
            baseline_screenshot = save_screenshot(raw_bytes, prefix="baseline")
        except Exception:
            pass
    finally:
        if dock_injected and page:
            try:
                from harness.console_hud import REMOVE_CONSOLE_JS
                await page.evaluate(REMOVE_CONSOLE_JS)
            except Exception:
                pass

    # Step 0: Lightweight initial reconnaissance
    initial_recon = await page.evaluate("""() => ({
        title: document.title,
        url: location.href,
        protocol: location.protocol,
        formCount: document.forms.length,
        externalScriptCount: Array.from(document.scripts).filter(s => s.src && !s.src.startsWith(location.origin)).length,
        metaTags: Array.from(document.querySelectorAll('meta[http-equiv], meta[name="referrer"]'))
            .map(m => ({ name: m.name || m.httpEquiv, content: m.content }))
    })""")

    # Baseline passive evaluation
    cookies_res = (await cdp.send("Network.getAllCookies")).get("cookies", [])
    dom_forms_sri = await execute_cdp_tool("inspect_forms_and_sri", {}, page, cdp)
    dom_libs = await execute_cdp_tool("inspect_frontend_libraries_and_links", {}, page, cdp)
    
    dom_data = {
        "missingSri": dom_forms_sri.get("missingSriAssets", []),
        "insecureForms": [f["action"] for f in dom_forms_sri.get("forms", []) if f.get("isHttpAction")],
        "unsafeLinks": dom_libs.get("unsafeTargetBlankLinks", []),
    }
    
    baseline_result = evaluate_asvs_requirements(
        requirements=asvs_requirements,
        headers=doc_headers,
        cookies=cookies_res,
        dom_data=dom_data,
        cdp_issues=cdp_issues,
        protocol=initial_recon.get("protocol", "https:"),
        screenshot=baseline_screenshot,
    )

    system_instruction = (
        "You are an automated web application security verification auditor. "
        "Your task is to audit the live web application against the provided OWASP ASVS 5.0.0 requirements. "
        "Use the diagnostic tools to inspect cookies, forms, Subresource Integrity, mixed content, and libraries. "
        "Stop calling tools once you have sufficient evidence to produce the final OWASP ASVS compliance report."
    )

    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(
                    text=json.dumps({
                        "task": "Audit website against OWASP ASVS 5.0.0 standard requirements",
                        "asvs_requirements_to_verify": asvs_requirements,
                        "initial_recon": initial_recon,
                        "http_response_headers": doc_headers,
                        "devtools_audit_issues": list(set(cdp_issues)),
                        "baseline_checks": {
                            "findings_count": len(baseline_result["findings"]),
                            "observable_score": baseline_result["score"],
                        }
                    })
                )
            ],
        )
    ]

    agent_trace = []

    # Up to 3 adaptive tool-calling turns for in-depth inspection
    for step in range(3):
        try:
            response = await client.aio.models.generate_content(
                model=MODEL_ID,
                contents=contents,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    tools=[SECURITY_TOOLS],
                ),
            )
        except Exception as exc:
            trace_entry = {
                "step": len(agent_trace) + 1,
                "tool": "deterministic_baseline_fallback",
                "status": "fallback",
                "reason": "AI model invocation failed; executing deterministic ASVS evaluator.",
                "observation_preview": f"AI error: {str(exc)[:180]}",
            }
            agent_trace.append(trace_entry)
            if on_step_callback:
                on_step_callback(agent_trace)
            break

        contents.append(response.candidates[0].content)

        if not response.function_calls:
            break

        function_response_parts = []
        for tool_call in response.function_calls:
            fn_name = tool_call.name
            fn_args = dict(tool_call.args) if tool_call.args else {}

            tool_output = await execute_cdp_tool(fn_name, fn_args, page, cdp)

            trace_entry = {
                "step": step + 1,
                "tool": fn_name,
                "reason": fn_args.get("reason", "Auditing ASVS requirement"),
                "observation_preview": json.dumps(tool_output)[:300],
            }
            if tool_output.get("screenshot"):
                trace_entry["screenshot"] = tool_output.get("screenshot")
            agent_trace.append(trace_entry)

            if on_step_callback:
                on_step_callback(agent_trace)

            resp_kwargs = {"name": fn_name, "response": {"result": tool_output}}
            call_id = getattr(tool_call, "id", None)
            if call_id:
                resp_kwargs["id"] = call_id

            function_response_parts.append(
                types.Part.from_function_response(**resp_kwargs)
            )

        contents.append(types.Content(role="user", parts=function_response_parts))

    # Synthesis Turn: Generate structured report
    contents.append(
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(
                    text=(
                        "Synthesize all observations into the final OWASP ASVS verification report. "
                        "Ensure each requirement in the test suite is evaluated with status "
                        "(PASS, FAIL, MANUAL_VERIFY, or NOT_APPLICABLE), specific evidence, and remediation."
                    )
                )
            ],
        )
    )

    try:
        final_response = await client.aio.models.generate_content(
            model=MODEL_ID,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                response_schema=GeminiSecurityReport,
            ),
        )
        report_data = json.loads(final_response.text)
        report_data["is_ai_synthesized"] = True
        report_data["ai_assessment_status"] = "SUCCESS"
        report_data["ai_error"] = None
    except Exception as exc:
        # Transparent fallback: return baseline structured results with clear status indicator
        fallback_step_exists = any(t.get("tool") == "deterministic_baseline_fallback" for t in agent_trace)
        if not fallback_step_exists:
            trace_entry = {
                "step": len(agent_trace) + 1,
                "tool": "deterministic_baseline_fallback",
                "status": "fallback",
                "reason": "AI model invocation failed; executing deterministic ASVS evaluator.",
                "observation_preview": f"AI error: {str(exc)[:180]}",
            }
            agent_trace.append(trace_entry)
            if on_step_callback:
                on_step_callback(agent_trace)

        report_data = {
            "score": baseline_result["score"],
            "grade": baseline_result["grade"],
            "scan_status": baseline_result.get("scan_status", "not_assessed" if baseline_result.get("metrics", {}).get("total_evaluated", 0) == 0 else "completed"),
            "coverage_percentage": baseline_result.get("coverage_percentage", 0.0),
            "pass_rate_percentage": baseline_result.get("pass_rate_percentage"),
            "is_ai_synthesized": False,
            "ai_assessment_status": "FAILED",
            "ai_error": str(exc),
            "summary": (
                f"AI reasoning/synthesis was unavailable; automated baseline assessment completed across "
                f"{len(asvs_requirements)} chapter requirements ({type(exc).__name__}: {str(exc)[:100]})."
            ),
            "asvs_results": baseline_result["asvs_results"],
            "findings": baseline_result["findings"],
            "metrics": baseline_result.get("metrics", {}),
        }

    # Zero-evaluated score guard
    eval_count = sum(
        1 for item in report_data.get("asvs_results", [])
        if (isinstance(item, dict) and item.get("status") in ["PASS", "FAIL"])
        or (hasattr(item, "status") and getattr(item, "status") in ["PASS", "FAIL"])
    )
    if eval_count == 0:
        report_data["score"] = None
        report_data["grade"] = "NOT_ASSESSED"
        report_data["scan_status"] = "not_assessed"
    elif "scan_status" not in report_data:
        report_data["scan_status"] = "completed"

    if baseline_screenshot and not report_data.get("screenshot"):
        report_data["screenshot"] = baseline_screenshot

    # Ensure findings are deduplicated with preserved mappings
    report_data["findings"] = deduplicate_findings(report_data.get("findings", []))
    if baseline_screenshot:
        for f in report_data.get("findings", []):
            if not f.get("screenshot"):
                f["screenshot"] = baseline_screenshot
        for r in report_data.get("asvs_results", []):
            if isinstance(r, dict) and not r.get("screenshot"):
                r["screenshot"] = baseline_screenshot

    report_data["agent_trace"] = agent_trace
    report_data["raw_headers"] = doc_headers
    return report_data
