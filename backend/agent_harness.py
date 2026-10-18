import os
import json
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from google import genai
from google.genai import types
from playwright.async_api import Page, CDPSession
from checks import evaluate_asvs_requirements

# Picks up GEMINI_API_KEY from the environment
client = genai.Client()
MODEL_ID = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# --- 1. Pydantic Schemas for Structured Output ---
class ASVSTestItem(BaseModel):
    requirement_id: str
    chapter_code: str
    chapter_name: str
    status: str       # "PASS" | "FAIL" | "MANUAL_VERIFY" | "NOT_APPLICABLE"
    severity: str     # "high" | "medium" | "low" | "info"
    evidence: str
    remediation: str

class FindingItem(BaseModel):
    severity: str     # "high" | "medium" | "low"
    category: str     # e.g., "Headers", "Cookies", "SRI", "Forms", "ASVS"
    title: str
    evidence: str
    remediation: str

class GeminiSecurityReport(BaseModel):
    score: int        # 0 - 100
    grade: str        # "A" | "B" | "C" | "D" | "F"
    summary: str
    asvs_results: List[ASVSTestItem]
    findings: List[FindingItem]


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
                    temperature=0.1,
                ),
            )
        except Exception as exc:
            trace_entry = {
                "step": step + 1,
                "tool": "gemini_model_fallback",
                "reason": f"Model invocation fallback: {str(exc)}",
                "observation_preview": "Using baseline evaluation results",
            }
            agent_trace.append(trace_entry)
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
            agent_trace.append(trace_entry)

            if on_step_callback:
                on_step_callback(agent_trace)

            function_response_parts.append(
                types.Part.from_function_response(
                    name=fn_name,
                    response={"result": tool_output},
                )
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
                temperature=0.1,
            ),
        )
        report_data = json.loads(final_response.text)
    except Exception as exc:
        # Resilient fallback: return baseline structured results
        report_data = {
            "score": baseline_result["score"],
            "grade": baseline_result["grade"],
            "summary": f"OWASP ASVS 5.0.0 automated audit completed across {len(asvs_requirements)} chapter requirements.",
            "asvs_results": baseline_result["asvs_results"],
            "findings": [
                {
                    "severity": f.get("severity", "medium"),
                    "category": f.get("type", "General"),
                    "title": f.get("detail", "Security Finding"),
                    "evidence": f.get("detail", ""),
                    "remediation": "Refer to OWASP ASVS recommendations for details."
                }
                for f in baseline_result["findings"]
            ],
        }

    report_data["agent_trace"] = agent_trace
    report_data["raw_headers"] = doc_headers
    return report_data
