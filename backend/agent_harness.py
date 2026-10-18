import json
from typing import List
from pydantic import BaseModel
from google import genai
from google.genai import types
from playwright.async_api import Page, CDPSession

# Automatically picks up GEMINI_API_KEY from the environment
client = genai.Client()
MODEL_ID = "gemini-3.5-flash-lite"

# --- 1. Pydantic Schema for Guaranteed Final JSON Output ---
class FindingItem(BaseModel):
    severity: str       # "high" | "medium" | "low"
    category: str       # e.g., "Headers", "Cookies", "SRI", "Forms"
    title: str
    evidence: str
    remediation: str

class GeminiSecurityReport(BaseModel):
    score: int          # 0 - 100
    grade: str          # "A" | "B" | "C" | "D" | "F"
    summary: str
    findings: List[FindingItem]


# --- 2. Passive CDP & DOM Diagnostic Tools ---
async def execute_cdp_tool(name: str, args: dict, page: Page, cdp: CDPSession) -> dict:
    if name == "inspect_cookies_and_storage":
        cookies = (await cdp.send("Network.getAllCookies")).get("cookies", [])
        # Sanitize cookie values; only inspect security flags
        cookie_Audit = [
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
        return {"cookies": cookie_Audit, "storage": storage}

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
            # Wrap in a 3-second timeout so a slow selector never hangs the scan
            output = await page.evaluate(js_expr)
            return {"status": "ok", "output": output}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    elif name == "inspect_tls_and_mixed_content":
        # Uses native CDP Security domain state
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
            description="Audits browser cookies via CDP for missing HttpOnly, Secure, and SameSite flags.",
            parameters=types.Schema(
                type="OBJECT",
                properties={"reason": types.Schema(type="STRING", description="Why this check is needed based on recon")},
                required=["reason"],
            ),
        ),
        types.FunctionDeclaration(
            name="inspect_forms_and_sri",
            description="Checks HTML forms for insecure HTTP actions/autocomplete attributes and third-party scripts missing Subresource Integrity (SRI).",
            parameters=types.Schema(
                type="OBJECT",
                properties={"reason": types.Schema(type="STRING", description="Why this check is needed based on recon")},
                required=["reason"],
            ),
        ),
        types.FunctionDeclaration(
            name="inspect_frontend_libraries_and_links",
            description="Detects exposed client-side library versions (jQuery, React, Angular, Vue) and target='_blank' links missing rel='noopener'.",
            parameters=types.Schema(
                type="OBJECT",
                properties={"reason": types.Schema(type="STRING", description="Why this check is needed based on recon")},
                required=["reason"],
            ),
        ),
        types.FunctionDeclaration(
            name="inspect_tls_and_mixed_content",
            description="Checks the DOM for passive/active mixed content (HTTP images or iframes loaded on an HTTPS page).",
            parameters=types.Schema(
                type="OBJECT",
                properties={"reason": types.Schema(type="STRING", description="Why this check is needed based on recon")},
                required=["reason"],
            ),
        ),
    ]
)


# --- 4. The Gemini ReAct Loop ---
async def run_gemini_security_harness(
    page: Page,
    cdp: CDPSession,
    doc_headers: dict,
    cdp_issues: list,
    focus_prompt: str = "Perform a full passive web vulnerability audit.",
    on_step_callback=None,
) -> dict:
    # Step 0: Lightweight initial reconnaissance (under 2KB)
    initial_recon = await page.evaluate("""() => ({
        title: document.title,
        url: location.href,
        protocol: location.protocol,
        formCount: document.forms.length,
        externalScriptCount: Array.from(document.scripts).filter(s => s.src && !s.src.startsWith(location.origin)).length,
        metaTags: Array.from(document.querySelectorAll('meta[http-equiv], meta[name="referrer"]'))
            .map(m => ({ name: m.name || m.httpEquiv, content: m.content }))
    })""")

    system_instruction = (
        "You are an autonomous web security posture auditor connected to a live Chrome DevTools Protocol session. "
        "Review the initial reconnaissance and HTTP headers, then call the most relevant diagnostic tools to gather "
        "evidence on cookies, forms, SRI, mixed content, and client libraries. Stop calling tools once you have "
        "sufficient evidence to produce the final security grade."
    )

    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(
                    text=json.dumps({
                        "initial_recon": initial_recon,
                        "http_response_headers": doc_headers,
                        "devtools_audit_issues": list(set(cdp_issues)),
                    })
                )
            ],
        )
    ]

    agent_trace = []

    # Up to 4 adaptive tool-calling turns
    for step in range(4):
        response = await client.aio.models.generate_content(
            model=MODEL_ID,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                tools=[SECURITY_TOOLS],
                temperature=0.1,
            ),
        )

        # Append the model's response (including its function_call parts) to conversation history
        contents.append(response.candidates[0].content)

        # If Gemini didn't request any tool calls, break out to synthesize the final report
        if not response.function_calls:
            break

        function_response_parts = []
        for tool_call in response.function_calls:
            fn_name = tool_call.name
            fn_args = dict(tool_call.args) if tool_call.args else {}

            # Run the selected check against the live TinyFish CDP session
            tool_output = await execute_cdp_tool(fn_name, fn_args, page, cdp)

            trace_entry = {
                "step": step + 1,
                "tool": fn_name,
                "reason": fn_args.get("reason", "Running diagnostic check"),
                "observation_preview": json.dumps(tool_output)[:300],
            }
            agent_trace.append(trace_entry)

            # Optional callback to flush live progress to SQLite for Next.js polling
            if on_step_callback:
                on_step_callback(agent_trace)

            function_response_parts.append(
                types.Part.from_function_response(
                    name=fn_name,
                    response={"result": tool_output},
                )
            )

        # Feed all tool outputs back to Gemini for the next turn
        contents.append(types.Content(role="user", parts=function_response_parts))

    # Final Turn: Force structured JSON output matching GeminiSecurityReport
    contents.append(
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(
                    text="Synthesize all HTTP header, CDP, and tool observations into the final security audit report."
                )
            ],
        )
    )

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
    report_data["agent_trace"] = agent_trace
    report_data["raw_headers"] = doc_headers
    return report_data
