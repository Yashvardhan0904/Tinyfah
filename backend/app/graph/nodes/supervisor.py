import json
from typing import Dict, Any, List
from google.genai import types

from app.graph.state import AuditGraphState
from app.config import GEMINI_MODEL
from app.services.agent import _get_client

AVAILABLE_SPECIALISTS = [
    "transport_headers",
    "input_encoding",
    "client_dom",
    "auth_session",
    "api_web_service",
    "crypto_data_protection",
]

async def supervisor_node(state: AuditGraphState) -> Dict[str, Any]:
    """The Coordinator Agent: analyzes surface, reviews current state, and decides next specialist action."""
    target_url = state.get("target_url", "")
    completed = state.get("completed_agents", [])
    remaining = [a for a in AVAILABLE_SPECIALISTS if a not in completed]
    iteration = state.get("iteration_count", 0)
    max_iter = state.get("max_iterations", 7)
    agent_trace = list(state.get("agent_trace", []))
    step = state.get("current_step", 1)

    # Termination check: all specialist tasks completed or iteration budget exhausted
    if not remaining or iteration >= max_iter:
        agent_trace.append({
            "step": step,
            "tool": "supervisor_agent",
            "reason": f"Specialist audit loop complete ({len(completed)} domain specialists executed). Transitioning to universal ASVS standards evaluator.",
            "observation_preview": f"Completed domains: {', '.join(completed)}. Initiating evaluation across all 17 ASVS chapters.",
            "status": "completed",
        })
        return {
            "next_agent": "standards_evaluator",
            "agent_trace": agent_trace,
            "current_step": step + 1,
            "iteration_count": iteration + 1,
        }

    # Select next agent (Gemini coordinated or deterministic fallback)
    next_choice = remaining[0]
    reasoning = f"Scheduling {next_choice} domain specialist based on attack surface profile."

    client = _get_client()
    if client:
        try:
            prompt = (
                f"You are the Lead Security Audit Supervisor orchestrating a multi-agent web security assessment.\n"
                f"Target URL: {target_url}\n"
                f"Discovered attack surface: {json.dumps(state.get('initial_recon', {}))[:300]}\n"
                f"Already completed domains: {completed}\n"
                f"Remaining eligible specialists: {remaining}\n"
                f"Choose exactly one specialist from the remaining list to execute next, and provide a 1-sentence rationale.\n"
                f"Respond with JSON format: {{\"next_agent\": \"<name>\", \"reason\": \"<sentence>\"}}"
            )
            resp = await client.aio.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    max_output_tokens=150,
                ),
            )
            parsed = json.loads(resp.text)
            if parsed.get("next_agent") in remaining:
                next_choice = parsed["next_agent"]
                reasoning = parsed.get("reason", reasoning)
        except Exception:
            pass

    agent_trace.append({
        "step": step,
        "tool": "supervisor_agent",
        "reason": f"Supervisor selected domain specialist '{next_choice}'",
        "observation_preview": reasoning,
        "status": "completed",
    })

    return {
        "next_agent": next_choice,
        "agent_trace": agent_trace,
        "current_step": step + 1,
        "iteration_count": iteration + 1,
    }
