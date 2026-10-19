from typing import Literal
from langgraph.graph import StateGraph, START, END

from app.graph.state import AuditGraphState
from app.graph.nodes import (
    recon_node,
    supervisor_node,
    transport_headers_node,
    input_encoding_node,
    client_dom_node,
    auth_session_node,
    api_web_service_node,
    crypto_data_protection_node,
    asvs_standards_evaluator_node,
    evidence_validator_node,
    synthesizer_node,
)

def route_supervisor(state: AuditGraphState) -> str:
    """Conditional router from supervisor to next specialist node or standards evaluator."""
    next_node = state.get("next_agent", "standards_evaluator")
    if next_node in [
        "transport_headers",
        "input_encoding",
        "client_dom",
        "auth_session",
        "api_web_service",
        "crypto_data_protection",
    ]:
        return next_node
    return "standards_evaluator"

def create_security_audit_graph():
    """Builds and compiles the multi-agent security audit LangGraph covering all ASVS standards."""
    workflow = StateGraph(AuditGraphState)

    # 1. Register all reconnaissance, supervisory, specialist, and evaluation nodes
    workflow.add_node("recon", recon_node)
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("transport_headers", transport_headers_node)
    workflow.add_node("input_encoding", input_encoding_node)
    workflow.add_node("client_dom", client_dom_node)
    workflow.add_node("auth_session", auth_session_node)
    workflow.add_node("api_web_service", api_web_service_node)
    workflow.add_node("crypto_data_protection", crypto_data_protection_node)
    workflow.add_node("standards_evaluator", asvs_standards_evaluator_node)
    workflow.add_node("validator", evidence_validator_node)
    workflow.add_node("synthesizer", synthesizer_node)

    # 2. Initial flow
    workflow.add_edge(START, "recon")
    workflow.add_edge("recon", "supervisor")

    # 3. Dynamic supervisory routing across specialists and standards evaluation
    workflow.add_conditional_edges(
        "supervisor",
        route_supervisor,
        {
            "transport_headers": "transport_headers",
            "input_encoding": "input_encoding",
            "client_dom": "client_dom",
            "auth_session": "auth_session",
            "api_web_service": "api_web_service",
            "crypto_data_protection": "crypto_data_protection",
            "standards_evaluator": "standards_evaluator",
        },
    )

    # 4. Specialist feedback loop back to supervisor
    workflow.add_edge("transport_headers", "supervisor")
    workflow.add_edge("input_encoding", "supervisor")
    workflow.add_edge("client_dom", "supervisor")
    workflow.add_edge("auth_session", "supervisor")
    workflow.add_edge("api_web_service", "supervisor")
    workflow.add_edge("crypto_data_protection", "supervisor")

    # 5. Deterministic standards evaluation, verification, and synthesis pipeline
    workflow.add_edge("standards_evaluator", "validator")
    workflow.add_edge("validator", "synthesizer")
    workflow.add_edge("synthesizer", END)

    return workflow.compile()

