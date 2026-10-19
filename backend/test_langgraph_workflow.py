import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from app.graph.state import AuditGraphState
from app.graph.workflow import create_security_audit_graph, route_supervisor
from app.graph.nodes.specialists import (
    transport_headers_node,
    client_dom_node,
    auth_session_node,
    api_web_service_node,
    crypto_data_protection_node,
)
from app.graph.nodes.asvs_evaluator import asvs_standards_evaluator_node, CHAPTER_NAMES
from app.graph.nodes.validator import evidence_validator_node
from app.graph.nodes.synthesizer import synthesizer_node

class TestLangGraphWorkflow(unittest.IsolatedAsyncioTestCase):

    def test_graph_compilation_and_nodes(self):
        """Verifies that the LangGraph workflow compiles successfully with all 11 multi-agent and standards nodes."""
        graph = create_security_audit_graph()
        self.assertIsNotNone(graph)
        node_keys = graph.nodes.keys()
        self.assertIn("recon", node_keys)
        self.assertIn("supervisor", node_keys)
        self.assertIn("transport_headers", node_keys)
        self.assertIn("input_encoding", node_keys)
        self.assertIn("client_dom", node_keys)
        self.assertIn("auth_session", node_keys)
        self.assertIn("api_web_service", node_keys)
        self.assertIn("crypto_data_protection", node_keys)
        self.assertIn("standards_evaluator", node_keys)
        self.assertIn("validator", node_keys)
        self.assertIn("synthesizer", node_keys)

    def test_supervisor_routing_logic(self):
        """Tests supervisor conditional routing between 6 specialist nodes and standards evaluator."""
        for spec in ["transport_headers", "input_encoding", "client_dom", "auth_session", "api_web_service", "crypto_data_protection"]:
            state: AuditGraphState = {"next_agent": spec}
            self.assertEqual(route_supervisor(state), spec)

        state_eval: AuditGraphState = {"next_agent": "standards_evaluator"}
        self.assertEqual(route_supervisor(state_eval), "standards_evaluator")

        state_unknown: AuditGraphState = {"next_agent": "random_agent"}
        self.assertEqual(route_supervisor(state_unknown), "standards_evaluator")

    async def test_transport_headers_node_audit(self):
        """Tests Transport & Headers specialist agent identifies missing HSTS and insecure HTTP."""
        state: AuditGraphState = {
            "target_url": "http://insecure.example.com",
            "protocol": "http:",
            "doc_headers": {"content-type": "text/html"},
            "cookies": [],
            "raw_findings": [],
            "asvs_results": [],
            "agent_trace": [],
            "completed_agents": [],
            "current_step": 1,
            "page": None,
            "cdp": None,
        }
        output = await transport_headers_node(state)
        self.assertIn("transport_headers", output["completed_agents"])
        findings = output["raw_findings"]
        asvs = output["asvs_results"]

        # Insecure HTTP must generate TLS failure finding
        tls_finding = next(f for f in findings if f["asvs"] == "V12.1.1")
        self.assertEqual(tls_finding["severity"], "high")

        # Missing CSP must generate CSP failure finding
        csp_finding = next(f for f in findings if f["asvs"] == "V3.4.2")
        self.assertEqual(csp_finding["severity"], "medium")

        # 0 cookies must mark V7.1.1 as NOT_TESTED
        v7_res = next(r for r in asvs if r["requirement_id"] == "V7.1.1")
        self.assertEqual(v7_res["status"], "NOT_TESTED")

    async def test_auth_session_node_audit(self):
        """Tests Auth & Session specialist agent detects credential leaks in URLs and insecure login transport."""
        state: AuditGraphState = {
            "target_url": "https://example.com/login?password=secret123&token=abc",
            "protocol": "https:",
            "raw_findings": [],
            "asvs_results": [],
            "agent_trace": [],
            "completed_agents": [],
            "current_step": 1,
            "page": None,
            "cdp": None,
        }
        output = await auth_session_node(state)
        self.assertIn("auth_session", output["completed_agents"])
        findings = output["raw_findings"]

        # Should flag credential in URL
        cred_finding = next(f for f in findings if "credential leaked in URL" in f.get("detail", "").lower() or f.get("asvs") == "V6.3.1")
        self.assertEqual(cred_finding["severity"], "high")

    async def test_api_web_service_node_audit(self):
        """Tests API specialist agent detects CORS wildcard with credentials."""
        state: AuditGraphState = {
            "target_url": "https://api.example.com",
            "protocol": "https:",
            "doc_headers": {
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
            "raw_findings": [],
            "asvs_results": [],
            "agent_trace": [],
            "completed_agents": [],
            "current_step": 1,
            "page": None,
            "cdp": None,
        }
        output = await api_web_service_node(state)
        self.assertIn("api_web_service", output["completed_agents"])
        findings = output["raw_findings"]

        cors_finding = next(f for f in findings if f["type"] == "cors")
        self.assertEqual(cors_finding["severity"], "critical")
        self.assertEqual(cors_finding["asvs"], "V4.3.1")

    async def test_crypto_data_protection_node_audit(self):
        """Tests Crypto & Data Protection specialist detects stack traces and sensitive comments."""
        state: AuditGraphState = {
            "target_url": "https://example.com",
            "protocol": "https:",
            "doc_headers": {"server": "Apache/2.4.41 (Ubuntu)"},
            "console_logs": [{"level": "error", "text": "Traceback (most recent call last): File app.py, line 12"}],
            "raw_findings": [],
            "asvs_results": [],
            "agent_trace": [],
            "completed_agents": [],
            "current_step": 1,
            "page": None,
            "cdp": None,
        }
        output = await crypto_data_protection_node(state)
        self.assertIn("crypto_data_protection", output["completed_agents"])
        findings = output["raw_findings"]

        # Traceback leak
        leak_finding = next(f for f in findings if f["type"] == "leak")
        self.assertEqual(leak_finding["severity"], "high")
        self.assertEqual(leak_finding["asvs"], "V16.1.1")

        # Server version disclosure
        server_finding = next(f for f in findings if f["asvs"] == "V13.1.4")
        self.assertEqual(server_finding["severity"], "low")

    async def test_asvs_standards_evaluator_all_17_chapters(self):
        """Verifies Universal ASVS Evaluator accounts for all 345 requirements across all 17 chapters."""
        state: AuditGraphState = {
            "target_url": "https://example.com",
            "protocol": "https:",
            "doc_headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "content-type": "text/html; charset=utf-8",
            },
            "cookies": [],
            "cdp_issues": [],
            "console_logs": [],
            "initial_recon": {"forms": []},
            "raw_findings": [],
            "asvs_results": [],
            "agent_trace": [],
            "current_step": 1,
        }
        output = await asvs_standards_evaluator_node(state)
        asvs_results = output["asvs_results"]
        breakdown = output["chapter_breakdown"]

        # Total requirements must equal 345 across all standards
        self.assertEqual(len(asvs_results), 345)

        # All 17 chapters must be represented in the scorecard
        self.assertEqual(len(breakdown), 17)
        for code in CHAPTER_NAMES:
            self.assertIn(code, breakdown)
            chap = breakdown[code]
            self.assertGreater(chap["total"], 0)
            self.assertIn(chap["grade"], ["A", "B", "C", "D", "F", "NOT_ASSESSED"])

        # Check V12 TLS passes on HTTPS
        v12_item = next(r for r in asvs_results if r["requirement_id"] == "V12.1.1")
        self.assertEqual(v12_item["status"], "PASS")

        # Check V3 HSTS passes
        v3_hsts = next(r for r in asvs_results if r["requirement_id"] == "V3.4.1")
        self.assertEqual(v3_hsts["status"], "PASS")

    async def test_validator_and_synthesizer_nodes(self):
        """Tests evidence validator scoring formulas and synthesizer report generation with chapter breakdown."""
        mock_asvs = [
            {"requirement_id": "V12.1.1", "chapter_code": "V12", "status": "PASS", "severity": "info", "evidence": "HTTPS"},
            {"requirement_id": "V3.4.2", "chapter_code": "V3", "status": "FAIL", "severity": "medium", "evidence": "No CSP"},
        ]
        mock_findings = [
            {"asvs": "V3.4.2", "type": "header", "severity": "medium", "detail": "Missing CSP", "evidence": "No CSP header"},
        ]
        validator_state: AuditGraphState = {
            "target_url": "https://example.com",
            "raw_findings": mock_findings,
            "asvs_results": mock_asvs,
            "chapter_breakdown": {
                "V3": {"chapter_code": "V3", "chapter_name": "Web Frontend Security", "total": 1, "passed": 0, "failed": 1, "score": 85, "grade": "B", "status": "completed"},
                "V12": {"chapter_code": "V12", "chapter_name": "Secure Communication", "total": 1, "passed": 1, "failed": 0, "score": 100, "grade": "A", "status": "completed"},
            },
            "agent_trace": [],
            "current_step": 1,
        }
        val_output = await evidence_validator_node(validator_state)
        self.assertEqual(val_output["score"], 85)
        self.assertEqual(val_output["grade"], "B")
        self.assertEqual(val_output["scan_status"], "completed")
        self.assertEqual(val_output["coverage_percentage"], 100.0)
        self.assertIn("V3", val_output["chapter_breakdown"])

        # Feed to synthesizer
        synth_state: AuditGraphState = {
            "target_url": "https://example.com",
            "score": val_output["score"],
            "grade": val_output["grade"],
            "scan_status": val_output["scan_status"],
            "coverage_percentage": val_output["coverage_percentage"],
            "pass_rate_percentage": val_output["pass_rate_percentage"],
            "raw_findings": val_output["raw_findings"],
            "asvs_results": val_output["asvs_results"],
            "chapter_breakdown": val_output["chapter_breakdown"],
            "metrics": val_output["metrics"],
            "agent_trace": val_output["agent_trace"],
            "current_step": 2,
        }
        synth_output = await synthesizer_node(synth_state)
        report = synth_output["final_report"]
        self.assertEqual(report["workflow"], "langgraph_multi_agent")
        self.assertEqual(report["score"], 85)
        self.assertEqual(report["grade"], "B")
        self.assertIn("summary", report)
        self.assertEqual(len(report["findings"]), 1)
        self.assertIn("chapter_breakdown", report)

if __name__ == "__main__":
    unittest.main()
