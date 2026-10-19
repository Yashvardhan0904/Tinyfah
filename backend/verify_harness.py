import sys
import os
import asyncio
import uvicorn
import time
from pathlib import Path
import threading

# Ensure paths
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_server import test_app
from harness.engine import HarnessEngine
from harness.registry import get_script_definition

def start_server():
    config = uvicorn.Config(test_app, host="127.0.0.1", port=8001, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.2)
    return server

async def test_deterministic_v1():
    print("=== STARTING DETERMINISTIC HARNESS & AGENT VERIFICATION ===")

    server = start_server()
    engine = HarnessEngine(use_local_fallback=True)

    try:
        # Verify ScriptDefinition registry
        v137_def = get_script_definition("V1.3.7")
        assert v137_def is not None, "V1.3.7 ScriptDefinition must be registered"
        assert v137_def.script_id == "V1_3_7_TEMPLATE_INJECTION"
        assert len(v137_def.steps) > 0
        assert "pass" in v137_def.evaluation_rules
        print("ScriptDefinition V1_3_7_TEMPLATE_INJECTION loaded successfully from registry.")

        # Test 1: Single test V1.2.1 against Secure endpoint
        print("\n--- Test 1: V1.2.1 against Secure Endpoint ---")
        secure_report = await engine.execute_harness(
            target_url="http://127.0.0.1:8001/secure",
            single_test_id="V1.2.1",
        )
        print(f"Secure Target Score: {secure_report['score']}, Grade: {secure_report['grade']}")
        v1_2_1_result = secure_report["asvs_results"][0]
        print(f"V1.2.1 Status on /secure: {v1_2_1_result['status']} (Expected: PASS)")
        assert v1_2_1_result["status"] == "PASS", f"Expected PASS on secure, got {v1_2_1_result['status']}"
        assert v1_2_1_result.get("screenshot") and v1_2_1_result["screenshot"].endswith((".png", ".jpg")), "Expected screenshot filename on v1_2_1_result"
        assert (Path(__file__).resolve().parent / "screenshots" / v1_2_1_result["screenshot"]).is_file(), "Expected screenshot file on disk"
        assert v1_2_1_result.get("script_id") == "V1_2_1_HTML_ATTRIBUTE_OUTPUT_ENCODING"
        assert v1_2_1_result.get("execution_status") == "completed"
        print(f"V1.2.1 Screenshot '{v1_2_1_result['screenshot']}' captured and verified on disk.")

        # Test 2: Single test V1.2.1 against Vulnerable endpoint
        print("\n--- Test 2: V1.2.1 against Vulnerable Endpoint ---")
        vuln_report = await engine.execute_harness(
            target_url="http://127.0.0.1:8001/vulnerable",
            single_test_id="V1.2.1",
        )
        print(f"Vulnerable Target Score: {vuln_report['score']}, Grade: {vuln_report['grade']}")
        v1_2_1_vuln = vuln_report["asvs_results"][0]
        print(f"V1.2.1 Status on /vulnerable: {v1_2_1_vuln['status']} (Expected: FAIL)")
        print(f"Evidence: {v1_2_1_vuln['evidence']}")
        assert v1_2_1_vuln["status"] == "FAIL", f"Expected FAIL on vulnerable, got {v1_2_1_vuln['status']}"
        assert v1_2_1_vuln.get("screenshot") and v1_2_1_vuln["screenshot"].endswith((".png", ".jpg")), "Expected screenshot filename on v1_2_1_vuln"
        assert (Path(__file__).resolve().parent / "screenshots" / v1_2_1_vuln["screenshot"]).is_file(), "Expected screenshot file on disk"
        print(f"V1.2.1 Failure screenshot '{v1_2_1_vuln['screenshot']}' verified on disk.")

        # Test 3: V1.3.7 Template Injection against /ssti_vulnerable
        print("\n--- Test 3: V1.3.7 Template Injection against /ssti_vulnerable ---")
        ssti_vuln_report = await engine.execute_harness(
            target_url="http://127.0.0.1:8001/ssti_vulnerable",
            single_test_id="V1.3.7",
        )
        v1_3_7_vuln = ssti_vuln_report["asvs_results"][0]
        print(f"V1.3.7 Status on /ssti_vulnerable: {v1_3_7_vuln['status']} (Expected: FAIL)")
        print(f"Evidence: {v1_3_7_vuln['evidence']}")
        assert v1_3_7_vuln["status"] == "FAIL", f"Expected FAIL on ssti_vulnerable, got {v1_3_7_vuln['status']}"
        assert v1_3_7_vuln["script_id"] == "V1_3_7_TEMPLATE_INJECTION"
        assert v1_3_7_vuln["execution_status"] == "completed"
        assert len(v1_3_7_vuln["tests"]) >= 3, "Expected at least 3 template injection test cases executed"
        print("V1.3.7 SSTI detection successfully verified.")

        # Test 4: V1.3.7 Template Injection against /ssti_secure
        print("\n--- Test 4: V1.3.7 Template Injection against /ssti_secure ---")
        ssti_sec_report = await engine.execute_harness(
            target_url="http://127.0.0.1:8001/ssti_secure",
            single_test_id="V1.3.7",
        )
        v1_3_7_sec = ssti_sec_report["asvs_results"][0]
        print(f"V1.3.7 Status on /ssti_secure: {v1_3_7_sec['status']} (Expected: PASS)")
        assert v1_3_7_sec["status"] == "PASS", f"Expected PASS on ssti_secure, got {v1_3_7_sec['status']}"
        assert v1_3_7_sec["script_id"] == "V1_3_7_TEMPLATE_INJECTION"
        assert v1_3_7_sec["execution_status"] == "completed"
        print("V1.3.7 SSTI literal handling successfully verified.")

        # Test 5: Full Chapter V1 Suite against Vulnerable endpoint
        print("\n--- Test 5: Full Chapter V1 Suite (all 30 requirements) against Vulnerable Endpoint ---")
        full_vuln_report = await engine.execute_harness(
            target_url="http://127.0.0.1:8001/vulnerable",
            chapter="V1",
        )
        print(f"Full Chapter V1 Score: {full_vuln_report['score']}, Grade: {full_vuln_report['grade']}")
        print(f"Total Requirements: {full_vuln_report['metrics']['total_requirements']}")
        print(f"Total Evaluated: {full_vuln_report['metrics']['total_evaluated']}")
        print(f"Passed: {full_vuln_report['metrics']['passed']}")
        print(f"Failed: {full_vuln_report['metrics']['failed']}")
        print(f"Manual Verify: {full_vuln_report['metrics']['manual_verify']}")
        print(f"Executive Summary: {full_vuln_report['summary']}")

        assert full_vuln_report['metrics']['total_requirements'] == 30
        assert full_vuln_report['metrics']['total_evaluated'] == 6
        assert full_vuln_report['metrics']['failed'] == 5
        assert full_vuln_report['metrics']['passed'] == 1
        assert full_vuln_report['metrics']['manual_verify'] == 20
        assert full_vuln_report['metrics']['not_tested'] == 4
        assert full_vuln_report['grade'] == 'F'

        # Verify actionable MANUAL_VERIFY entries
        manual_items = [r for r in full_vuln_report['asvs_results'] if r.get('status') == 'MANUAL_VERIFY']
        for m in manual_items[:5]:
            assert m.get("reason"), f"Expected reason on MANUAL_VERIFY for {m.get('requirement_id')}"
            assert len(m.get("missing_evidence", [])) > 0, f"Expected missing_evidence on {m.get('requirement_id')}"
            assert m.get("next_action"), f"Expected next_action on {m.get('requirement_id')}"
        print(f"Verified {len(manual_items)} actionable MANUAL_VERIFY entries with reasons and next actions.")

        assert any(f.get("screenshot") and f["screenshot"].endswith((".png", ".jpg")) for f in full_vuln_report["findings"]), "Expected findings to contain screenshots"
        print(f"Findings contain screenshots: {[f.get('title') for f in full_vuln_report['findings'] if f.get('screenshot')]}")

        print("\n=== ALL DETERMINISTIC HARNESS & AGENT TESTS PASSED SUCCESSFULLY ===")

    finally:
        server.should_exit = True

if __name__ == "__main__":
    asyncio.run(test_deterministic_v1())
