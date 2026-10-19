import sys
import os
import asyncio
import uvicorn
import multiprocessing
import time
from pathlib import Path

# Ensure paths
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_server import test_app
from harness.engine import HarnessEngine

import threading

def start_server():
    config = uvicorn.Config(test_app, host="127.0.0.1", port=8001, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.2)
    return server

async def test_deterministic_v1():
    print("=== STARTING DETERMINISTIC HARNESS VERIFICATION ===")

    server = start_server()
    engine = HarnessEngine(use_local_fallback=True)

    try:
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

        # Test 3: Full Chapter V1 Suite against Vulnerable endpoint
        print("\n--- Test 3: Full Chapter V1 Suite (all 30 requirements) against Vulnerable Endpoint ---")
        full_vuln_report = await engine.execute_harness(
            target_url="http://127.0.0.1:8001/vulnerable",
            chapter="V1",
        )
        print(f"Full Chapter V1 Score: {full_vuln_report['score']}, Grade: {full_vuln_report['grade']}")
        print(f"Total Evaluated: {full_vuln_report['metrics']['total_evaluated']}")
        print(f"Passed: {full_vuln_report['metrics']['passed']}")
        print(f"Failed: {full_vuln_report['metrics']['failed']}")
        print(f"Manual Verify: {full_vuln_report['metrics']['manual_verify']}")
        print(f"Executive Summary: {full_vuln_report['summary']}")

        assert full_vuln_report['metrics']['total_evaluated'] == 30
        assert full_vuln_report['metrics']['failed'] >= 2  # At least V1.2.1 and V1.3.2 or V1.2.2

        print("\n=== ALL DETERMINISTIC HARNESS TESTS PASSED SUCCESSFULLY ===")

    finally:
        server.should_exit = True

if __name__ == "__main__":
    asyncio.run(test_deterministic_v1())
