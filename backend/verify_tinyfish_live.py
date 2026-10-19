import sys
import os
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness.engine import HarnessEngine

async def test_live_tinyfish():
    print("=== TESTING LIVE SCAN VIA TINYFISH CLOUD BROWSER ===")
    api_key = os.getenv("TINYFISH_API_KEY")
    if not api_key:
        print("Skipping TinyFish live test (no key found)")
        return

    engine = HarnessEngine(tinyfish_api_key=api_key, use_local_fallback=False)
    target_url = "https://example.com"

    print(f"Executing deterministic V1.2.1 test on {target_url} via TinyFish...")
    report = await engine.execute_harness(
        target_url=target_url,
        single_test_id="V1.2.1",
    )

    print("TinyFish Execution Complete!")
    print(f"Target: {report['target_url']}")
    print(f"Score: {report['score']} | Grade: {report['grade']}")
    print(f"ASVS Results: {len(report['asvs_results'])} item(s)")
    for res in report['asvs_results']:
        print(f"  - [{res['status']}] {res['shortcode']}: {res['name']}")
        print(f"    Evidence: {res['evidence']}")

    assert report["score"] >= 90
    print("=== LIVE TINYFISH TEST PASSED ===")

if __name__ == "__main__":
    asyncio.run(test_live_tinyfish())
