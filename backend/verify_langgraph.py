import sys
import asyncio
import threading
import time
import uvicorn
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.graph.runner import run_langgraph_security_audit
from test_server import test_app

def start_testbed_server(port: int = 8003):
    config = uvicorn.Config(test_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.2)
    return server

def print_trace(trace: list):
    if trace:
        last = trace[-1]
        step = last.get("step")
        tool = last.get("tool")
        reason = last.get("reason", "")
        obs = last.get("observation_preview", "")
        print(f"  [Step {step}] ⚙️  {tool}: {reason}")
        if obs:
            print(f"            ↳ {obs[:120]}...")

async def run_audit(target_url: str):
    print(f"\n==================================================================")
    print(f"🚀 Running LangGraph Multi-Agent Security Audit on: {target_url}")
    print(f"==================================================================")

    last_step_count = 0

    def on_step(trace):
        nonlocal last_step_count
        if len(trace) > last_step_count:
            last_step_count = len(trace)
            print_trace(trace)

    report = await run_langgraph_security_audit(
        target_url=target_url,
        on_step_callback=on_step,
        use_local_fallback=True,
    )

    print("\n------------------------------------------------------------------")
    print("📊 Audit Results Summary:")
    print(f"  - Workflow:    {report.get('workflow')}")
    print(f"  - Target:      {report.get('target_url')}")
    print(f"  - Score:       {report.get('score')} / 100 (Grade: {report.get('grade')})")
    print(f"  - Status:      {report.get('scan_status')}")
    print(f"  - Coverage:    {report.get('coverage_percentage')}%")
    print(f"  - Pass Rate:   {report.get('pass_rate_percentage')}%")
    print(f"  - Findings:    {len(report.get('findings', []))} verified finding(s)")

    if report.get("screenshot"):
        print(f"  - Screenshot:  {report.get('screenshot')}")

    print("\n🔍 Verified Findings:")
    for f in report.get("findings", []):
        print(f"  • [{str(f.get('severity', 'info')).upper()}] {f.get('detail', f.get('title'))}")
        print(f"    Evidence:    {f.get('evidence')[:100]}...")
        if f.get("remediation"):
            print(f"    Remediation: {f.get('remediation')[:100]}...")

    ch_breakdown = report.get("chapter_breakdown", {})
    if ch_breakdown:
        print("\n🏛️  OWASP ASVS 5.0.0 All-Chapters Compliance Matrix (17 Chapters / 345 Requirements):")
        print(f"  {'Code':<6} {'Chapter Name':<38} {'Total':<6} {'Pass':<6} {'Fail':<6} {'Manual':<8} {'Score':<8} {'Grade'}")
        print("  " + "-" * 84)
        for code in sorted(ch_breakdown.keys(), key=lambda x: int(x[1:]) if x[1:].isdigit() else 99):
            cd = ch_breakdown[code]
            sc = f"{cd.get('score')}/100" if cd.get('score') is not None else "N/A"
            print(f"  {code:<6} {cd.get('chapter_name')[:36]:<38} {cd.get('total'):<6} {cd.get('passed'):<6} {cd.get('failed'):<6} {cd.get('manual_verify'):<8} {sc:<8} {cd.get('grade')}")

    print("\n📝 Executive Summary:")
    print(f"  {report.get('summary')}")
    print("==================================================================\n")
    return report

async def main():
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        await run_audit(target_url)
    else:
        print("No target URL specified. Starting local testbed server on port 8003...")
        start_testbed_server(8003)
        print("Testing against local vulnerable testbed: http://127.0.0.1:8003/vulnerable")
        await run_audit("http://127.0.0.1:8003/vulnerable")

if __name__ == "__main__":
    asyncio.run(main())
