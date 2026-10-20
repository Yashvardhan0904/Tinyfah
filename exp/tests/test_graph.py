from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from app.agent.graph import GraphDeps, build_exploit_graph, initial_state

SNAPSHOT = {
    "url": "https://staging.example.com/",
    "origin": "https://staging.example.com",
    "title": "Example",
    "links": [
        {"href": "http://insecure.example.com/x", "text": "x"},
        {"href": "https://staging.example.com/?token=leak", "text": "y"},
    ],
    "forms": [
        {
            "action": "https://staging.example.com/",
            "method": "GET",
            "inputs": [{"name": "q", "type": "text"}],
        }
    ],
}

TARGET = "https://staging.example.com/"


def _get_action() -> dict:
    return {
        "id": "get1",
        "playbook": "reflected_input",
        "description": "probe reflection",
        "method": "GET",
        "target": "https://staging.example.com/?q=canary",
        "params": {},
        "tool": "http_get",
        "verifier": "reflected_canary",
        "action_class": "PROBE",
    }


def _post_action() -> dict:
    return {
        "id": "post1",
        "playbook": "state",
        "description": "state change",
        "method": "POST",
        "target": "https://staging.example.com/api/update",
        "params": {},
        "tool": "http_post",
        "verifier": "unauthenticated_admin_access",
        "action_class": "STATE_CHANGE",
    }


def _deps(executed: list[str], candidates: list[dict]) -> GraphDeps:
    async def recon(_state):
        return {
            "snapshot": SNAPSHOT,
            "inventory": {"admin_hints": [], "forms": []},
            "browser_mode": "fake",
        }

    async def plan(_state):
        return list(candidates)

    async def execute(state, action):
        executed.append(action["id"])
        if action["verifier"] == "reflected_canary":
            body = f"<html>{state['canary']}</html>"
        else:
            body = "Welcome to the admin panel"
        return {"status": 200, "body_excerpt": body, "headers": {}, "url": action["target"]}

    return GraphDeps(recon=recon, plan=plan, execute=execute)


async def test_explore_completes_and_skips_disabled_state_change():
    executed: list[str] = []
    graph = build_exploit_graph(
        deps=_deps(executed, [_get_action(), _post_action()]), checkpointer=MemorySaver()
    )
    config = {"configurable": {"thread_id": "t-complete"}}

    await graph.ainvoke(initial_state("t-complete", TARGET), config)
    snapshot = await graph.aget_state(config)
    report = snapshot.values["report"]

    assert executed == ["get1"]
    assert report["actions_planned"] == 2
    assert report["finding_count"] >= 2
    reasons = " ".join(item["reason"] for item in report["skipped"])
    assert "disabled" in reasons


async def test_state_change_requires_and_honors_approval():
    executed: list[str] = []
    graph = build_exploit_graph(deps=_deps(executed, [_post_action()]), checkpointer=MemorySaver())
    config = {"configurable": {"thread_id": "t-approve"}}

    first = await graph.ainvoke(
        initial_state("t-approve", TARGET, approved_state_change=True), config
    )
    assert "__interrupt__" in first
    pending = await graph.aget_state(config)
    assert pending.next

    await graph.ainvoke(Command(resume=True), config)
    final = await graph.aget_state(config)

    assert executed == ["post1"]
    assert final.values["report"]["finding_count"] >= 1


async def test_state_change_denial_skips_action():
    executed: list[str] = []
    graph = build_exploit_graph(deps=_deps(executed, [_post_action()]), checkpointer=MemorySaver())
    config = {"configurable": {"thread_id": "t-deny"}}

    await graph.ainvoke(initial_state("t-deny", TARGET, approved_state_change=True), config)
    await graph.ainvoke(Command(resume=False), config)
    final = await graph.aget_state(config)

    assert executed == []
    reasons = " ".join(item["reason"] for item in final.values["report"]["skipped"])
    assert "denied" in reasons
