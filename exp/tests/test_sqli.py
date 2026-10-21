from langgraph.checkpoint.memory import MemorySaver

from app.agent.graph import GraphDeps, build_exploit_graph, initial_state
from app.agent.playbooks import SQLI_USERNAME_PAYLOADS, build_candidates
from app.agent.verifiers import VerificationInput, verify_sql_injection_login

TARGET = "https://staging.example.com/login"

SNAPSHOT = {
    "url": TARGET,
    "origin": "https://staging.example.com",
    "title": "Login",
    "links": [],
    "forms": [
        {
            "action": "https://staging.example.com/login",
            "method": "POST",
            "inputs": [
                {"name": "email", "type": "email"},
                {"name": "password", "type": "password"},
                {"name": "csrf", "type": "hidden"},
            ],
        }
    ],
    "hasPasswordField": True,
}

INVENTORY = {
    "admin_hints": [{"href": "https://staging.example.com/admin", "text": "Admin"}],
    "forms": SNAPSHOT["forms"],
    "has_password_field": True,
}


def _sqli_candidates() -> list[dict]:
    return build_candidates(
        SNAPSHOT,
        INVENTORY,
        target_url=TARGET,
        canary="<canary>",
        include_sqli=True,
    )


def test_login_form_generates_browser_sqli_candidates():
    candidates = [c for c in _sqli_candidates() if c["playbook"] == "sql_injection_auth_bypass"]
    assert len(candidates) == len(SQLI_USERNAME_PAYLOADS)
    first = candidates[0]
    assert first["tool"] == "browser_sql_login"
    assert first["verifier"] == "sql_injection_login"
    assert first["action_class"] == "STATE_CHANGE"
    assert first["login"]["username_field"] == "email"
    assert first["login"]["password_field"] == "password"
    assert first["login"]["admin_target"] == "https://staging.example.com/admin"


def test_admin_target_prefers_same_origin_over_internal_hosts():
    inventory = {
        **INVENTORY,
        "admin_hints": [
            {"href": "http://insecure-auth-gateway.internal/api/login", "text": "Internal"},
            {"href": "https://staging.example.com/admin", "text": "Admin"},
        ],
    }
    candidates = [
        candidate
        for candidate in build_candidates(
            SNAPSHOT,
            inventory,
            target_url=TARGET,
            canary="<canary>",
            include_sqli=True,
        )
        if candidate["playbook"] == "sql_injection_auth_bypass"
    ]
    assert candidates[0]["login"]["admin_target"] == "https://staging.example.com/admin"


def test_admin_target_falls_back_to_origin_admin_path():
    inventory = {
        **INVENTORY,
        "admin_hints": [
            {"href": "http://insecure-auth-gateway.internal/api/login", "text": "Internal"},
        ],
    }
    candidates = [
        candidate
        for candidate in build_candidates(
            SNAPSHOT,
            inventory,
            target_url=TARGET,
            canary="<canary>",
            include_sqli=True,
        )
        if candidate["playbook"] == "sql_injection_auth_bypass"
    ]
    assert candidates[0]["login"]["admin_target"] == "https://staging.example.com/admin"


def test_login_link_generates_sqli_candidates_without_inline_form():
    snapshot = {
        **SNAPSHOT,
        "forms": [],
        "links": [
            {"href": "https://staging.example.com/login", "text": "Sign in"},
            {"href": "https://staging.example.com/logout", "text": "Log out"},
        ],
    }
    candidates = [
        candidate
        for candidate in build_candidates(
            snapshot,
            {"admin_hints": [], "forms": []},
            target_url=TARGET,
            canary="<canary>",
            include_sqli=True,
        )
        if candidate["playbook"] == "sql_injection_auth_bypass"
    ]

    assert len(candidates) == len(SQLI_USERNAME_PAYLOADS)
    assert candidates[0]["login"]["page_url"] == "https://staging.example.com/login"
    assert candidates[0]["login"]["username_field"] == ""


def test_no_sqli_candidates_without_password_field():
    snapshot = {
        **SNAPSHOT,
        "forms": [
            {
                "action": TARGET,
                "method": "GET",
                "inputs": [{"name": "q", "type": "text"}],
            }
        ],
    }
    candidates = build_candidates(
        snapshot,
        {"admin_hints": [], "forms": snapshot["forms"]},
        target_url=TARGET,
        canary="<canary>",
        include_sqli=True,
    )
    assert all(c["playbook"] != "sql_injection_auth_bypass" for c in candidates)


def test_verify_sql_injection_login_requires_authenticated_response():
    action = _sqli_candidates()[0]
    verified = verify_sql_injection_login(
        VerificationInput(
            action=action,
            response={
                "authenticated": True,
                "url": "https://staging.example.com/admin",
                "matched_marker": "admin panel",
                "screenshot": "shot.png",
                "browser_mode": "tinyfish",
            },
        )
    )
    assert verified is not None
    assert verified["severity"] == "critical"
    assert verified["evidence"]["screenshot"] == "shot.png"

    denied = verify_sql_injection_login(
        VerificationInput(action=action, response={"authenticated": False})
    )
    assert denied is None


async def test_sqli_mode_executes_without_manual_approval():
    executed: list[str] = []

    async def recon(_state):
        return {"snapshot": SNAPSHOT, "inventory": INVENTORY, "browser_mode": "fake"}

    async def execute(_state, action):
        executed.append(action["id"])
        return {
            "status": 200,
            "url": "https://staging.example.com/admin",
            "body_excerpt": "Admin panel",
            "headers": {},
            "authenticated": True,
            "matched_marker": "admin panel",
            "screenshot": "sqli_admin.png",
            "browser_mode": "fake",
        }

    graph = build_exploit_graph(
        deps=GraphDeps(recon=recon, execute=execute), checkpointer=MemorySaver()
    )
    config = {"configurable": {"thread_id": "t-sqli"}}
    await graph.ainvoke(
        initial_state("t-sqli", TARGET, mode="sqli", approved_state_change=True), config
    )
    snapshot = await graph.aget_state(config)

    assert len(executed) == 1
    assert snapshot.values["report"]["finding_count"] == 1
    assert snapshot.values["report"]["screenshots"] == ["sqli_admin.png"]


async def test_sqli_mode_skips_when_state_change_disabled():
    executed: list[str] = []

    async def recon(_state):
        return {"snapshot": SNAPSHOT, "inventory": INVENTORY, "browser_mode": "fake"}

    async def execute(_state, action):
        executed.append(action["id"])
        return {"status": 200, "url": TARGET, "body_excerpt": "", "headers": {}}

    graph = build_exploit_graph(
        deps=GraphDeps(recon=recon, execute=execute), checkpointer=MemorySaver()
    )
    config = {"configurable": {"thread_id": "t-sqli-off"}}
    await graph.ainvoke(
        initial_state("t-sqli-off", TARGET, mode="sqli", approved_state_change=False), config
    )
    snapshot = await graph.aget_state(config)

    assert executed == []
    reasons = " ".join(item["reason"] for item in snapshot.values["report"]["skipped"])
    assert "disabled" in reasons
