from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.main as main
from app.main import app

client = TestClient(app)


def test_root_reports_service():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["service"] == "tinyfah-exploit"


def test_health_reports_llm_chain():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["llm"]["configured"] is True
    assert body["llm"]["chain"] == ["ollama/qwen2.5:14b"]


def test_providers_endpoint():
    response = client.get("/providers")
    assert response.status_code == 200
    assert response.json()["chain"] == ["ollama/qwen2.5:14b"]


def test_start_run_rejects_off_scope_target(monkeypatch):
    monkeypatch.setattr(main, "ALLOWED_HOSTS", ("staging.example.com",))
    response = client.post("/runs", json={"target_url": "https://evil.test/"})
    assert response.status_code == 400
    assert "not in EXPLOIT_ALLOWED_HOSTS" in response.json()["detail"]


def test_start_run_rejects_http_target(monkeypatch):
    monkeypatch.setattr(main, "ALLOWED_HOSTS", ("staging.example.com",))
    response = client.post("/runs", json={"target_url": "http://staging.example.com/"})
    assert response.status_code == 400
    assert "https" in response.json()["detail"]


def test_unknown_run_returns_404():
    response = client.get("/runs/does-not-exist")
    assert response.status_code == 404


def test_explore_mode_queues_run(monkeypatch):
    calls: list[tuple[str, str]] = []

    async def fake_explore(run_id: str, target: str) -> None:
        calls.append((run_id, target))

    monkeypatch.setattr(main, "ALLOWED_HOSTS", ("staging.example.com",))
    monkeypatch.setattr(main, "_execute_explore", fake_explore)

    response = client.post(
        "/runs", json={"target_url": "https://staging.example.com/", "mode": "explore"}
    )

    assert response.status_code == 202
    body = response.json()
    assert body["mode"] == "explore"
    assert calls == [(body["id"], "https://staging.example.com/")]


def test_approve_unknown_run_returns_404():
    response = client.post("/runs/does-not-exist/approve", json={"approved": True})
    assert response.status_code == 404


def test_approve_run_not_pending_returns_409(monkeypatch):
    monkeypatch.setattr(main, "get_run", lambda _run_id: SimpleNamespace(id="x", status="queued"))
    response = client.post("/runs/x/approve", json={"approved": True})
    assert response.status_code == 409
