from app.agent import verifiers
from app.agent.verifiers import (
    VerificationInput,
    static_findings,
    verify_access_control_bypass,
    verify_exposed_artifact,
    verify_reflected_canary,
)


def _action(verifier: str, target: str) -> dict:
    return {"id": "a1", "verifier": verifier, "target": target}


def test_exposed_artifact_openapi_is_medium():
    inp = VerificationInput(
        action=_action("exposed_artifact", "https://staging.example.com/openapi.json"),
        response={"status": 200, "body_excerpt": '{"openapi":"3.0.0","paths":{}}'},
    )
    out = verify_exposed_artifact(inp)
    assert out is not None
    assert out["verified"] is True
    assert out["severity"] == "medium"


def test_exposed_artifact_env_is_high():
    inp = VerificationInput(
        action=_action("exposed_artifact", "https://staging.example.com/.env"),
        response={"status": 200, "body_excerpt": "DB_PASSWORD=supersecret\nDEBUG=true"},
    )
    out = verify_exposed_artifact(inp)
    assert out is not None
    assert out["severity"] == "high"


def test_exposed_artifact_missing_returns_none():
    inp = VerificationInput(
        action=_action("exposed_artifact", "https://staging.example.com/.env"),
        response={"status": 404, "body_excerpt": "not found"},
    )
    assert verify_exposed_artifact(inp) is None


def test_reflected_canary_unescaped_verified():
    canary = "<tinyfah-canary-1>"
    inp = VerificationInput(
        action=_action("reflected_canary", "https://staging.example.com/?q=x"),
        response={"status": 200, "body_excerpt": f"<html><body>{canary}</body></html>"},
        canary=canary,
    )
    out = verify_reflected_canary(inp)
    assert out is not None
    assert out["severity"] == "medium"


def test_reflected_canary_escaped_is_ignored():
    canary = "<tinyfah-canary-1>"
    inp = VerificationInput(
        action=_action("reflected_canary", "https://staging.example.com/?q=x"),
        response={"status": 200, "body_excerpt": "<html>&lt;tinyfah-canary-1&gt;</html>"},
        canary=canary,
    )
    assert verify_reflected_canary(inp) is None


def test_access_control_bypass_detects_admin_body():
    inp = VerificationInput(
        action=_action("access_control_bypass", "https://staging.example.com/?role=admin"),
        response={"status": 200, "body_excerpt": "Welcome to the admin panel", "headers": {}},
    )
    out = verify_access_control_bypass(inp)
    assert out is not None
    assert out["severity"] == "high"


def test_access_control_bypass_ignores_redirect_to_login():
    inp = VerificationInput(
        action=_action("access_control_bypass", "https://staging.example.com/?role=admin"),
        response={
            "status": 200,
            "body_excerpt": "admin panel",
            "headers": {"location": "/login"},
        },
    )
    assert verify_access_control_bypass(inp) is None


def test_access_control_bypass_ignores_marker_present_in_control():
    inp = VerificationInput(
        action=_action("access_control_bypass", "https://staging.example.com/?role=admin"),
        response={"status": 200, "body_excerpt": "admin panel", "headers": {}},
        baseline={"status": 200, "body_excerpt": "admin panel", "headers": {}},
    )
    assert verify_access_control_bypass(inp) is None


def test_static_findings_cover_transport_and_credentials():
    snapshot = {
        "url": "https://staging.example.com/",
        "links": [
            {"href": "http://insecure.example.com/thing", "text": "x"},
            {"href": "https://staging.example.com/?token=abc123", "text": "y"},
        ],
        "forms": [],
    }
    names = {finding["verifier"] for finding in static_findings(snapshot)}
    assert "transport_weakness" in names
    assert "credential_in_url" in names


def test_verifiers_registry_contains_expected_keys():
    for name in (
        "exposed_artifact",
        "graphql_introspection",
        "access_control_bypass",
        "unauthenticated_admin_access",
        "reflected_canary",
    ):
        assert name in verifiers.VERIFIERS
