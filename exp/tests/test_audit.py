from app.core.audit import AuditLog


def test_audit_redacts_secrets(tmp_path):
    log = AuditLog("run123", directory=tmp_path)
    log.record(
        "http_request",
        url="https://staging.example.com/login?token=supersecret",
        headers={"Authorization": "Bearer abcdefghijk", "Accept": "text/html"},
        note="password=supersecret",
    )

    entries = log.read()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["event"] == "http_request"
    assert "supersecret" not in str(entry)
    assert entry["headers"]["Authorization"] == "[redacted]"
    assert entry["headers"]["Accept"] == "text/html"


def test_audit_appends(tmp_path):
    log = AuditLog("run456", directory=tmp_path)
    log.record("started", target="https://staging.example.com/")
    log.record("finished", status="completed")
    assert [entry["event"] for entry in log.read()] == ["started", "finished"]
