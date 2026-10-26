from __future__ import annotations

import json

import httpx
from fastapi.testclient import TestClient

import sovereign_gateway.ords_api as ords_api
from sovereign_gateway.audit import AuditStore
from sovereign_gateway.config import Settings
from sovereign_gateway.main import create_app
from sovereign_gateway.ords_api import ORDSClient, ORDSOAuthError, ORDSSettings
from sovereign_gateway.redaction import inspect_and_redact


CLIENT_HEADERS = {"X-API-Key": "client-test-key"}
ADMIN_HEADERS = {"X-Admin-Key": "admin-test-key"}


def test_redactor_masks_common_sensitive_values():
    text = "Contact alice@example.com or +92 300 1234567. CNIC 35202-1234567-1; password=hunter2; key sk-abcdefghijklmnop1234"
    cleaned, findings = inspect_and_redact(text)
    categories = {item.category for item in findings}
    assert "alice@example.com" not in cleaned
    assert "35202-1234567-1" not in cleaned
    assert "+92 300 1234567" not in cleaned
    assert "hunter2" not in cleaned
    assert "sk-abcdefghijklmnop1234" not in cleaned
    assert {"email", "phone", "cnic", "password", "api_key"}.issubset(categories)


def make_client(tmp_path, policy_mode="redact", capture_mode="metadata"):
    settings = Settings(
        client_api_key="client-test-key",
        admin_api_key="admin-test-key",
        audit_hmac_key="test-hmac-secret",
        database_path=str(tmp_path / "audit.sqlite3"),
        initial_provider="mock",
        initial_model="offline-test",
        initial_policy_mode=policy_mode,
        initial_capture_mode=capture_mode,
        ollama_base_url="http://localhost:11434",
        ollama_model="llama3.2",
    )
    app = create_app(settings)
    return TestClient(app), settings


def test_redact_mode_forwards_only_sanitized_prompt_and_audits(tmp_path):
    client, settings = make_client(tmp_path)
    response = client.post(
        "/v1/chat/completions",
        headers=CLIENT_HEADERS,
        json={"messages": [{"role": "user", "content": "Email alice@example.com and password=secret123"}]},
    )
    assert response.status_code == 200
    assert response.json()["gateway"]["policy_action"] == "redacted"
    events = client.get("/admin/audit", headers=ADMIN_HEADERS).json()["events"]
    request_event = next(event for event in events if event["event_type"] == "chat.request")
    encoded = json.dumps(request_event["details"])
    assert "alice@example.com" not in encoded
    assert "secret123" not in encoded
    assert client.get("/admin/audit/verify", headers=ADMIN_HEADERS).json()["valid"] is True


def test_ords_settings_loads_dotenv_values(monkeypatch):
    called = {"value": False}

    def fake_load_dotenv(*args, **kwargs):
        called["value"] = True
        monkeypatch.setenv("ORDS_ENABLED", "true")
        monkeypatch.setenv("ORDS_BASE_URL", "https://oracleapex.com/ords/sagdemo")
        monkeypatch.setenv("ORDS_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("ORDS_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("ORDS_TIMEOUT_SECONDS", "30")

    monkeypatch.setattr(ords_api, "load_dotenv", fake_load_dotenv)
    for key in [
        "ORDS_ENABLED",
        "ORDS_BASE_URL",
        "ORDS_CLIENT_ID",
        "ORDS_CLIENT_SECRET",
        "ORDS_TIMEOUT_SECONDS",
    ]:
        monkeypatch.delenv(key, raising=False)

    settings = ORDSSettings.from_env()

    assert called["value"] is True
    assert settings.enabled is True
    assert settings.base_url == "https://oracleapex.com/ords/sagdemo"
    assert settings.client_id == "test-client-id"
    assert settings.client_secret == "test-client-secret"
    assert settings.timeout_seconds == 30.0


async def test_ords_token_timeout_is_reported_as_gateway_timeout():
    def timeout_request(request):
        raise httpx.ReadTimeout("timed out", request=request)

    settings = ORDSSettings(
        enabled=True,
        base_url="https://oracleapex.com/ords/sagdemo",
        client_id="test-client-id",
        client_secret="test-client-secret",
        timeout_seconds=30.0,
    )
    client = ORDSClient(settings, transport=httpx.MockTransport(timeout_request))

    import pytest

    with pytest.raises(ORDSOAuthError) as error:
        await client._fetch_token()

    assert error.value.code == "ords_oauth_timeout"
    assert error.value.status_code == 504


def test_block_mode_does_not_contact_provider(tmp_path):
    client, _ = make_client(tmp_path, policy_mode="block")
    response = client.post(
        "/v1/chat/completions",
        headers=CLIENT_HEADERS,
        json={"messages": [{"role": "user", "content": "My email is alice@example.com"}]},
    )
    assert response.status_code == 403
    events = client.get("/admin/audit", headers=ADMIN_HEADERS).json()["events"]
    assert events[0]["event_type"] == "chat.blocked"
    assert events[0]["details"]["provider_contacted"] is False


def test_authentication_is_required(tmp_path):
    client, _ = make_client(tmp_path)
    response = client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "hello"}]})
    assert response.status_code == 401
    assert client.get("/admin/audit").status_code == 401


def test_audit_chain_detects_modified_event(tmp_path):
    db_path = str(tmp_path / "tamper.sqlite3")
    store = AuditStore(db_path)
    store.append("test.one", "tester", None, {"value": "one"})
    store.append("test.two", "tester", None, {"value": "two"})
    assert store.verify()["valid"] is True
    with store._connect() as db:
        db.execute("UPDATE audit_events SET details_json = ? WHERE id = 1", ('{"value":"modified"}',))
    result = store.verify()
    assert result["valid"] is False
    assert result["first_invalid_event_id"] == 1


def test_admin_can_change_policy_and_change_is_audited(tmp_path):
    client, _ = make_client(tmp_path)
    response = client.patch("/admin/config", headers=ADMIN_HEADERS, json={"policy_mode": "block"})
    assert response.status_code == 200
    assert response.json()["policy_mode"] == "block"
    events = client.get("/admin/audit", headers=ADMIN_HEADERS).json()["events"]
    assert events[0]["event_type"] == "config.changed"


def test_redacted_capture_stores_only_sanitized_content(tmp_path):
    client, _ = make_client(tmp_path, capture_mode="redacted")
    response = client.post(
        "/v1/chat/completions",
        headers=CLIENT_HEADERS,
        json={"messages": [{"role": "user", "content": "Email alice@example.com"}]},
    )
    assert response.status_code == 200
    events = client.get("/admin/audit", headers=ADMIN_HEADERS).json()["events"]
    request_event = next(event for event in events if event["event_type"] == "chat.request")
    sanitized = request_event["details"]["sanitized_messages"][0]["content"]
    assert "alice@example.com" not in sanitized
    assert "<REDACTED:EMAIL>" in sanitized


def test_runtime_config_is_compared_with_audited_snapshot(tmp_path):
    client, settings = make_client(tmp_path)
    client.patch("/admin/config", headers=ADMIN_HEADERS, json={"policy_mode": "block"})
    with client.app.state.audit_store._connect() as db:
        db.execute("UPDATE runtime_config SET config_json = ? WHERE singleton_id = 1", ('{"capture_mode":"metadata","model":"offline-test","policy_mode":"redact","provider":"mock"}',))
    import pytest
    with pytest.raises(RuntimeError, match="does not match"):
        create_app(settings)


def test_switching_provider_selects_its_configured_model(tmp_path):
    client, _ = make_client(tmp_path)
    response = client.patch("/admin/config", headers=ADMIN_HEADERS, json={"provider": "ollama"})
    assert response.status_code == 200
    assert response.json()["provider"] == "ollama"
    assert response.json()["model"] == "llama3.2"
    response = client.patch("/admin/config", headers=ADMIN_HEADERS, json={"provider": "mock"})
    assert response.status_code == 200
    assert response.json()["model"] == "offline-test"
