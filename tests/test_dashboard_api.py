from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sovereign_gateway.dashboard_api import router


class FakeAuditStore:
    def __init__(self):
        self.events = [
            {
                "id": 5,
                "occurred_at": "2026-10-26T08:35:00+00:00",
                "event_type": "agent.tool.succeeded",
                "actor": "gateway",
                "request_id": "req-123",
                "previous_hash": "p" * 64,
                "event_hash": "h" * 64,
                "details": {
                    "tool_name": "department_summary",
                    "arguments": {"department_code": "IT"},
                    "result_sha256": "d" * 64,
                    "raw_prompt": "must never be returned",
                },
            },
            {
                "id": 4,
                "occurred_at": "2026-10-26T08:34:00+00:00",
                "event_type": "agent.requested",
                "actor": "api-client",
                "request_id": "req-123",
                "previous_hash": "x" * 64,
                "event_hash": "y" * 64,
                "details": {
                    "policy_action": "redacted",
                    "sensitive_categories": {"email": 1},
                    "prompt_hmac": "private-fingerprint",
                    "sanitized_messages": [{"content": "email <REDACTED>"}],
                },
            },
            {
                "id": 3,
                "occurred_at": "2026-10-26T08:33:00+00:00",
                "event_type": "agent.request.blocked",
                "actor": "api-client",
                "request_id": "req-122",
                "previous_hash": "z" * 64,
                "event_hash": "w" * 64,
                "details": {"policy_action": "blocked", "sensitive_categories": {"email": 1}},
            },
        ]

    def list_events(self, limit=100):
        return self.events[:limit]

    def verify(self):
        return {"valid": True, "checked_events": len(self.events), "first_invalid_event_id": None}


class FakeORDSSettings:
    def validate_enabled(self):
        return None


class FakeORDSClient:
    settings = FakeORDSSettings()

    async def list_audit_events(self):
        return [
            {
                "event_id": 21,
                "gateway_request_id": "req-123",
                "occurred_at": "2026-10-26T08:35:01.000",
                "operation_name": "DEPARTMENT_SUMMARY",
                "department_code": "IT",
                "actor": "WKSP_USMAN1415",
                "outcome": "SUCCESS",
                "details": "Approved read-only summary returned",
            },
            {
                "event_id": 20,
                "gateway_request_id": None,
                "occurred_at": "2026-10-26T08:20:00.000",
                "operation_name": "DEPARTMENT_SUMMARY",
                "department_code": "HR",
                "actor": "WKSP_USMAN1415",
                "outcome": "SUCCESS",
                "details": "Approved read-only summary returned",
            },
        ]


def make_client():
    app = FastAPI()
    app.include_router(router)
    app.state.settings = SimpleNamespace(admin_api_key="admin-test-key")
    app.state.audit_store = FakeAuditStore()
    app.state.ords_client = FakeORDSClient()
    return TestClient(app)


def test_dashboard_shell_is_no_store_and_contains_no_data():
    client = make_client()
    response = client.get("/admin/dashboard")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "Security &amp; Activity Monitor" not in response.text  # Static HTML is plain text, not escaped.
    assert "Security & Activity Monitor" in response.text


def test_dashboard_api_requires_admin_key():
    client = make_client()
    response = client.get("/admin/dashboard/api/overview")
    assert response.status_code == 401


def test_overview_returns_metrics_and_audit_integrity():
    client = make_client()
    response = client.get(
        "/admin/dashboard/api/overview",
        headers={"X-Admin-Key": "admin-test-key"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["agent_requests"] == 2
    assert data["blocked_events"] == 1
    assert data["redacted_requests"] == 1
    assert data["tool_executions"] == 1
    assert data["audit_integrity"]["valid"] is True


def test_event_api_does_not_return_raw_prompt_or_prompt_fingerprint():
    client = make_client()
    response = client.get(
        "/admin/dashboard/api/events",
        headers={"X-Admin-Key": "admin-test-key"},
    )
    assert response.status_code == 200
    body = response.text
    assert "must never be returned" not in body
    assert "private-fingerprint" not in body
    assert "sanitized_messages" not in body
    assert "department_summary" in body


def test_oracle_audit_and_request_correlation():
    client = make_client()
    headers = {"X-Admin-Key": "admin-test-key"}
    audit = client.get("/admin/dashboard/api/oracle-audit", headers=headers)
    assert audit.status_code == 200
    assert audit.json()["count"] == 2
    assert audit.json()["correlated_count"] == 1
    assert audit.json()["correlated_request_ids"] == ["req-123"]

    correlation = client.get("/admin/dashboard/api/correlation", headers=headers)
    assert correlation.status_code == 200
    data = correlation.json()
    assert data["matched_count"] == 1
    assert data["unmatched_oracle_count"] == 1
    assert data["matched"][0]["oracle_event"]["gateway_request_id"] == "req-123"
