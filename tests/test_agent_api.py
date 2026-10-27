from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sovereign_gateway.agent_api import router
from sovereign_gateway.ords_api import ORDSSettings


class MemoryAuditStore:
    def __init__(self):
        self.events = []

    def append(self, event_type, actor, request_id, details):
        self.events.append({
            "event_type": event_type,
            "actor": actor,
            "request_id": request_id,
            "details": details,
        })


class FakeORDSClient:
    def __init__(self):
        self.settings = ORDSSettings(
            True,
            "https://oracleapex.com/ords/sagdemo",
            "test-client",
            "test-secret",
        )
        self.summary_calls = []
        self.list_calls = 0

    async def department_summary(self, department_code, *, gateway_request_id=None):
        self.summary_calls.append((department_code, gateway_request_id))
        return {
            "department_code": department_code,
            "department_name": "Information Technology",
            "headcount": 18,
            "monthly_budget": 42000,
            "currency_code": "USD",
            "data_source": "oracle_apex_ords",
        }

    async def list_departments(self):
        self.list_calls += 1
        return [
            {
                "department_code": "IT",
                "department_name": "Information Technology",
                "headcount": 18,
                "monthly_budget": 42000,
                "currency_code": "USD",
            }
        ]


def make_app(monkeypatch, ollama_handler, *, policy_mode="redact"):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "gemma4:e4b")
    monkeypatch.setenv("AUDIT_HMAC_KEY", "test-hmac-key")

    app = FastAPI()
    app.include_router(router)
    app.state.settings = SimpleNamespace(
        client_api_key="test-gateway-key",
        audit_hmac_key="test-hmac-key",
        ollama_base_url="http://127.0.0.1:11434",
        ollama_model="gemma4:e4b",
    )
    app.state.runtime_config = {"policy_mode": policy_mode}
    app.state.audit_store = MemoryAuditStore()
    app.state.ords_client = FakeORDSClient()
    app.state.ollama_transport = httpx.MockTransport(ollama_handler)
    return app


def assistant_tool_call(name="department_summary", arguments=None):
    return {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "function": {
                    "name": name,
                    "arguments": arguments if arguments is not None else {"department_code": "IT"},
                }
            }
        ],
    }


def test_agent_executes_allowlisted_summary_and_returns_final_answer(monkeypatch):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        seen.append(payload)
        if len(seen) == 1:
            assert "tools" in payload
            assert request.headers["user-agent"] == "SovereignAIGateway/0.1"
            return httpx.Response(200, json={"model": "gemma4:e4b", "message": assistant_tool_call()})
        assert "tools" not in payload
        messages = payload["messages"]
        assert messages[-1]["role"] == "tool"
        assert messages[-1]["tool_name"] == "department_summary"
        tool_result = json.loads(messages[-1]["content"])
        assert tool_result["headcount"] == 18
        return httpx.Response(200, json={
            "model": "gemma4:e4b",
            "message": {"role": "assistant", "content": "IT has 18 employees and a monthly budget of USD 42,000."},
        })

    app = make_app(monkeypatch, handler)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/chat",
            headers={"X-API-Key": "test-gateway-key"},
            json={"message": "How many employees work in IT and what is its monthly budget?"},
        )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["tool_execution"] == {"name": "department_summary", "arguments": {"department_code": "IT"}}
    assert data["data"]["headcount"] == 18
    assert "18 employees" in data["answer"]
    assert len(app.state.ords_client.summary_calls) == 1
    assert app.state.ords_client.summary_calls[0][0] == "IT"
    assert app.state.ords_client.summary_calls[0][1] == data["request_id"]
    assert len(seen) == 2
    event_names = [event["event_type"] for event in app.state.audit_store.events]
    assert "agent.tool.requested" in event_names
    assert "agent.tool.succeeded" in event_names
    assert "agent.completed" in event_names


def test_agent_executes_department_list(monkeypatch):
    calls = {"ollama": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["ollama"] += 1
        payload = json.loads(request.content)
        if calls["ollama"] == 1:
            return httpx.Response(200, json={
                "model": "gemma4:e4b",
                "message": assistant_tool_call("list_departments", {}),
            })
        assert payload["messages"][-1]["tool_name"] == "list_departments"
        return httpx.Response(200, json={
            "model": "gemma4:e4b",
            "message": {"role": "assistant", "content": "The IT department has 18 employees."},
        })

    app = make_app(monkeypatch, handler)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/chat",
            headers={"X-API-Key": "test-gateway-key"},
            json={"message": "List the departments."},
        )

    assert response.status_code == 200, response.text
    assert response.json()["tool_execution"]["name"] == "list_departments"
    assert app.state.ords_client.list_calls == 1


def test_unknown_tool_is_rejected_and_not_executed(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "model": "gemma4:e4b",
            "message": assistant_tool_call("run_sql", {"sql": "select * from user_tables"}),
        })

    app = make_app(monkeypatch, handler)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/chat",
            headers={"X-API-Key": "test-gateway-key"},
            json={"message": "Show me all tables."},
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "tool_not_allowed"
    assert app.state.ords_client.summary_calls == []
    assert app.state.ords_client.list_calls == 0
    assert any(event["event_type"] == "agent.tool.rejected" for event in app.state.audit_store.events)


def test_block_policy_stops_before_ollama(monkeypatch):
    ollama_calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        ollama_calls["count"] += 1
        return httpx.Response(500)

    app = make_app(monkeypatch, handler, policy_mode="block")
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/chat",
            headers={"X-API-Key": "test-gateway-key"},
            json={"message": "Please look up alice@example.com in the department database."},
        )

    assert response.status_code == 403
    assert ollama_calls["count"] == 0
    assert app.state.ords_client.summary_calls == []


def test_invalid_department_arguments_are_rejected_before_ords(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "model": "gemma4:e4b",
            "message": assistant_tool_call("department_summary", {"department_code": "IT", "sql": "drop table"}),
        })

    app = make_app(monkeypatch, handler)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/chat",
            headers={"X-API-Key": "test-gateway-key"},
            json={"message": "Get the IT department details."},
        )

    assert response.status_code == 422
    assert app.state.ords_client.summary_calls == []


def test_non_tool_response_does_not_claim_database_facts(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "model": "gemma4:e4b",
            "message": {"role": "assistant", "content": "The IT department has 99 employees."},
        })

    app = make_app(monkeypatch, handler)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/chat",
            headers={"X-API-Key": "test-gateway-key"},
            json={"message": "How many employees are in IT?"},
        )

    assert response.status_code == 200
    assert "99 employees" not in response.json()["answer"]
    assert response.json()["tool_execution"] is None
    assert app.state.ords_client.summary_calls == []
