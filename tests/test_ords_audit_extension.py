from __future__ import annotations

import json

import httpx
import pytest

from sovereign_gateway.ords_api import ORDSClient, ORDSSettings


@pytest.mark.asyncio
async def test_department_summary_sends_gateway_request_id():
    seen = {"token": 0, "body": None}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth/token"):
            seen["token"] += 1
            return httpx.Response(
                200,
                json={"access_token": "test-token", "token_type": "bearer", "expires_in": 36000},
            )
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "department_name": "Information Technology",
                "headcount": 18,
                "monthly_budget": 42000,
                "currency_code": "USD",
            },
        )

    settings = ORDSSettings(True, "https://oracleapex.com/ords/sagdemo", "id", "secret")
    client = ORDSClient(settings, transport=httpx.MockTransport(handler))
    result = await client.department_summary("IT", gateway_request_id="7c1df6cf-99b8-41c4-ac87-af100f32e4d9")

    assert result["headcount"] == 18
    assert seen["body"] == {
        "department_code": "IT",
        "gateway_request_id": "7c1df6cf-99b8-41c4-ac87-af100f32e4d9",
    }
    assert seen["token"] == 1


@pytest.mark.asyncio
async def test_oracle_audit_events_are_normalized():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth/token"):
            return httpx.Response(
                200,
                json={"access_token": "test-token", "token_type": "bearer", "expires_in": 36000},
            )
        assert request.url.path.endswith("/ai-gateway/audit/")
        assert request.headers["user-agent"] == "SovereignAIGateway/0.1"
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "EVENT_ID": 19,
                        "GATEWAY_REQUEST_ID": "7c1df6cf-99b8-41c4-ac87-af100f32e4d9",
                        "OCCURRED_AT": "2026-10-26T08:30:00.000",
                        "OPERATION_NAME": "DEPARTMENT_SUMMARY",
                        "DEPARTMENT_CODE": "IT",
                        "ACTOR": "WKSP_USMAN1415",
                        "OUTCOME": "SUCCESS",
                        "DETAILS": "Approved read-only summary returned",
                        "UNEXPECTED_COLUMN": "must be discarded",
                    }
                ]
            },
        )

    settings = ORDSSettings(True, "https://oracleapex.com/ords/sagdemo", "id", "secret")
    client = ORDSClient(settings, transport=httpx.MockTransport(handler))
    rows = await client.list_audit_events()
    assert len(rows) == 1
    assert rows[0]["event_id"] == 19
    assert rows[0]["department_code"] == "IT"
    assert "unexpected_column" not in rows[0]
