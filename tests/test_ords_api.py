from __future__ import annotations

import json

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sovereign_gateway.ords_api import ORDSClient, ORDSSettings, DepartmentSummaryRequest


@pytest.mark.asyncio
async def test_oauth_token_is_cached_and_department_list_is_parsed():
    calls = {"token": 0, "departments": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth/token"):
            calls["token"] += 1
            assert request.method == "POST"
            assert request.content.decode() == "grant_type=client_credentials"
            return httpx.Response(200, json={"access_token": "test-token", "token_type": "bearer", "expires_in": 36000})
        if request.url.path.endswith("/ai-gateway/departments/"):
            calls["departments"] += 1
            assert request.headers.get("authorization") == "Bearer test-token"
            return httpx.Response(200, json={"items": [{
                "DEPARTMENT_CODE": "IT",
                "DEPARTMENT_NAME": "Information Technology",
                "HEADCOUNT": 18,
                "MONTHLY_BUDGET": 42000,
                "CURRENCY_CODE": "USD",
                "UPDATED_AT": "2026-10-21T00:00:00Z",
            }]})
        return httpx.Response(404)

    settings = ORDSSettings(True, "https://oracleapex.com/ords/sagdemo", "client-id", "client-secret")
    client = ORDSClient(settings, transport=httpx.MockTransport(handler))
    first = await client.list_departments()
    second = await client.list_departments()

    assert first[0]["department_code"] == "IT"
    assert first[0]["headcount"] == 18
    assert second == first
    assert calls == {"token": 1, "departments": 2}


@pytest.mark.asyncio
async def test_summary_sends_only_approved_code_in_json_body():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth/token"):
            return httpx.Response(200, json={"access_token": "test-token", "token_type": "bearer", "expires_in": 36000})
        assert request.method == "POST"
        assert request.url.path.endswith("/ai-gateway/department-summary/")
        assert json.loads(request.content) == {"department_code": "OPS"}
        return httpx.Response(200, json={
            "department_name": "Operations",
            "headcount": 27,
            "monthly_budget": 51000,
            "currency_code": "USD",
            "message": "Department summary retrieved",
        })

    settings = ORDSSettings(True, "https://oracleapex.com/ords/sagdemo", "client-id", "client-secret")
    client = ORDSClient(settings, transport=httpx.MockTransport(handler))
    result = await client.department_summary("OPS")
    assert result["department_name"] == "Operations"
    assert result["headcount"] == 27
    assert result["data_source"] == "oracle_apex_ords"


def test_department_code_validation_normalizes_and_rejects_extra_fields():
    valid = DepartmentSummaryRequest(department_code=" it ")
    assert valid.department_code == "IT"

    with pytest.raises(Exception):
        DepartmentSummaryRequest(department_code="IT; DROP TABLE AI_DEPARTMENTS")

    with pytest.raises(Exception):
        DepartmentSummaryRequest(department_code="IT", sql="select * from dual")


def test_ords_settings_require_https_and_credentials_when_enabled(monkeypatch):
    monkeypatch.setenv("ORDS_ENABLED", "true")
    monkeypatch.setenv("ORDS_BASE_URL", "http://oracleapex.com/ords/sagdemo")
    monkeypatch.setenv("ORDS_CLIENT_ID", "client")
    monkeypatch.setenv("ORDS_CLIENT_SECRET", "secret")
    with pytest.raises(RuntimeError):
        ORDSSettings.from_env()
