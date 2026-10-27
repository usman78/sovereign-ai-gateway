from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/oracle", tags=["Oracle APEX / ORDS"])

_DEPARTMENT_CODE_RE = re.compile(r"^[A-Z]{2,5}$")


@dataclass(frozen=True)
class ORDSSettings:
    enabled: bool
    base_url: str
    client_id: str
    client_secret: str
    timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> "ORDSSettings":
        enabled = os.getenv("ORDS_ENABLED", "false").strip().lower() in {
            "1", "true", "yes", "on"
        }
        base_url = os.getenv("ORDS_BASE_URL", "").strip().rstrip("/")
        client_id = os.getenv("ORDS_CLIENT_ID", "").strip()
        client_secret = os.getenv("ORDS_CLIENT_SECRET", "")
        try:
            timeout_seconds = float(os.getenv("ORDS_TIMEOUT_SECONDS", "30"))
        except ValueError as exc:
            raise RuntimeError("ORDS_TIMEOUT_SECONDS must be a number") from exc

        if timeout_seconds < 3 or timeout_seconds > 180:
            raise RuntimeError("ORDS_TIMEOUT_SECONDS must be between 3 and 180")

        if enabled:
            parsed = urlsplit(base_url)
            if (
                parsed.scheme != "https"
                or not parsed.netloc
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
            ):
                raise RuntimeError(
                    "ORDS_BASE_URL must be an HTTPS schema URL, e.g. "
                    "https://oracleapex.com/ords/sagdemo"
                )
            if not client_id or not client_secret:
                raise RuntimeError(
                    "ORDS_CLIENT_ID and ORDS_CLIENT_SECRET are required when ORDS_ENABLED=true"
                )

        return cls(
            enabled=enabled,
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            timeout_seconds=timeout_seconds,
        )

    def validate_enabled(self) -> None:
        if not self.enabled:
            raise HTTPException(
                status_code=503,
                detail={"code": "ords_integration_disabled"},
            )


class DepartmentSummaryRequest(BaseModel):
    """Strict input contract. No SQL, table, schema, or package names are accepted."""

    model_config = ConfigDict(extra="forbid")
    department_code: str = Field(
        min_length=2,
        max_length=5,
        description="Synthetic demo department code: IT, HR, FIN or OPS.",
        examples=["IT"],
    )

    @field_validator("department_code")
    @classmethod
    def normalize_department_code(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not _DEPARTMENT_CODE_RE.fullmatch(normalized):
            raise ValueError("department_code must contain 2–5 letters")
        return normalized


class ORDSAPIError(RuntimeError):
    def __init__(self, status_code: int, code: str = "ords_request_failed"):
        super().__init__(code)
        self.status_code = status_code
        self.code = code


class ORDSOAuthError(RuntimeError):
    pass


class ORDSClient:
    """Minimal ORDS client with an in-memory OAuth client-credentials token cache.

    Tokens and client secrets are never logged or written to the audit database.
    Each worker process maintains its own cache and obtains a token as needed.
    """

    def __init__(
        self,
        settings: ORDSSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self._transport = transport
        self._access_token: str | None = None
        self._expires_at = 0.0
        self._token_lock = asyncio.Lock()

    def _client(self, timeout: float | None = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=httpx.Timeout(timeout or self.settings.timeout_seconds, connect=10.0),
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
            headers={
                "Accept": "application/json",
                "User-Agent": "SovereignAIGateway/0.1",
            },
        )

    async def _fetch_token(self) -> tuple[str, float]:
        token_url = f"{self.settings.base_url}/oauth/token"
        try:
            async with self._client(timeout=25.0) as client:
                response = await client.post(
                    token_url,
                    auth=(self.settings.client_id, self.settings.client_secret),
                    data={"grant_type": "client_credentials"},
                    headers={"Accept": "application/json"},
                )
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPStatusError as exc:
            # Avoid logging or returning the OAuth response body: it may contain
            # identity-provider details. The status is enough for diagnostics.
            logger.error("ORDS OAuth token request failed: HTTP %s", exc.response.status_code)
            raise ORDSOAuthError(
                f"ORDS OAuth token endpoint returned HTTP {exc.response.status_code}"
            ) from exc
        except (httpx.RequestError, ValueError) as exc:
            logger.exception("ORDS OAuth token request could not be completed")
            raise ORDSOAuthError(
                f"ORDS OAuth token request failed: {type(exc).__name__}"
            ) from exc

        access_token = payload.get("access_token") if isinstance(payload, dict) else None
        token_type = payload.get("token_type", "Bearer") if isinstance(payload, dict) else ""
        try:
            expires_in = float(payload.get("expires_in", 0)) if isinstance(payload, dict) else 0
        except (TypeError, ValueError):
            expires_in = 0

        if not isinstance(access_token, str) or not access_token or str(token_type).lower() != "bearer":
            raise ORDSOAuthError("ORDS OAuth response did not contain a valid bearer token")
        if expires_in <= 0:
            raise ORDSOAuthError("ORDS OAuth response contained an invalid expires_in value")

        # Refresh slightly before expiry to avoid a token expiring mid-request.
        refresh_margin = min(60.0, max(5.0, expires_in * 0.10))
        cache_for = max(0.0, expires_in - refresh_margin)
        return access_token, time.monotonic() + cache_for

    async def access_token(self, *, force_refresh: bool = False) -> str:
        async with self._token_lock:
            if (
                not force_refresh
                and self._access_token
                and time.monotonic() < self._expires_at
            ):
                return self._access_token

            token, expires_at = await self._fetch_token()
            self._access_token = token
            self._expires_at = expires_at
            return token

    async def _request(
        self,
        method: str,
        resource_path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # resource_path is a fixed literal selected by our route handlers, never user input.
        url = f"{self.settings.base_url}/{resource_path.lstrip('/')}"

        for attempt in range(2):
            token = await self.access_token(force_refresh=(attempt == 1))
            try:
                async with self._client() as client:
                    response = await client.request(
                        method,
                        url,
                        json=json_body,
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/json",
                        },
                    )
                if response.status_code == 401 and attempt == 0:
                    # Cached token may have been revoked; fetch a fresh one and retry once.
                    continue
                if response.status_code >= 400:
                    raise ORDSAPIError(response.status_code)
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise ORDSAPIError(502, "ords_invalid_json_response") from exc
                if not isinstance(payload, dict):
                    raise ORDSAPIError(502, "ords_unexpected_response_shape")
                return payload
            except httpx.TimeoutException as exc:
                logger.warning("ORDS API request timed out: method=%s path=%s", method, resource_path)
                raise ORDSAPIError(504, "ords_request_timeout") from exc
            except httpx.RequestError as exc:
                logger.exception("ORDS API connection failed: method=%s path=%s", method, resource_path)
                raise ORDSAPIError(502, "ords_connection_failed") from exc

        raise ORDSAPIError(502, "ords_authentication_failed")

    async def list_departments(self) -> list[dict[str, Any]]:
        payload = await self._request("GET", "ai-gateway/departments/")
        items = payload.get("items")
        if not isinstance(items, list):
            raise ORDSAPIError(502, "ords_department_list_shape_invalid")

        allowed_fields = (
            "department_code",
            "department_name",
            "headcount",
            "monthly_budget",
            "currency_code",
            "updated_at",
        )
        cleaned: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            lowered = {str(key).lower(): value for key, value in item.items()}
            cleaned.append({field: lowered.get(field) for field in allowed_fields})
        return cleaned

    async def list_audit_events(self) -> list[dict[str, Any]]:
        """Read the latest Oracle-side audit events through a protected, fixed ORDS endpoint."""
        payload = await self._request("GET", "ai-gateway/audit/")
        items = payload.get("items")
        if not isinstance(items, list):
            raise ORDSAPIError(502, "ords_audit_list_shape_invalid")

        allowed_fields = (
            "event_id",
            "gateway_request_id",
            "occurred_at",
            "operation_name",
            "department_code",
            "actor",
            "outcome",
            "details",
        )
        cleaned: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            lowered = {str(key).lower(): value for key, value in item.items()}
            cleaned.append({field: lowered.get(field) for field in allowed_fields})
        return cleaned

    async def department_summary(
        self,
        department_code: str,
        *,
        gateway_request_id: str | None = None,
    ) -> dict[str, Any]:
        request_body: dict[str, Any] = {"department_code": department_code}
        if gateway_request_id:
            request_body["gateway_request_id"] = gateway_request_id
        payload = await self._request(
            "POST",
            "ai-gateway/department-summary/",
            json_body=request_body,
        )
        # ORDS PL/SQL OUT parameters normally appear as top-level JSON properties.
        # Accept a single-item collection too, to tolerate ORDS response variations.
        if isinstance(payload.get("items"), list) and payload["items"]:
            candidate = payload["items"][0]
            if isinstance(candidate, dict):
                payload = candidate
        lowered = {str(key).lower(): value for key, value in payload.items()}
        required = ("department_name", "headcount", "monthly_budget", "currency_code")
        if not all(key in lowered for key in required):
            raise ORDSAPIError(502, "ords_department_summary_shape_invalid")
        return {
            "department_code": department_code,
            "department_name": lowered["department_name"],
            "headcount": lowered["headcount"],
            "monthly_budget": lowered["monthly_budget"],
            "currency_code": lowered["currency_code"],
            "data_source": "oracle_apex_ords",
        }


def _get_ords_client(request: Request) -> ORDSClient:
    client = getattr(request.app.state, "ords_client", None)
    if client is None:
        client = ORDSClient(ORDSSettings.from_env())
        request.app.state.ords_client = client
    client.settings.validate_enabled()
    return client


async def _require_gateway_client(
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> str:
    settings = request.app.state.settings
    supplied = x_api_key
    if not supplied and authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    expected = getattr(settings, "client_api_key", None)
    import hmac

    if not supplied or not expected or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing gateway client API key")
    return "api-client"


def _audit(request: Request):
    store = getattr(request.app.state, "audit_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Gateway audit store is unavailable")
    return store


def _audit_before(store: Any, event_type: str, actor: str, request_id: str, details: dict[str, Any]) -> None:
    try:
        store.append(event_type, actor, request_id, details)
    except Exception as exc:
        logger.exception("Could not write pre-call ORDS audit event")
        raise HTTPException(
            status_code=503,
            detail={"code": "audit_store_unavailable", "ords_contacted": False},
        ) from exc


def _audit_after(store: Any, event_type: str, actor: str, request_id: str, details: dict[str, Any]) -> None:
    try:
        store.append(event_type, actor, request_id, details)
    except Exception as exc:
        logger.exception("Could not write post-call ORDS audit event")
        raise HTTPException(
            status_code=503,
            detail={"code": "audit_recording_failed", "request_id": request_id},
        ) from exc


def _map_ords_error(exc: Exception, request_id: str) -> HTTPException:
    if isinstance(exc, ORDSOAuthError):
        logger.error("ORDS OAuth authentication failed: %s", str(exc))
        return HTTPException(
            status_code=502,
            detail={"code": "ords_oauth_failed", "request_id": request_id},
        )
    if isinstance(exc, ORDSAPIError):
        if exc.status_code == 404:
            status = 404
        elif exc.status_code == 400:
            status = 400
        elif exc.status_code == 504:
            status = 504
        else:
            status = 502
        return HTTPException(
            status_code=status,
            detail={"code": exc.code, "upstream_status": exc.status_code, "request_id": request_id},
        )
    logger.exception("Unexpected ORDS integration error: request_id=%s", request_id)
    return HTTPException(
        status_code=502,
        detail={"code": "ords_unexpected_error", "request_id": request_id},
    )


@router.get("/health")
async def ords_health(
    request: Request,
    actor: str = Depends(_require_gateway_client),
    client: ORDSClient = Depends(_get_ords_client),
) -> dict[str, Any]:
    request_id = str(uuid.uuid4())
    store = _audit(request)
    _audit_before(
        store,
        "ords.health.requested",
        actor,
        request_id,
        {"upstream": "oracle_apex_ords", "raw_data_logged": False},
    )
    try:
        departments = await client.list_departments()
        digest = hashlib.sha256(
            json.dumps(departments, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        _audit_after(
            store,
            "ords.health.succeeded",
            "gateway",
            request_id,
            {"department_count": len(departments), "response_sha256": digest},
        )
        return {
            "connected": True,
            "provider": "oracle_apex_ords",
            "authenticated": True,
            "department_count": len(departments),
            "request_id": request_id,
        }
    except HTTPException:
        raise
    except Exception as exc:
        try:
            _audit_after(
                store,
                "ords.health.failed",
                "gateway",
                request_id,
                {"error_type": type(exc).__name__},
            )
        except HTTPException:
            raise
        raise _map_ords_error(exc, request_id) from exc


@router.get("/departments")
async def ords_departments(
    request: Request,
    actor: str = Depends(_require_gateway_client),
    client: ORDSClient = Depends(_get_ords_client),
) -> dict[str, Any]:
    request_id = str(uuid.uuid4())
    store = _audit(request)
    _audit_before(
        store,
        "ords.departments.requested",
        actor,
        request_id,
        {"operation": "list_departments", "raw_data_logged": False},
    )
    try:
        departments = await client.list_departments()
        digest = hashlib.sha256(
            json.dumps(departments, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        _audit_after(
            store,
            "ords.departments.succeeded",
            "gateway",
            request_id,
            {"department_count": len(departments), "response_sha256": digest},
        )
        return {
            "request_id": request_id,
            "source": "oracle_apex_ords",
            "count": len(departments),
            "items": departments,
        }
    except HTTPException:
        raise
    except Exception as exc:
        try:
            _audit_after(
                store,
                "ords.departments.failed",
                "gateway",
                request_id,
                {"error_type": type(exc).__name__},
            )
        except HTTPException:
            raise
        raise _map_ords_error(exc, request_id) from exc


@router.post("/department-summary")
async def ords_department_summary(
    payload: DepartmentSummaryRequest,
    request: Request,
    actor: str = Depends(_require_gateway_client),
    client: ORDSClient = Depends(_get_ords_client),
) -> dict[str, Any]:
    request_id = str(uuid.uuid4())
    department_code = payload.department_code
    store = _audit(request)
    _audit_before(
        store,
        "ords.department_summary.requested",
        actor,
        request_id,
        {
            "operation": "department_summary",
            "parameters": {"department_code": department_code},
            "raw_data_logged": False,
        },
    )
    try:
        result = await client.department_summary(department_code, gateway_request_id=request_id)
        digest = hashlib.sha256(
            json.dumps(result, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        _audit_after(
            store,
            "ords.department_summary.succeeded",
            "gateway",
            request_id,
            {
                "operation": "department_summary",
                "department_code": department_code,
                "response_sha256": digest,
            },
        )
        return {"request_id": request_id, "result": result}
    except HTTPException:
        raise
    except Exception as exc:
        try:
            _audit_after(
                store,
                "ords.department_summary.failed",
                "gateway",
                request_id,
                {
                    "operation": "department_summary",
                    "department_code": department_code,
                    "error_type": type(exc).__name__,
                },
            )
        except HTTPException:
            raise
        raise _map_ords_error(exc, request_id) from exc


@router.get("/tools")
async def ords_tools(_: str = Depends(_require_gateway_client)) -> dict[str, Any]:
    """Static allowlist metadata for the later Gemma tool-calling stage."""
    return {
        "tools": [
            {
                "name": "list_departments",
                "description": "List synthetic department summaries from the approved Oracle APEX REST API.",
                "method": "GET",
                "gateway_path": "/v1/oracle/departments",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "department_summary",
                "description": "Read the name, headcount and monthly budget for one synthetic department.",
                "method": "POST",
                "gateway_path": "/v1/oracle/department-summary",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "department_code": {
                            "type": "string",
                            "enum": ["IT", "HR", "FIN", "OPS"],
                        }
                    },
                    "required": ["department_code"],
                    "additionalProperties": False,
                },
            },
        ]
    }
