from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/oracle", tags=["Oracle tools"])

# Only simple, unquoted Oracle identifiers are accepted from environment config.
# The model/user never supplies a package name or SQL statement.
_PACKAGE_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_$#]*(?:\.[A-Za-z][A-Za-z0-9_$#]*)?$"
)
_DEPARTMENT_CODE_PATTERN = r"^[A-Za-z0-9_-]{2,12}$"


@dataclass(frozen=True)
class OracleSettings:
    enabled: bool
    user: str
    password: str
    dsn: str
    package_name: str

    @classmethod
    def from_env(cls) -> "OracleSettings":
        enabled = os.getenv("ORACLE_ENABLED", "false").strip().lower() in {
            "1", "true", "yes", "on"
        }
        user = os.getenv("ORACLE_USER", "").strip()
        password = os.getenv("ORACLE_PASSWORD", "")
        dsn = os.getenv("ORACLE_DSN", "").strip()
        package_name = os.getenv(
            "ORACLE_PACKAGE_NAME", "AI_DEMO_OWNER.AI_GATEWAY_API"
        ).strip().upper()

        if not _PACKAGE_PATTERN.fullmatch(package_name):
            raise RuntimeError(
                "ORACLE_PACKAGE_NAME must be a simple package name, optionally schema-qualified"
            )

        return cls(
            enabled=enabled,
            user=user,
            password=password,
            dsn=dsn,
            package_name=package_name,
        )

    def validate_enabled(self) -> None:
        if not self.enabled:
            raise HTTPException(
                status_code=503,
                detail={"code": "oracle_integration_disabled"},
            )
        missing = [
            key
            for key, value in (
                ("ORACLE_USER", self.user),
                ("ORACLE_PASSWORD", self.password),
                ("ORACLE_DSN", self.dsn),
            )
            if not value
        ]
        if missing:
            raise HTTPException(
                status_code=503,
                detail={"code": "oracle_configuration_incomplete", "missing": missing},
            )


class OracleToolRequest(BaseModel):
    """Strict request schema: no arbitrary SQL, table, schema, or package fields."""

    model_config = ConfigDict(extra="forbid")
    operation: Literal["department_summary"]
    department_code: str = Field(
        min_length=2,
        max_length=12,
        pattern=_DEPARTMENT_CODE_PATTERN,
        description="Synthetic demo department code, e.g. IT or HR.",
    )


async def require_client(
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> str:
    settings = request.app.state.settings
    supplied = x_api_key
    if not supplied and authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not supplied or not hmac.compare_digest(supplied, settings.client_api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing client API key")
    return "api-client"


def _execute_department_summary(
    oracle_settings: OracleSettings, department_code: str
) -> tuple[dict, str]:
    """Execute one fixed, definer-rights PL/SQL procedure using bound arguments."""
    try:
        import oracledb
    except ImportError as exc:  # pragma: no cover - depends on local optional install
        raise RuntimeError(
            "Oracle driver is not installed. Run: pip install 'oracledb>=2.4,<3'"
        ) from exc

    with oracledb.connect(
        user=oracle_settings.user,
        password=oracle_settings.password,
        dsn=oracle_settings.dsn,
    ) as connection:
        with connection.cursor() as cursor:
            # This transaction is read-only. The package itself also contains only SELECT.
            cursor.execute("SET TRANSACTION READ ONLY")

            department_name = cursor.var(oracledb.DB_TYPE_VARCHAR, size=100)
            headcount = cursor.var(oracledb.DB_TYPE_NUMBER)
            monthly_budget = cursor.var(oracledb.DB_TYPE_NUMBER)

            # The package name is fixed in server configuration. The caller controls only
            # the validated department code, passed as a bind argument to the procedure.
            cursor.callproc(
                f"{oracle_settings.package_name}.GET_DEPARTMENT_SUMMARY",
                [department_code.upper(), department_name, headcount, monthly_budget],
            )

            budget_value = monthly_budget.getvalue()
            if isinstance(budget_value, Decimal):
                budget_value = float(budget_value)
            elif budget_value is not None:
                budget_value = float(budget_value)

            result = {
                "department_code": department_code.upper(),
                "department_name": department_name.getvalue(),
                "headcount": int(headcount.getvalue()),
                "monthly_budget": budget_value,
                "currency": "USD",
                "data_source": "synthetic_demo_data",
            }
            return result, connection.version


def _execute_health_check(oracle_settings: OracleSettings) -> dict:
    try:
        import oracledb
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Oracle driver is not installed. Run: pip install 'oracledb>=2.4,<3'"
        ) from exc

    with oracledb.connect(
        user=oracle_settings.user,
        password=oracle_settings.password,
        dsn=oracle_settings.dsn,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")
            cursor.execute(
                "SELECT SYS_CONTEXT('USERENV', 'SESSION_USER'), "
                "SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL"
            )
            session_user, current_schema = cursor.fetchone()
            return {
                "connected": True,
                "database_version": connection.version,
                "session_user": session_user,
                "current_schema": current_schema,
                "driver_mode": "thin" if connection.thin else "thick",
            }


def _audit_store(request: Request):
    return request.app.state.audit_store


def _oracle_settings() -> OracleSettings:
    # python-dotenv is loaded by the application's existing Settings.from_env().
    return OracleSettings.from_env()


@router.get("/tools")
async def list_oracle_tools(_: str = Depends(require_client)) -> dict:
    """Return the static allowlist; no database connection is made."""
    return {
        "tools": [
            {
                "name": "department_summary",
                "description": (
                    "Read the synthetic name, headcount and monthly budget for one "
                    "approved demo department."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "department_code": {
                            "type": "string",
                            "pattern": _DEPARTMENT_CODE_PATTERN,
                            "examples": ["IT", "HR", "FIN", "OPS"],
                        }
                    },
                    "required": ["department_code"],
                    "additionalProperties": False,
                },
            }
        ]
    }


@router.get("/health")
async def oracle_health(
    request: Request,
    _: str = Depends(require_client),
) -> dict:
    oracle_settings = _oracle_settings()
    oracle_settings.validate_enabled()
    request_id = str(uuid.uuid4())
    store = _audit_store(request)

    try:
        store.append(
            "oracle.health.requested",
            "api-client",
            request_id,
            {"database_contacted": False},
        )
    except Exception as exc:
        logger.exception("Could not write Oracle health audit event")
        raise HTTPException(status_code=503, detail="Audit store unavailable") from exc

    try:
        result = await asyncio.to_thread(_execute_health_check, oracle_settings)
        store.append(
            "oracle.health.succeeded",
            "gateway",
            request_id,
            {
                "database_version": result["database_version"],
                "session_user": result["session_user"],
                "driver_mode": result["driver_mode"],
            },
        )
        return {"request_id": request_id, **result}
    except Exception as exc:
        logger.exception("Oracle health check failed: request_id=%s", request_id)
        try:
            store.append(
                "oracle.health.failed",
                "gateway",
                request_id,
                {"error_type": type(exc).__name__, "database_contacted": True},
            )
        except Exception:
            logger.exception("Could not audit Oracle health failure")
        raise HTTPException(
            status_code=502,
            detail={"code": "oracle_connection_failed", "request_id": request_id},
        ) from exc


@router.post("/execute")
async def execute_oracle_tool(
    payload: OracleToolRequest,
    request: Request,
    actor: str = Depends(require_client),
) -> dict:
    oracle_settings = _oracle_settings()
    oracle_settings.validate_enabled()

    request_id = str(uuid.uuid4())
    department_code = payload.department_code.upper()
    store = _audit_store(request)

    # Fail closed: establish the audit record before opening an Oracle connection.
    try:
        store.append(
            "oracle.tool.requested",
            actor,
            request_id,
            {
                "operation": payload.operation,
                "parameters": {"department_code": department_code},
                "database_contacted": False,
            },
        )
    except Exception as exc:
        logger.exception("Could not write Oracle tool request audit event")
        raise HTTPException(status_code=503, detail="Audit store unavailable; Oracle not contacted") from exc

    try:
        result, database_version = await asyncio.to_thread(
            _execute_department_summary,
            oracle_settings,
            department_code,
        )
        result_json = json.dumps(result, sort_keys=True, separators=(",", ":"))
        result_hash = hashlib.sha256(result_json.encode("utf-8")).hexdigest()

        # Do not place returned business data in the audit log. Record only its digest.
        store.append(
            "oracle.tool.succeeded",
            "gateway",
            request_id,
            {
                "operation": payload.operation,
                "database_version": database_version,
                "result_sha256": result_hash,
                "database_contacted": True,
            },
        )

        return {
            "request_id": request_id,
            "operation": payload.operation,
            "result": result,
        }

    except Exception as exc:
        logger.exception(
            "Oracle tool failed: request_id=%s operation=%s",
            request_id,
            payload.operation,
        )
        try:
            store.append(
                "oracle.tool.failed",
                "gateway",
                request_id,
                {
                    "operation": payload.operation,
                    "error_type": type(exc).__name__,
                    "oracle_call_attempted": True,
                },
            )
        except Exception:
            logger.exception("Could not audit Oracle tool failure")
        raise HTTPException(
            status_code=502,
            detail={"code": "oracle_tool_failed", "request_id": request_id},
        ) from exc
