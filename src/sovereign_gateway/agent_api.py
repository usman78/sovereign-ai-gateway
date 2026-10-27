from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .audit import prompt_fingerprint
from .ords_api import (
    ORDSAPIError,
    ORDSClient,
    ORDSOAuthError,
    DepartmentSummaryRequest,
    _get_ords_client,
    _require_gateway_client,
)
from .redaction import redact_messages

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/agent", tags=["Gemma Oracle Agent"])

_ALLOWED_DEPARTMENT_CODES = {"IT", "HR", "FIN", "OPS"}

_SYSTEM_PROMPT = """You are a read-only assistant for a synthetic company department database.
You have access only to the tools explicitly provided in this request.
For questions asking for department details, headcount, monthly budget, or a list of departments,
use the matching tool. Never invent database facts. Never generate SQL. Never request credentials,
URLs, table names, schema names, package names, or arbitrary code. If a requested department is
unclear, ask the user to specify IT, HR, FIN, or OPS. After receiving a tool result, answer using
only the returned data. Make it clear that the information came from the Oracle demo database.
"""

_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_departments",
            "description": "List all available synthetic departments, headcounts, monthly budgets, and currencies from the approved Oracle demo database.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "department_summary",
            "description": "Retrieve the name, employee headcount, monthly budget, and currency for one department. Use when the user asks about a specific department.",
            "parameters": {
                "type": "object",
                "properties": {
                    "department_code": {
                        "type": "string",
                        "enum": ["IT", "HR", "FIN", "OPS"],
                        "description": "One of IT, HR, FIN, or OPS.",
                    }
                },
                "required": ["department_code"],
                "additionalProperties": False,
            },
        },
    },
]


class AgentChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=4000)


def _audit_store(request: Request) -> Any:
    store = getattr(request.app.state, "audit_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail={"code": "audit_store_unavailable"})
    return store


def _ollama_config(request: Request) -> tuple[str, str, float, str]:
    settings = request.app.state.settings
    base_url = str(getattr(settings, "ollama_base_url", None) or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).strip().rstrip("/")
    model = str(getattr(settings, "ollama_model", None) or os.getenv("OLLAMA_MODEL", "gemma4:e4b")).strip()
    try:
        timeout_seconds = float(os.getenv("OLLAMA_AGENT_TIMEOUT_SECONDS", "300"))
    except ValueError as exc:
        raise HTTPException(status_code=500, detail={"code": "invalid_ollama_agent_timeout"}) from exc
    if timeout_seconds < 30 or timeout_seconds > 900:
        raise HTTPException(status_code=500, detail={"code": "ollama_agent_timeout_out_of_range"})
    keep_alive = os.getenv("OLLAMA_KEEP_ALIVE", "15m").strip() or "15m"
    parsed = urlsplit(base_url)
    local_http = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    secure_remote = parsed.scheme == "https" and bool(parsed.hostname)
    if (
        not (local_http or secure_remote)
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise HTTPException(status_code=500, detail={"code": "invalid_ollama_base_url"})
    return base_url, model, timeout_seconds, keep_alive


def _parse_tool_arguments(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail={"code": "invalid_tool_arguments"}) from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail={"code": "invalid_tool_arguments"})
    return value


def _validate_and_normalize_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "list_departments":
        if arguments:
            raise HTTPException(status_code=422, detail={"code": "unexpected_tool_arguments"})
        return {}

    if name == "department_summary":
        try:
            parsed = DepartmentSummaryRequest.model_validate(arguments)
        except Exception as exc:
            raise HTTPException(status_code=422, detail={"code": "invalid_department_tool_arguments"}) from exc
        if parsed.department_code not in _ALLOWED_DEPARTMENT_CODES:
            raise HTTPException(status_code=422, detail={"code": "unsupported_department_code"})
        return {"department_code": parsed.department_code}

    # Never execute a function name that is not explicitly allowlisted.
    raise HTTPException(status_code=403, detail={"code": "tool_not_allowed"})


def _append_audit(store: Any, event_type: str, actor: str, request_id: str, details: dict[str, Any]) -> None:
    try:
        store.append(event_type, actor, request_id, details)
    except Exception as exc:
        logger.exception("Agent audit write failed: event=%s", event_type)
        raise HTTPException(
            status_code=503,
            detail={"code": "audit_store_unavailable", "request_id": request_id},
        ) from exc


async def _ollama_chat(
    request: Request,
    *,
    messages: list[dict[str, Any]],
    include_tools: bool,
) -> dict[str, Any]:
    base_url, model, timeout_seconds, keep_alive = _ollama_config(request)
    timeout = httpx.Timeout(
        connect=5.0,
        read=timeout_seconds,
        write=30.0,
        pool=10.0,
    )
    transport = getattr(request.app.state, "ollama_transport", None)
    headers = {
        "Accept": "application/json",
        "User-Agent": "SovereignAIGateway/0.1",
    }
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": False,
        "keep_alive": keep_alive,
        "options": {"temperature": 0},
    }
    if include_tools:
        payload["tools"] = _TOOLS

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            headers=headers,
        ) as client:
            response = await client.post(f"{base_url}/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
    except httpx.TimeoutException as exc:
        logger.warning("Ollama agent request timed out: %s", type(exc).__name__)
        raise HTTPException(status_code=504, detail={"code": "ollama_agent_timeout"}) from exc
    except httpx.HTTPStatusError as exc:
        logger.error("Ollama agent returned HTTP %s", exc.response.status_code)
        raise HTTPException(status_code=502, detail={"code": "ollama_agent_http_error", "upstream_status": exc.response.status_code}) from exc
    except httpx.RequestError as exc:
        logger.exception("Ollama agent connection failed")
        raise HTTPException(status_code=502, detail={"code": "ollama_agent_connection_failed"}) from exc
    except ValueError as exc:
        logger.exception("Ollama agent returned invalid JSON")
        raise HTTPException(status_code=502, detail={"code": "ollama_agent_invalid_json"}) from exc

    if not isinstance(data, dict) or not isinstance(data.get("message"), dict):
        raise HTTPException(status_code=502, detail={"code": "ollama_agent_response_shape_invalid"})
    return data


@router.post("/chat")
async def agent_chat(
    payload: AgentChatRequest,
    request: Request,
    actor: str = Depends(_require_gateway_client),
    ords_client: ORDSClient = Depends(_get_ords_client),
) -> dict[str, Any]:
    """Ask Gemma 4; execute at most one explicitly allowlisted Oracle tool; return its grounded answer."""
    request_id = str(uuid.uuid4())
    store = _audit_store(request)
    runtime_config = getattr(request.app.state, "runtime_config", {}) or {}
    policy_mode = runtime_config.get("policy_mode", "redact")

    sanitized, findings = redact_messages([{"role": "user", "content": payload.message}])
    sanitized_prompt = sanitized[0]["content"]
    categories = {item.category: item.count for item in findings}
    settings = request.app.state.settings
    hmac_key = getattr(settings, "audit_hmac_key", None) or os.getenv("AUDIT_HMAC_KEY", "")
    if not hmac_key:
        raise HTTPException(status_code=503, detail={"code": "audit_hmac_key_missing"})
    prompt_hmac = prompt_fingerprint([{"role": "user", "content": payload.message}], hmac_key)

    if findings and policy_mode == "block":
        _append_audit(
            store,
            "agent.request.blocked",
            actor,
            request_id,
            {"sensitive_categories": categories, "prompt_hmac": prompt_hmac, "provider_contacted": False},
        )
        raise HTTPException(
            status_code=403,
            detail={"code": "sensitive_data_detected", "request_id": request_id, "categories": categories},
        )

    policy_action = "redacted" if findings else "forwarded"
    _append_audit(
        store,
        "agent.requested",
        actor,
        request_id,
        {
            "model_provider": "ollama",
            "model": getattr(settings, "ollama_model", None) or os.getenv("OLLAMA_MODEL", "gemma4:e4b"),
            "policy_action": policy_action,
            "sensitive_categories": categories,
            "prompt_hmac": prompt_hmac,
            "raw_prompt_logged": False,
        },
    )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": sanitized_prompt},
    ]

    started = time.perf_counter()
    first_response = await _ollama_chat(request, messages=messages, include_tools=True)
    assistant_message = first_response["message"]
    tool_calls = assistant_message.get("tool_calls") or []

    # No model-requested operation: do not expose ungrounded model-generated database facts.
    if not tool_calls:
        answer = (
            "I couldn't identify an approved Oracle database operation for that request. "
            "You can ask me to list departments or request a summary for IT, HR, FIN, or OPS."
        )
        _append_audit(
            store,
            "agent.completed_without_tool",
            "gateway",
            request_id,
            {"model": first_response.get("model"), "tool_executed": False, "elapsed_ms": int((time.perf_counter() - started) * 1000)},
        )
        return {
            "request_id": request_id,
            "model": first_response.get("model"),
            "answer": answer,
            "tool_execution": None,
            "data": None,
            "policy_action": policy_action,
            "source": None,
        }

    # Initial version deliberately permits only one DB operation per user turn.
    if not isinstance(tool_calls, list) or len(tool_calls) != 1:
        _append_audit(
            store,
            "agent.tool.rejected",
            "gateway",
            request_id,
            {"reason": "tool_call_limit_exceeded", "requested_count": len(tool_calls) if isinstance(tool_calls, list) else None},
        )
        raise HTTPException(status_code=422, detail={"code": "one_tool_call_per_request_limit"})

    call = tool_calls[0]
    function = call.get("function") if isinstance(call, dict) else None
    if not isinstance(function, dict):
        raise HTTPException(status_code=422, detail={"code": "invalid_tool_call_shape"})
    tool_name = function.get("name")
    if tool_name not in {"list_departments", "department_summary"}:
        _append_audit(
            store,
            "agent.tool.rejected",
            "gateway",
            request_id,
            {"requested_tool_name": str(tool_name)[:80], "reason": "tool_not_allowlisted"},
        )
        raise HTTPException(status_code=403, detail={"code": "tool_not_allowed"})

    try:
        arguments = _parse_tool_arguments(function.get("arguments", {}))
        normalized_arguments = _validate_and_normalize_tool(tool_name, arguments)
    except HTTPException as exc:
        _append_audit(
            store,
            "agent.tool.rejected",
            "gateway",
            request_id,
            {"tool_name": tool_name, "reason": str(exc.detail.get("code", "invalid_tool_arguments"))},
        )
        raise

    # Record the proposed operation before contacting ORDS. No model-supplied URL/SQL is accepted.
    _append_audit(
        store,
        "agent.tool.requested",
        actor,
        request_id,
        {"tool_name": tool_name, "arguments": normalized_arguments, "provider_contacted": False},
    )

    try:
        if tool_name == "list_departments":
            tool_result: Any = await ords_client.list_departments()
        else:
            tool_result = await ords_client.department_summary(normalized_arguments["department_code"], gateway_request_id=request_id)
    except (ORDSOAuthError, ORDSAPIError) as exc:
        _append_audit(
            store,
            "agent.tool.failed",
            "gateway",
            request_id,
            {"tool_name": tool_name, "error_type": type(exc).__name__},
        )
        if isinstance(exc, ORDSOAuthError):
            raise HTTPException(status_code=502, detail={"code": "ords_oauth_failed", "request_id": request_id}) from exc
        status = 504 if exc.status_code == 504 else (404 if exc.status_code == 404 else 502)
        raise HTTPException(status_code=status, detail={"code": exc.code, "request_id": request_id}) from exc
    except Exception as exc:
        logger.exception("Unexpected Oracle tool execution failure: tool=%s", tool_name)
        _append_audit(
            store,
            "agent.tool.failed",
            "gateway",
            request_id,
            {"tool_name": tool_name, "error_type": type(exc).__name__},
        )
        raise HTTPException(status_code=502, detail={"code": "oracle_tool_execution_failed", "request_id": request_id}) from exc

    result_json = json.dumps(tool_result, sort_keys=True, default=str, ensure_ascii=False)
    result_digest = hashlib.sha256(result_json.encode("utf-8")).hexdigest()
    _append_audit(
        store,
        "agent.tool.succeeded",
        "gateway",
        request_id,
        {"tool_name": tool_name, "result_sha256": result_digest, "provider_contacted": True},
    )

    # Return the tool result to Gemma in Ollama's documented conversation format.
    assistant_history: dict[str, Any] = {
        "role": "assistant",
        "content": assistant_message.get("content") or "",
        "tool_calls": tool_calls,
    }
    tool_history = {
        "role": "tool",
        "tool_name": tool_name,
        "content": result_json,
    }
    final_messages = [*messages, assistant_history, tool_history]

    final_response = await _ollama_chat(request, messages=final_messages, include_tools=False)
    final_message = final_response["message"]
    if final_message.get("tool_calls"):
        # No second execution round in this version; never execute chained requests implicitly.
        raise HTTPException(status_code=422, detail={"code": "additional_tool_call_not_allowed"})

    answer = (final_message.get("content") or "").strip()
    if not answer:
        answer = "The Oracle operation completed, but the model did not produce a final text response."

    _append_audit(
        store,
        "agent.completed",
        "gateway",
        request_id,
        {
            "tool_name": tool_name,
            "result_sha256": result_digest,
            "model": final_response.get("model"),
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
        },
    )

    return {
        "request_id": request_id,
        "model": final_response.get("model", first_response.get("model")),
        "answer": answer,
        "tool_execution": {"name": tool_name, "arguments": normalized_arguments},
        "data": tool_result,
        "policy_action": policy_action,
        "source": "oracle_apex_ords",
    }
