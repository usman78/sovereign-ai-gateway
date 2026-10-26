from __future__ import annotations
import logging
import hashlib
import hmac
import time
# from .oracle_api import router as oracle_router
from .ords_api import router as ords_router
from .agent_api import router as agent_router
import uuid
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditStore, prompt_fingerprint
from .config import Settings
from .providers import ProviderError, complete
from .redaction import redact_messages

logger = logging.getLogger(__name__)

class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["system", "developer", "user", "assistant"]
    content: str = Field(min_length=1, max_length=12000)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str | None = None
    messages: list[ChatMessage] = Field(min_length=1, max_length=32)
    stream: bool = False


class RuntimeConfigPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["mock", "ollama"] | None = None
    model: str | None = Field(default=None, min_length=1, max_length=100)
    policy_mode: Literal["redact", "block"] | None = None
    capture_mode: Literal["metadata", "redacted"] | None = None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    store = AuditStore(settings.database_path)
    runtime_config = store.load_config()
    if runtime_config is None:
        runtime_config = settings.initial_runtime_config()
        store.save_config(runtime_config)
        store.append("config.initialized", "system", None, {"after": runtime_config})
    else:
        integrity = store.verify()
        if not integrity["valid"]:
            raise RuntimeError(f"Audit chain verification failed at event {integrity['first_invalid_event_id']}")
        latest_snapshot = store.latest_config_snapshot()
        if latest_snapshot is not None and latest_snapshot != runtime_config:
            raise RuntimeError("Persisted runtime configuration does not match the latest audited configuration")

    app = FastAPI(
        title="Sovereign AI Gateway",
        version="0.1.0",
        description="Local-first proof of concept for prompt controls and tamper-evident AI audit events.",
    )
    app.state.settings = settings
    app.state.audit_store = store
    app.state.runtime_config = runtime_config
    # app.include_router(oracle_router)
    app.include_router(ords_router)
    app.include_router(agent_router)
    
    async def require_client(
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> str:
        supplied = x_api_key
        if not supplied and authorization and authorization.lower().startswith("bearer "):
            supplied = authorization[7:].strip()
        if not supplied or not hmac.compare_digest(supplied, settings.client_api_key):
            raise HTTPException(status_code=401, detail="Invalid or missing client API key")
        return "api-client"

    async def require_admin(x_admin_key: str | None = Header(default=None)) -> str:
        if not x_admin_key or not hmac.compare_digest(x_admin_key, settings.admin_api_key):
            raise HTTPException(status_code=401, detail="Invalid or missing admin API key")
        return "administrator"

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat(payload: ChatRequest, actor: str = Depends(require_client)) -> dict:
        if payload.stream:
            raise HTTPException(status_code=400, detail="Streaming is not supported by this proof of concept")

        request_id = str(uuid.uuid4())
        config = dict(app.state.runtime_config)
        original_messages = [message.model_dump() for message in payload.messages]
        sanitized_messages, findings = redact_messages(original_messages)
        categories = {finding.category: finding.count for finding in findings}
        raw_fingerprint = prompt_fingerprint(original_messages, settings.audit_hmac_key)
        sanitized_fingerprint = prompt_fingerprint(sanitized_messages, settings.audit_hmac_key)
        has_findings = bool(findings)

        if has_findings and config["policy_mode"] == "block":
            details = {
                "provider": config["provider"],
                "model": config["model"],
                "message_count": len(original_messages),
                "sensitive_categories": categories,
                "policy_action": "blocked",
                "prompt_hmac": raw_fingerprint,
                "provider_contacted": False,
            }
            if config["capture_mode"] == "redacted":
                details["sanitized_messages"] = sanitized_messages
            try:
                store.append("chat.blocked", actor, request_id, details)
            except Exception as exc:
                raise HTTPException(status_code=503, detail="Audit store unavailable; request blocked") from exc
            raise HTTPException(
                status_code=403,
                detail={"code": "sensitive_data_detected", "request_id": request_id, "categories": categories},
            )

        details = {
            "provider": config["provider"],
            "model": config["model"],
            "message_count": len(original_messages),
            "sensitive_categories": categories,
            "policy_action": "redacted" if has_findings else "forwarded",
            "prompt_hmac": raw_fingerprint,
            "sanitized_prompt_hmac": sanitized_fingerprint,
            "provider_contact_expected": True,
        }
        if config["capture_mode"] == "redacted":
            # This stores sanitized content only; it can still contain confidential context.
            details["sanitized_messages"] = sanitized_messages
        try:
            store.append("chat.request", actor, request_id, details)
        except Exception as exc:
            # Fail closed: never contact a model if the audit event cannot be written.
            raise HTTPException(status_code=503, detail="Audit store unavailable; request not sent") from exc

        try:
            answer = await complete(
                provider=config["provider"],
                model=config["model"],
                messages=sanitized_messages,
                ollama_base_url=settings.ollama_base_url,
            )
        except ProviderError as exc:
                
            logger.exception(
                "LLM provider failed: request_id=%s provider=%s model=%s",
                request_id,
                config["provider"],
                config["model"]
            )
                
            try:
                store.append(
                    "chat.error", "gateway", request_id,
                    {"provider": config["provider"], "model": config["model"], "error_type": type(exc).__name__},
                )
            except Exception:
                pass
            raise HTTPException(status_code=502, detail={"code": "provider_error", "request_id": request_id}) from exc

        response_hash = hashlib.sha256(answer.encode("utf-8")).hexdigest()
        try:
            store.append(
                "chat.response", "gateway", request_id,
                {"provider": config["provider"], "model": config["model"], "response_sha256": response_hash},
            )
        except Exception as exc:
            # The model has already responded; report an audit failure rather than hiding it.
            raise HTTPException(status_code=503, detail={"code": "response_audit_failed", "request_id": request_id}) from exc

        return {
            "id": f"chatcmpl-{request_id}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": config["model"],
            "choices": [{"index": 0, "message": {"role": "assistant", "content": answer}, "finish_reason": "stop"}],
            "gateway": {"request_id": request_id, "policy_action": "redacted" if has_findings else "forwarded"},
        }

    @app.get("/admin/config")
    async def get_config(_: str = Depends(require_admin)) -> dict[str, str]:
        return dict(app.state.runtime_config)

    @app.patch("/admin/config")
    async def patch_config(patch: RuntimeConfigPatch, _: str = Depends(require_admin)) -> dict[str, str]:
        current = dict(app.state.runtime_config)
        updated = {key: value for key, value in patch.model_dump(exclude_none=True).items()}
        next_config = {**current, **updated}
        if "provider" in updated and "model" not in updated:
            next_config["model"] = (
                settings.ollama_model if next_config["provider"] == "ollama" else settings.initial_model
            )
        if next_config == current:
            return current
        try:
            store.append("config.changed", "administrator", None, {"before": current, "after": next_config})
            store.save_config(next_config)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Could not persist configuration change") from exc
        app.state.runtime_config = next_config
        return next_config

    @app.get("/admin/audit")
    async def get_audit(limit: int = Query(default=50, ge=1, le=200), _: str = Depends(require_admin)) -> dict:
        return {"events": store.list_events(limit=limit)}

    @app.get("/admin/audit/verify")
    async def verify_audit(_: str = Depends(require_admin)) -> dict:
        return store.verify()

    return app


app = create_app()
