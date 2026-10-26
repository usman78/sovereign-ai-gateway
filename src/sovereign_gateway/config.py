from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
except ImportError:  # .env loading is optional when environment variables are set directly.
    load_dotenv = None


@dataclass(frozen=True)
class Settings:
    client_api_key: str
    admin_api_key: str
    audit_hmac_key: str
    database_path: str
    initial_provider: str
    initial_model: str
    initial_policy_mode: str
    initial_capture_mode: str
    ollama_base_url: str
    ollama_model: str

    @classmethod
    def from_env(cls) -> "Settings":
        if load_dotenv is not None:
            load_dotenv()
        return cls(
            client_api_key=os.getenv("CLIENT_API_KEY", "local-client-key-change-this"),
            admin_api_key=os.getenv("ADMIN_API_KEY", "local-admin-key-change-this"),
            audit_hmac_key=os.getenv("AUDIT_HMAC_KEY", "development-only-change-this"),
            database_path=os.getenv("DATABASE_PATH", "./data/audit.sqlite3"),
            initial_provider=os.getenv("GATEWAY_PROVIDER", "mock").lower(),
            initial_model=os.getenv("GATEWAY_MODEL", "local-demo"),
            initial_policy_mode=os.getenv("POLICY_MODE", "redact").lower(),
            initial_capture_mode=os.getenv("AUDIT_CAPTURE", "metadata").lower(),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/"),
            ollama_model=os.getenv("OLLAMA_MODEL", "llama3.2"),
        )

    def initial_runtime_config(self) -> dict[str, str]:
        provider = self.initial_provider if self.initial_provider in {"mock", "ollama"} else "mock"
        policy = self.initial_policy_mode if self.initial_policy_mode in {"redact", "block"} else "redact"
        capture = self.initial_capture_mode if self.initial_capture_mode in {"metadata", "redacted"} else "metadata"
        model = self.ollama_model if provider == "ollama" else self.initial_model
        return {"provider": provider, "model": model, "policy_mode": policy, "capture_mode": capture}
