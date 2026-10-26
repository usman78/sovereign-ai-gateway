from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AuditStore:
    """SQLite event store with a sequential SHA-256 hash chain.

    The chain is tamper-evident, not immutable: an administrator able to rewrite the
    entire database can also recompute it. Production deployments should anchor or
    sign periodic chain heads outside this database.
    """

    def __init__(self, database_path: str):
        self.database_path = database_path
        if database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    request_id TEXT,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS runtime_config (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    config_json TEXT NOT NULL
                )
            """)

    def load_config(self) -> dict[str, str] | None:
        with self._connect() as db:
            row = db.execute("SELECT config_json FROM runtime_config WHERE singleton_id = 1").fetchone()
        return json.loads(row["config_json"]) if row else None

    def save_config(self, config: dict[str, str]) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO runtime_config(singleton_id, config_json) VALUES(1, ?) "
                "ON CONFLICT(singleton_id) DO UPDATE SET config_json=excluded.config_json",
                (canonical_json(config),),
            )

    def latest_config_snapshot(self) -> dict[str, str] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT details_json FROM audit_events "
                "WHERE event_type IN ('config.initialized', 'config.changed') "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        details = json.loads(row["details_json"])
        return details.get("after")

    def append(self, event_type: str, actor: str, request_id: str | None, details: dict[str, Any]) -> dict[str, Any]:
        occurred_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        details_json = canonical_json(details)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
            previous_hash = previous["event_hash"] if previous else "0" * 64
            body = {
                "occurred_at": occurred_at,
                "event_type": event_type,
                "actor": actor,
                "request_id": request_id,
                "details_json": details_json,
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            cursor = db.execute(
                "INSERT INTO audit_events(occurred_at,event_type,actor,request_id,details_json,previous_hash,event_hash) "
                "VALUES(?,?,?,?,?,?,?)",
                (occurred_at, event_type, actor, request_id, details_json, previous_hash, event_hash),
            )
            event_id = cursor.lastrowid
        return {"id": event_id, **body, "event_hash": event_hash, "details": details}

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            result.append(item)
        return result

    def verify(self) -> dict[str, Any]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
        expected_previous = "0" * 64
        for row in rows:
            body = {
                "occurred_at": row["occurred_at"],
                "event_type": row["event_type"],
                "actor": row["actor"],
                "request_id": row["request_id"],
                "details_json": row["details_json"],
                "previous_hash": row["previous_hash"],
            }
            calculated = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            if row["previous_hash"] != expected_previous or not hmac.compare_digest(calculated, row["event_hash"]):
                return {"valid": False, "checked_events": row["id"] - 1, "first_invalid_event_id": row["id"]}
            expected_previous = row["event_hash"]
        return {"valid": True, "checked_events": len(rows), "first_invalid_event_id": None}


def prompt_fingerprint(messages: list[dict[str, str]], secret: str) -> str:
    payload = canonical_json(messages).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
