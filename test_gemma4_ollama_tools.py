from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from typing import Any

import httpx

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma4:e4b")

TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_departments",
            "description": "List the available synthetic company departments from the approved Oracle database tool.",
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
            "description": "Retrieve the department name, employee headcount and monthly budget for exactly one department. Use this when the user asks about a specific department.",
            "parameters": {
                "type": "object",
                "properties": {
                    "department_code": {
                        "type": "string",
                        "enum": ["IT", "HR", "FIN", "OPS"],
                        "description": "One of the supported department codes: IT, HR, FIN or OPS.",
                    }
                },
                "required": ["department_code"],
                "additionalProperties": False,
            },
        },
    },
]

SYSTEM_PROMPT = """You are an assistant connected to a read-only Oracle demo database through approved tools.
You cannot access the database directly and must never invent database values.
For questions about a particular department's headcount or budget, call department_summary.
For requests to list all departments, call list_departments.
Only use the tools and department codes supplied. Do not generate SQL.
After receiving tool results, answer in concise natural language."""


async def main() -> int:
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "How many employees are in the IT department, and what is its "
                    "monthly budget? Use the approved department tool."
                ),
            },
        ],
        "tools": TOOLS,
        "stream": False,
        "options": {"temperature": 0},
    }

    timeout = httpx.Timeout(connect=5.0, read=180.0, write=30.0, pool=10.0)
    start = time.perf_counter()

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            trust_env=False,
            follow_redirects=False,
            headers={"Accept": "application/json", "User-Agent": "SovereignAIGateway/0.1"},
        ) as client:
            response = await client.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload)
            elapsed = time.perf_counter() - start
            print(f"HTTP status: {response.status_code}")
            print(f"Elapsed: {elapsed:.2f} seconds")
            response.raise_for_status()
            data = response.json()
    except httpx.TimeoutException as exc:
        print(f"TIMEOUT: {type(exc).__name__}")
        return 2
    except httpx.HTTPStatusError as exc:
        print(f"OLLAMA HTTP ERROR: {exc.response.status_code}")
        print(exc.response.text[:1000])
        return 3
    except (httpx.RequestError, ValueError) as exc:
        print(f"REQUEST/RESPONSE ERROR: {type(exc).__name__}: {exc}")
        return 4

    message = data.get("message") or {}
    tool_calls = message.get("tool_calls") or []
    print("Model:", data.get("model", OLLAMA_MODEL))
    print("Message role:", message.get("role"))
    print("Assistant text:", (message.get("content") or "").strip() or "<empty>")

    if not tool_calls:
        print("\nRESULT: NO_NATIVE_TOOL_CALL_RETURNED")
        print("The model did not return message.tool_calls for the supplied tool schema.")
        print("Do not enable automatic database tool execution yet.")
        return 5

    print("\nRESULT: NATIVE_TOOL_CALLS_RETURNED")
    for index, call in enumerate(tool_calls, start=1):
        function = call.get("function") or {}
        name = function.get("name")
        arguments = function.get("arguments", {})
        print(f"Tool call {index}: {name}")
        print("Arguments:", json.dumps(arguments, ensure_ascii=False, sort_keys=True))
        if name not in {"list_departments", "department_summary"}:
            print("WARNING: Model requested a tool outside the allowlist.")
        if name == "department_summary" and arguments.get("department_code") not in {"IT", "HR", "FIN", "OPS"}:
            print("WARNING: Department code is outside the supported enum.")

    print("\nThis test only checks model tool selection. It does NOT call Oracle or execute any tool.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
