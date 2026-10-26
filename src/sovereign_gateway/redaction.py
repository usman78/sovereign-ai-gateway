from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    category: str
    count: int


# These are deliberately small demonstration detectors, not a complete DLP engine.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("api_key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")),
    ("cnic", re.compile(r"\b\d{5}-\d{7}-\d\b")),
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("password", re.compile(r"\b(password|passwd|pwd)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE)),
    ("phone", re.compile(r"(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{4}(?!\w)")),
]


def _password_replacer(match: re.Match[str]) -> str:
    return f"{match.group(1)}=<REDACTED:PASSWORD>"


def inspect_and_redact(value: str) -> tuple[str, list[Finding]]:
    """Return a sanitized string and category counts; matched values are never returned."""
    counts: Counter[str] = Counter()
    sanitized = value
    for category, pattern in _PATTERNS:
        if category == "password":
            def replace_password(match: re.Match[str]) -> str:
                counts[category] += 1
                return _password_replacer(match)
            sanitized = pattern.sub(replace_password, sanitized)
        else:
            def replace(match: re.Match[str], category_name: str = category) -> str:
                counts[category_name] += 1
                return f"<REDACTED:{category_name.upper()}>"
            sanitized = pattern.sub(replace, sanitized)
    return sanitized, [Finding(category=key, count=counts[key]) for key in sorted(counts)]


def redact_messages(messages: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[Finding]]:
    sanitized_messages: list[dict[str, str]] = []
    totals: Counter[str] = Counter()
    for message in messages:
        content, findings = inspect_and_redact(message["content"])
        sanitized_messages.append({"role": message["role"], "content": content})
        for finding in findings:
            totals[finding.category] += finding.count
    return sanitized_messages, [Finding(category=key, count=totals[key]) for key in sorted(totals)]
