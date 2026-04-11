"""
MCP Spine — Secret Detection & Scrubbing

Regex-based detection and redaction of credentials, tokens,
and other sensitive values before they reach logs or responses.
"""

from __future__ import annotations

import re

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Token", re.compile(r"(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("Generic API Key", re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*\S+")),
    ("Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("Private Key Block", re.compile(r"-----BEGIN\s+(RSA |EC |DSA )?PRIVATE KEY-----")),
    ("Base64 Long Secret", re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9])")),
    ("Connection String", re.compile(r"(?i)(postgres|mysql|mongodb|redis)://\S+:\S+@")),
]

REDACTED = "[REDACTED]"


def scrub_secrets(text: str) -> str:
    """Replace detected secrets with [REDACTED]. Returns cleaned text."""
    for _name, pattern in _SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def contains_secret(text: str) -> bool:
    """Quick check: does this string contain a likely secret?"""
    return any(pattern.search(text) for _, pattern in _SECRET_PATTERNS)
