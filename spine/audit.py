"""
MCP Spine — Audit Logger

Structured logging to both stderr (human-readable) and SQLite (queryable).
All log entries are fingerprinted for tamper detection.
Secrets are automatically scrubbed before logging.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Generator

from rich.console import Console

from spine.security import audit_fingerprint, hash_content, scrub_secrets

_console = Console(stderr=True)


class LogLevel(Enum):
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3
    SECURITY = 4  # always logged, never suppressed


class EventType(Enum):
    # Lifecycle
    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    SERVER_CONNECT = "server_connect"
    SERVER_DISCONNECT = "server_disconnect"

    # Proxy operations
    TOOL_LIST = "tool_list"
    TOOL_CALL = "tool_call"
    TOOL_RESPONSE = "tool_response"
    TOOL_ROUTED = "tool_routed"
    TOOL_BLOCKED = "tool_blocked"

    # Security events
    RATE_LIMITED = "rate_limited"
    PATH_VIOLATION = "path_violation"
    SECRET_DETECTED = "secret_detected"
    VALIDATION_ERROR = "validation_error"
    POLICY_DENY = "policy_deny"

    # State Guard
    FILE_CHANGED = "file_changed"
    STATE_PIN = "state_pin"


@dataclass
class AuditEntry:
    timestamp: float
    event_type: EventType
    tool_name: str | None
    server_name: str | None
    details: dict[str, Any]
    fingerprint: str | None = None


class AuditLogger:
    """
    Dual-output logger: rich stderr + SQLite audit trail.

    All string values in details are scrubbed for secrets before storage.
    Each entry gets an HMAC fingerprint for tamper detection.
    Thread-safe: uses a lock for all database operations.
    """

    def __init__(
        self,
        db_path: str = "spine_audit.db",
        level: LogLevel = LogLevel.INFO,
        scrub: bool = True,
        console: Console | None = None,
    ):
        self._level = level
        self._scrub = scrub
        self._console = console or _console
        self._db_path = db_path
        self._db: sqlite3.Connection | None = None
        self._db_lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite audit database."""
        self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                tool_name TEXT,
                server_name TEXT,
                details TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_event_type
            ON audit_log(event_type)
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_log(timestamp)
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_tool
            ON audit_log(tool_name)
        """)
        self._db.commit()

    def _scrub_details(self, details: dict[str, Any]) -> dict[str, Any]:
        """Deep-scrub secrets from detail values."""
        if not self._scrub:
            return details
        cleaned = {}
        for k, v in details.items():
            if isinstance(v, str):
                cleaned[k] = scrub_secrets(v)
            elif isinstance(v, dict):
                cleaned[k] = self._scrub_details(v)
            elif isinstance(v, list):
                cleaned[k] = [
                    scrub_secrets(item) if isinstance(item, str) else item
                    for item in v
                ]
            else:
                cleaned[k] = v
        return cleaned

    def log(
        self,
        event_type: EventType,
        level: LogLevel = LogLevel.INFO,
        tool_name: str | None = None,
        server_name: str | None = None,
        **details: Any,
    ) -> None:
        """Log an event to both stderr and SQLite."""
        if level.value < self._level.value and level != LogLevel.SECURITY:
            return

        ts = time.time()
        clean_details = self._scrub_details(details)
        details_json = json.dumps(clean_details, default=str)

        # Generate tamper-evident fingerprint
        payload_hash = hash_content(details_json.encode())[:16]
        fp = audit_fingerprint(
            event_type.value,
            tool_name or "",
            ts,
            payload_hash,
        )

        # Stderr output (human-readable)
        style = self._style_for_level(level)
        prefix = f"[{event_type.value}]"
        tool_str = f" tool={tool_name}" if tool_name else ""
        server_str = f" server={server_name}" if server_name else ""
        msg = f"{prefix}{tool_str}{server_str}"

        # Add key details inline
        for k, v in clean_details.items():
            if isinstance(v, str) and len(v) < 100:
                msg += f" {k}={v}"

        self._console.print(f"[{style}]SPINE {msg}[/{style}]")

        # SQLite persistence (thread-safe)
        if self._db:
            with self._db_lock:
                try:
                    self._db.execute(
                        """INSERT INTO audit_log
                           (timestamp, event_type, tool_name, server_name, details, fingerprint)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (ts, event_type.value, tool_name, server_name, details_json, fp),
                    )
                    self._db.commit()
                except sqlite3.Error as e:
                    self._console.print(f"[red]SPINE audit DB error: {e}[/red]")

    def _style_for_level(self, level: LogLevel) -> str:
        return {
            LogLevel.DEBUG: "dim",
            LogLevel.INFO: "cyan",
            LogLevel.WARN: "yellow",
            LogLevel.ERROR: "red bold",
            LogLevel.SECURITY: "red bold reverse",
        }.get(level, "white")

    # Convenience methods
    def info(self, event_type: EventType, **kw: Any) -> None:
        self.log(event_type, LogLevel.INFO, **kw)

    def warn(self, event_type: EventType, **kw: Any) -> None:
        self.log(event_type, LogLevel.WARN, **kw)

    def error(self, event_type: EventType, **kw: Any) -> None:
        self.log(event_type, LogLevel.ERROR, **kw)

    def security(self, event_type: EventType, **kw: Any) -> None:
        self.log(event_type, LogLevel.SECURITY, **kw)

    def close(self) -> None:
        with self._db_lock:
            if self._db:
                self._db.close()
                self._db = None

    @contextmanager
    def timed(self, event_type: EventType, **kw: Any) -> Generator[dict, None, None]:
        """Context manager that logs duration on exit."""
        ctx: dict[str, Any] = {}
        start = time.monotonic()
        try:
            yield ctx
        finally:
            ctx["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
            self.info(event_type, **{**kw, **ctx})
