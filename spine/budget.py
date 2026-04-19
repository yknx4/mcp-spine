"""
MCP Spine — Token Budget Tracker

Tracks daily token consumption across tool calls and optionally
blocks further calls once a configurable limit is reached.

Tokens are estimated from JSON-RPC message sizes using a simple
"characters / 4" heuristic — a reasonable approximation for
English tool arguments and responses.

Daily totals persist to the audit SQLite database so the budget
survives restarts within the same day. Totals roll over when the
local calendar date changes.

Thread-safe via an internal lock.
"""

from __future__ import annotations

import datetime as _dt
import json
import sqlite3
import threading
from typing import Any


def estimate_tokens(payload: Any) -> int:
    """
    Rough token estimate: len(serialized_payload) // 4.

    Accepts strings, dicts, lists, or anything JSON-serializable.
    """
    if payload is None:
        return 0
    if isinstance(payload, (bytes, bytearray)):
        return max(1, len(payload) // 4)
    if isinstance(payload, str):
        return max(1, len(payload) // 4) if payload else 0
    try:
        blob = json.dumps(payload, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        blob = str(payload)
    return max(1, len(blob) // 4) if blob else 0


class TokenBudget:
    """
    Tracks token usage against a daily limit.

    Usage:
        budget = TokenBudget(daily_limit=500_000, warn_at=0.8,
                             action="warn", db_path="spine_audit.db")
        budget.record(tokens)
        if budget.is_over_budget():
            ...

    Core methods:
        record(tokens): add to today's running total
        remaining(): tokens left today (max 0)
        usage_pct(): 0.0..1.0 (clamped at 1.0 for over-budget)
        is_over_budget(): True if usage >= limit
        is_warn_threshold(): True if usage >= warn_at * limit

    Persistence:
        A ``token_usage`` table is created in the audit DB with one
        row per day: (date TEXT PRIMARY KEY, tokens_used INTEGER,
        tokens_limit INTEGER). ``record()`` upserts this row.

    Midnight reset:
        The running counter is keyed on the local calendar date.
        The first ``record()`` call on a new day resets the counter
        (persisting the new day's row).

    A ``daily_limit`` of 0 disables the budget — ``record()`` still
    accumulates (for analytics), but ``is_over_budget`` and
    ``is_warn_threshold`` always return False.
    """

    def __init__(
        self,
        daily_limit: int = 0,
        warn_at: float = 0.8,
        action: str = "warn",
        db_path: str | None = None,
        clock: Any = None,
    ):
        if daily_limit < 0:
            raise ValueError("daily_limit must be >= 0")
        if not 0.0 <= warn_at <= 1.0:
            raise ValueError("warn_at must be between 0.0 and 1.0")
        if action not in ("warn", "block"):
            raise ValueError("action must be 'warn' or 'block'")

        self.daily_limit = int(daily_limit)
        self.warn_at = float(warn_at)
        self.action = action
        self._db_path = db_path
        self._clock = clock or _dt.date.today  # swappable for tests

        self._lock = threading.Lock()
        self._current_date: str = self._today()
        self._used: int = 0
        self._warn_fired: bool = False

        self._db: sqlite3.Connection | None = None
        if db_path:
            self._init_db()
            self._load_today()

    # ────────────────────────────────────────────────
    # Persistence
    # ────────────────────────────────────────────────

    def _init_db(self) -> None:
        """Create the token_usage table if it doesn't exist."""
        self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS token_usage (
                date         TEXT PRIMARY KEY,
                tokens_used  INTEGER NOT NULL DEFAULT 0,
                tokens_limit INTEGER NOT NULL DEFAULT 0,
                updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self._db.commit()

    def _load_today(self) -> None:
        """Restore today's running total from the audit DB, if any."""
        if not self._db:
            return
        row = self._db.execute(
            "SELECT tokens_used FROM token_usage WHERE date = ?",
            (self._current_date,),
        ).fetchone()
        if row is not None:
            self._used = int(row[0])

    def _persist(self) -> None:
        """Upsert today's running total. Caller must hold the lock."""
        if not self._db:
            return
        try:
            self._db.execute(
                """
                INSERT INTO token_usage (date, tokens_used, tokens_limit)
                VALUES (?, ?, ?)
                ON CONFLICT(date) DO UPDATE SET
                    tokens_used  = excluded.tokens_used,
                    tokens_limit = excluded.tokens_limit,
                    updated_at   = CURRENT_TIMESTAMP
                """,
                (self._current_date, self._used, self.daily_limit),
            )
            self._db.commit()
        except sqlite3.Error:
            # Persistence failures are non-fatal; the in-memory counter
            # keeps enforcing the budget for the current process.
            pass

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                try:
                    self._db.close()
                except sqlite3.Error:
                    pass
                self._db = None

    # ────────────────────────────────────────────────
    # Date handling
    # ────────────────────────────────────────────────

    def _today(self) -> str:
        return self._clock().isoformat()

    def _roll_over_if_needed(self) -> None:
        """Reset the counter if the local date has changed."""
        today = self._today()
        if today != self._current_date:
            self._current_date = today
            self._used = 0
            self._warn_fired = False
            # Load any preexisting row for the new day (or create one).
            if self._db:
                row = self._db.execute(
                    "SELECT tokens_used FROM token_usage WHERE date = ?",
                    (today,),
                ).fetchone()
                self._used = int(row[0]) if row else 0

    # ────────────────────────────────────────────────
    # Public API
    # ────────────────────────────────────────────────

    def record(self, tokens: int) -> int:
        """
        Add ``tokens`` to today's running total.

        Returns the new running total. Negative inputs are clamped to 0.
        """
        if tokens < 0:
            tokens = 0
        with self._lock:
            self._roll_over_if_needed()
            self._used += int(tokens)
            self._persist()
            return self._used

    def used(self) -> int:
        """Tokens consumed today so far."""
        with self._lock:
            self._roll_over_if_needed()
            return self._used

    def remaining(self) -> int:
        """Tokens left in today's budget. 0 if no limit is set."""
        with self._lock:
            self._roll_over_if_needed()
            if self.daily_limit <= 0:
                return 0
            return max(0, self.daily_limit - self._used)

    def usage_pct(self) -> float:
        """Fraction of the daily limit consumed (0.0 if no limit)."""
        with self._lock:
            self._roll_over_if_needed()
            if self.daily_limit <= 0:
                return 0.0
            return min(1.0, self._used / self.daily_limit)

    def is_over_budget(self) -> bool:
        """True if today's usage has reached the daily limit."""
        with self._lock:
            self._roll_over_if_needed()
            if self.daily_limit <= 0:
                return False
            return self._used >= self.daily_limit

    def is_warn_threshold(self) -> bool:
        """True if today's usage has crossed ``warn_at * daily_limit``."""
        with self._lock:
            self._roll_over_if_needed()
            if self.daily_limit <= 0:
                return False
            return self._used >= int(self.daily_limit * self.warn_at)

    def should_fire_warning(self) -> bool:
        """
        True once per day when the warn threshold is first crossed.

        Subsequent calls return False until a new day begins.
        Use this in the proxy to inject the warning banner only once
        per response-chain (so we don't spam every tool response).
        """
        with self._lock:
            self._roll_over_if_needed()
            if self.daily_limit <= 0:
                return False
            at_threshold = self._used >= int(self.daily_limit * self.warn_at)
            if at_threshold and not self._warn_fired:
                self._warn_fired = True
                return True
            return False

    def stats(self) -> dict[str, Any]:
        """Snapshot of current budget state."""
        with self._lock:
            self._roll_over_if_needed()
            used = self._used
            limit = self.daily_limit
            pct = (used / limit) if limit > 0 else 0.0
            remaining = max(0, limit - used) if limit > 0 else 0
            return {
                "date": self._current_date,
                "daily_limit": limit,
                "tokens_used": used,
                "tokens_remaining": remaining,
                "usage_pct": round(min(1.0, pct), 4),
                "warn_at": self.warn_at,
                "action": self.action,
                "over_budget": (limit > 0 and used >= limit),
                "warn_threshold_reached": (
                    limit > 0 and used >= int(limit * self.warn_at)
                ),
            }
