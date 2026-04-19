"""
Tests for MCP Spine Token Budget tracker.

Covers:
  - Recording and running totals
  - Daily reset at midnight (simulated via a swappable clock)
  - Warn threshold detection and one-shot firing
  - Block behavior (is_over_budget)
  - SQLite persistence (token_usage table)
  - The spine_budget meta-tool
"""

from __future__ import annotations

import datetime as _dt
import sqlite3

import pytest

from spine.budget import TokenBudget, estimate_tokens

# ───────────────────────────────────────────────
# Helpers
# ───────────────────────────────────────────────


class _FrozenClock:
    """A mutable ``date.today``-compatible callable for tests."""

    def __init__(self, date: _dt.date):
        self.date = date

    def __call__(self) -> _dt.date:
        return self.date

    def advance_days(self, n: int = 1) -> None:
        self.date = self.date + _dt.timedelta(days=n)


# ───────────────────────────────────────────────
# Token estimator
# ───────────────────────────────────────────────


class TestEstimateTokens:
    def test_empty_inputs_return_zero(self):
        assert estimate_tokens("") == 0
        assert estimate_tokens(None) == 0

    def test_string_is_chars_div_4(self):
        # 8 chars / 4 = 2, but we clamp to min 1 for non-empty strings
        assert estimate_tokens("a") == 1
        assert estimate_tokens("abcdefgh") == 2
        assert estimate_tokens("x" * 40) == 10

    def test_dict_serializes_to_json_and_counts(self):
        payload = {"hello": "world"}
        # compact json: {"hello":"world"} = 17 chars → 4 tokens
        assert estimate_tokens(payload) == 4

    def test_list_counted(self):
        assert estimate_tokens([1, 2, 3, 4, 5]) >= 1

    def test_bytes_counted(self):
        assert estimate_tokens(b"abcdefgh") == 2


# ───────────────────────────────────────────────
# Recording + basic math
# ───────────────────────────────────────────────


class TestRecording:
    def test_record_increases_used(self):
        b = TokenBudget(daily_limit=1000)
        assert b.used() == 0
        b.record(100)
        assert b.used() == 100
        b.record(250)
        assert b.used() == 350

    def test_negative_tokens_clamped_to_zero(self):
        b = TokenBudget(daily_limit=1000)
        b.record(-50)
        assert b.used() == 0

    def test_remaining_and_usage_pct(self):
        b = TokenBudget(daily_limit=1000)
        b.record(250)
        assert b.remaining() == 750
        assert b.usage_pct() == pytest.approx(0.25)

    def test_usage_pct_clamps_at_one(self):
        b = TokenBudget(daily_limit=100)
        b.record(500)
        assert b.usage_pct() == 1.0
        assert b.remaining() == 0

    def test_disabled_budget_records_but_never_blocks(self):
        b = TokenBudget(daily_limit=0)
        b.record(999_999)
        assert b.used() == 999_999
        assert b.is_over_budget() is False
        assert b.is_warn_threshold() is False
        assert b.usage_pct() == 0.0
        assert b.remaining() == 0


# ───────────────────────────────────────────────
# Warn threshold
# ───────────────────────────────────────────────


class TestWarnThreshold:
    def test_warn_threshold_not_reached(self):
        b = TokenBudget(daily_limit=1000, warn_at=0.8)
        b.record(500)
        assert b.is_warn_threshold() is False

    def test_warn_threshold_reached(self):
        b = TokenBudget(daily_limit=1000, warn_at=0.8)
        b.record(800)
        assert b.is_warn_threshold() is True

    def test_should_fire_warning_only_once_per_day(self):
        b = TokenBudget(daily_limit=1000, warn_at=0.8)
        b.record(799)
        assert b.should_fire_warning() is False  # below threshold

        b.record(10)  # now at 809, over 80%
        assert b.should_fire_warning() is True   # fires once
        assert b.should_fire_warning() is False  # no second shot

    def test_warn_fires_again_after_date_rollover(self):
        clock = _FrozenClock(_dt.date(2026, 4, 18))
        b = TokenBudget(daily_limit=1000, warn_at=0.8, clock=clock)
        b.record(850)
        assert b.should_fire_warning() is True
        assert b.should_fire_warning() is False

        clock.advance_days(1)
        # New day: counter resets, warn flag resets
        b.record(850)
        assert b.should_fire_warning() is True


# ───────────────────────────────────────────────
# Block / over-budget
# ───────────────────────────────────────────────


class TestBlockBehavior:
    def test_is_over_budget_false_under_limit(self):
        b = TokenBudget(daily_limit=1000, action="block")
        b.record(500)
        assert b.is_over_budget() is False

    def test_is_over_budget_true_at_limit(self):
        b = TokenBudget(daily_limit=1000, action="block")
        b.record(1000)
        assert b.is_over_budget() is True

    def test_is_over_budget_true_above_limit(self):
        b = TokenBudget(daily_limit=1000, action="block")
        b.record(1500)
        assert b.is_over_budget() is True

    def test_over_budget_ignored_when_limit_zero(self):
        b = TokenBudget(daily_limit=0, action="block")
        b.record(10_000)
        assert b.is_over_budget() is False


# ───────────────────────────────────────────────
# Daily reset
# ───────────────────────────────────────────────


class TestDailyReset:
    def test_counter_resets_on_new_day(self):
        clock = _FrozenClock(_dt.date(2026, 4, 18))
        b = TokenBudget(daily_limit=1000, clock=clock)
        b.record(600)
        assert b.used() == 600

        clock.advance_days(1)
        # Counter rolls over on the next interaction
        assert b.used() == 0
        assert b.remaining() == 1000

    def test_usage_pct_resets_on_new_day(self):
        clock = _FrozenClock(_dt.date(2026, 4, 18))
        b = TokenBudget(daily_limit=1000, clock=clock)
        b.record(900)
        assert b.usage_pct() == pytest.approx(0.9)

        clock.advance_days(1)
        assert b.usage_pct() == 0.0

    def test_recording_after_reset_starts_fresh(self):
        clock = _FrozenClock(_dt.date(2026, 4, 18))
        b = TokenBudget(daily_limit=1000, clock=clock)
        b.record(999)

        clock.advance_days(1)
        b.record(100)
        assert b.used() == 100
        assert b.remaining() == 900


# ───────────────────────────────────────────────
# Persistence
# ───────────────────────────────────────────────


class TestPersistence:
    def test_token_usage_table_created(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        b = TokenBudget(daily_limit=500, db_path=db_path)
        b.record(100)
        b.close()

        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='token_usage'"
        ).fetchall()
        conn.close()
        assert len(rows) == 1

    def test_row_written_with_correct_columns(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        b = TokenBudget(daily_limit=500, db_path=db_path)
        b.record(100)
        b.record(50)
        b.close()

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT date, tokens_used, tokens_limit FROM token_usage"
        ).fetchone()
        conn.close()

        today = _dt.date.today().isoformat()
        assert row is not None
        assert row[0] == today
        assert row[1] == 150
        assert row[2] == 500

    def test_reload_resumes_todays_total(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        b1 = TokenBudget(daily_limit=500, db_path=db_path)
        b1.record(300)
        b1.close()

        # New instance (simulating restart) — should see 300 already recorded
        b2 = TokenBudget(daily_limit=500, db_path=db_path)
        assert b2.used() == 300
        b2.record(100)
        assert b2.used() == 400
        b2.close()

    def test_persistence_failure_does_not_crash(self, tmp_path):
        """Closing the DB then recording should not raise."""
        db_path = str(tmp_path / "audit.db")
        b = TokenBudget(daily_limit=500, db_path=db_path)
        # Forcefully close the underlying connection to simulate DB failure
        if b._db is not None:
            b._db.close()
            b._db = None
        # Should not raise — in-memory counter still works
        b.record(50)
        assert b.used() == 50


# ───────────────────────────────────────────────
# Stats snapshot
# ───────────────────────────────────────────────


class TestStats:
    def test_stats_fields(self):
        b = TokenBudget(daily_limit=1000, warn_at=0.8, action="warn")
        b.record(850)
        stats = b.stats()
        assert stats["daily_limit"] == 1000
        assert stats["tokens_used"] == 850
        assert stats["tokens_remaining"] == 150
        assert stats["usage_pct"] == pytest.approx(0.85)
        assert stats["warn_at"] == 0.8
        assert stats["action"] == "warn"
        assert stats["over_budget"] is False
        assert stats["warn_threshold_reached"] is True

    def test_stats_over_budget(self):
        b = TokenBudget(daily_limit=1000, action="block")
        b.record(1500)
        stats = b.stats()
        assert stats["over_budget"] is True
        assert stats["usage_pct"] == 1.0
        assert stats["tokens_remaining"] == 0


# ───────────────────────────────────────────────
# Config wiring
# ───────────────────────────────────────────────


class TestConfigParsing:
    def test_config_parses_token_budget_section(self):
        from spine.config import parse_config
        raw = {
            "servers": [],
            "token_budget": {
                "daily_limit": 250_000,
                "warn_at": 0.75,
                "action": "block",
            },
        }
        cfg = parse_config(raw)
        assert cfg.token_budget.daily_limit == 250_000
        assert cfg.token_budget.warn_at == 0.75
        assert cfg.token_budget.action == "block"

    def test_config_defaults(self):
        from spine.config import parse_config
        cfg = parse_config({"servers": []})
        assert cfg.token_budget.daily_limit == 0
        assert cfg.token_budget.warn_at == 0.8
        assert cfg.token_budget.action == "warn"

    def test_config_rejects_invalid_action(self):
        from spine.config import parse_config
        with pytest.raises(ValueError, match="token_budget.action"):
            parse_config({
                "servers": [],
                "token_budget": {"action": "explode"},
            })

    def test_config_rejects_out_of_range_warn_at(self):
        from spine.config import parse_config
        with pytest.raises(ValueError, match="warn_at"):
            parse_config({
                "servers": [],
                "token_budget": {"warn_at": 1.5},
            })

    def test_config_rejects_negative_limit(self):
        from spine.config import parse_config
        with pytest.raises(ValueError, match="daily_limit"):
            parse_config({
                "servers": [],
                "token_budget": {"daily_limit": -1},
            })


# ───────────────────────────────────────────────
# spine_budget meta-tool
# ───────────────────────────────────────────────


class TestMetaTool:
    def _build_proxy(self, tmp_path, **tb_overrides):
        """Build a SpineProxy with a temp audit DB and no downstream servers."""
        from spine.config import (
            SpineConfig,
            StateGuardConfig,
            TokenBudgetConfig,
        )
        from spine.proxy import SpineProxy

        tb_kwargs = {
            "daily_limit": 1000,
            "warn_at": 0.8,
            "action": "warn",
        }
        tb_kwargs.update(tb_overrides)

        cfg = SpineConfig(
            log_level="info",
            audit_db=str(tmp_path / "audit.db"),
            servers=[],
            state_guard=StateGuardConfig(enabled=False),
            token_budget=TokenBudgetConfig(**tb_kwargs),
        )
        return SpineProxy(cfg)

    def test_meta_tool_is_exposed(self, tmp_path):
        proxy = self._build_proxy(tmp_path)
        tool = proxy._get_budget_meta_tool()
        assert tool["name"] == "spine_budget"
        assert "description" in tool
        assert tool["inputSchema"]["type"] == "object"

    def test_meta_tool_returns_stats(self, tmp_path):
        proxy = self._build_proxy(tmp_path, daily_limit=1000)
        proxy._budget.record(250)

        resp = proxy._handle_budget(msg_id=42, arguments={})
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 42
        result = resp["result"]
        assert "stats" in result
        stats = result["stats"]
        assert stats["tokens_used"] == 250
        assert stats["daily_limit"] == 1000
        assert stats["tokens_remaining"] == 750
        assert stats["usage_pct"] == pytest.approx(0.25)

        # Content block carries a human-readable summary
        assert any(
            "250" in block.get("text", "")
            for block in result.get("content", [])
        )

    def test_meta_tool_handles_disabled_budget(self, tmp_path):
        proxy = self._build_proxy(tmp_path, daily_limit=0)
        resp = proxy._handle_budget(msg_id=1, arguments={})
        text = resp["result"]["content"][0]["text"]
        assert "not configured" in text

    def test_inject_banner_prepends_to_content(self, tmp_path):
        proxy = self._build_proxy(tmp_path)
        payload = {"content": [{"type": "text", "text": "original"}]}
        out = proxy._inject_banner(payload, "[SPINE] Warning: 80%")
        assert out["content"][0]["text"] == "[SPINE] Warning: 80%"
        assert out["content"][1]["text"] == "original"

    def test_inject_banner_wraps_bare_payload(self, tmp_path):
        proxy = self._build_proxy(tmp_path)
        out = proxy._inject_banner({"foo": "bar"}, "[SPINE] hi")
        assert out["content"][0]["text"] == "[SPINE] hi"
        assert out["foo"] == "bar"
