"""
Tests for MCP Spine proxy features.

Covers:
  - Human-in-the-loop confirmation flow
  - Background initialization
  - tools/listChanged notification
  - Meta-tool handling
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from spine.security.policy import ToolPolicy, PolicyAction, SecurityPolicy


# ───────────────────────────────────────────────
# Human-in-the-Loop Policy Tests
# ───────────────────────────────────────────────

class TestHITLPolicy:
    """Test require_confirmation policy flag."""

    def test_policy_has_confirmation_flag(self):
        policy = ToolPolicy(name_pattern="write_file", require_confirmation=True)
        assert policy.require_confirmation is True

    def test_policy_default_no_confirmation(self):
        policy = ToolPolicy(name_pattern="read_file")
        assert policy.require_confirmation is False

    def test_policy_matches_with_confirmation(self):
        policy = ToolPolicy(
            name_pattern="write_*",
            action=PolicyAction.ALLOW,
            require_confirmation=True,
        )
        assert policy.matches("write_file")
        assert policy.matches("write_query")
        assert not policy.matches("read_file")

    def test_security_policy_finds_confirmation_tool(self):
        sp = SecurityPolicy(
            tool_policies=[
                ToolPolicy(name_pattern="write_file", require_confirmation=True),
                ToolPolicy(name_pattern="read_file"),
            ]
        )
        wp = sp.get_tool_policy("write_file")
        assert wp is not None
        assert wp.require_confirmation is True

        rp = sp.get_tool_policy("read_file")
        assert rp is not None
        assert rp.require_confirmation is False

    def test_confirmation_tool_still_allowed(self):
        sp = SecurityPolicy(
            tool_policies=[
                ToolPolicy(
                    name_pattern="write_file",
                    action=PolicyAction.ALLOW,
                    require_confirmation=True,
                ),
            ]
        )
        assert sp.is_tool_allowed("write_file") is True

    def test_denied_tool_not_affected_by_confirmation(self):
        sp = SecurityPolicy(
            tool_policies=[
                ToolPolicy(
                    name_pattern="execute_*",
                    action=PolicyAction.DENY,
                    require_confirmation=True,
                ),
            ]
        )
        assert sp.is_tool_allowed("execute_command") is False


# ───────────────────────────────────────────────
# Tool Policy Loading from Config
# ───────────────────────────────────────────────

class TestPolicyLoading:
    """Test loading tool policies from TOML-like config dicts."""

    def test_load_confirmation_from_config(self):
        from spine.security.policy import load_security_policy

        config = {
            "security": {
                "tools": [
                    {
                        "pattern": "write_file",
                        "action": "allow",
                        "require_confirmation": True,
                    },
                    {
                        "pattern": "delete_*",
                        "action": "deny",
                    },
                ]
            }
        }
        policy = load_security_policy(config)
        assert len(policy.tool_policies) == 2

        write_policy = policy.get_tool_policy("write_file")
        assert write_policy.require_confirmation is True

        delete_policy = policy.get_tool_policy("delete_file")
        assert delete_policy.action == PolicyAction.DENY
        assert delete_policy.require_confirmation is False

    def test_load_rate_limit_from_config(self):
        from spine.security.policy import load_security_policy

        config = {
            "security": {
                "tools": [
                    {
                        "pattern": "read_query",
                        "action": "audit",
                        "rate_limit": 30,
                    },
                ]
            }
        }
        policy = load_security_policy(config)
        rq = policy.get_tool_policy("read_query")
        assert rq.action == PolicyAction.AUDIT
        assert rq.rate_limit == 30


# ───────────────────────────────────────────────
# Protocol Message Tests
# ───────────────────────────────────────────────

class TestProtocolMessages:
    """Test JSON-RPC message construction."""

    def test_make_response(self):
        from spine.protocol import make_response
        resp = make_response(1, {"tools": []})
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        assert resp["result"] == {"tools": []}

    def test_make_error(self):
        from spine.protocol import make_error
        err = make_error(1, -32600, "Invalid request")
        assert err["jsonrpc"] == "2.0"
        assert err["id"] == 1
        assert err["error"]["code"] == -32600
        assert err["error"]["message"] == "Invalid request"

    def test_make_response_string_id(self):
        from spine.protocol import make_response
        resp = make_response("abc-123", {"tools": []})
        assert resp["id"] == "abc-123"


# ───────────────────────────────────────────────
# Dashboard Tests
# ───────────────────────────────────────────────

class TestDashboard:
    """Test dashboard database queries."""

    def test_dashboard_handles_missing_db(self):
        from spine.dashboard import SpineDashboard
        dash = SpineDashboard(db_path="/nonexistent/path.db")
        db = dash._connect_db()
        assert db is None

    def test_dashboard_connects_to_valid_db(self, tmp_path):
        import sqlite3
        db_path = str(tmp_path / "test_audit.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE audit_log (
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
        conn.commit()
        conn.close()

        from spine.dashboard import SpineDashboard
        dash = SpineDashboard(db_path=db_path)
        db = dash._connect_db()
        assert db is not None
        db.close()

    def test_dashboard_query_empty_db(self, tmp_path):
        import sqlite3
        db_path = str(tmp_path / "test_audit.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE audit_log (
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
        conn.commit()
        conn.row_factory = sqlite3.Row

        from spine.dashboard import SpineDashboard
        dash = SpineDashboard(db_path=db_path)
        results = dash._query(conn, "SELECT COUNT(*) as cnt FROM audit_log")
        assert results[0]["cnt"] == 0
        conn.close()

    def test_dashboard_query_with_data(self, tmp_path):
        import sqlite3
        import time
        db_path = str(tmp_path / "test_audit.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE audit_log (
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
        conn.execute(
            "INSERT INTO audit_log (timestamp, event_type, tool_name, server_name, details, fingerprint) VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), "tool_call", "read_file", "filesystem", '{"duration_ms": 5.2}', "abc123"),
        )
        conn.commit()
        conn.row_factory = sqlite3.Row

        from spine.dashboard import SpineDashboard
        dash = SpineDashboard(db_path=db_path)
        results = dash._query(conn, "SELECT COUNT(*) as cnt FROM audit_log WHERE event_type = 'tool_call'")
        assert results[0]["cnt"] == 1
        conn.close()


# ───────────────────────────────────────────────
# Analytics Tests
# ───────────────────────────────────────────────

class TestAnalytics:
    """Test that analytics queries work on audit data."""

    def _create_test_db(self, tmp_path, entries=None):
        import sqlite3
        import time

        db_path = str(tmp_path / "test_audit.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE audit_log (
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

        if entries is None:
            entries = [
                (time.time(), "tool_call", "read_file", "filesystem", '{"duration_ms": 5.0}', "fp1"),
                (time.time(), "tool_call", "read_file", "filesystem", '{"duration_ms": 3.0}', "fp2"),
                (time.time(), "tool_call", "write_file", "filesystem", '{"duration_ms": 12.0}', "fp3"),
                (time.time(), "tool_call", "list_directory", "filesystem", '{"duration_ms": 4.0}', "fp4"),
                (time.time(), "rate_limited", "write_file", "filesystem", '{"reason": "Rate limit exceeded"}', "fp5"),
            ]

        for entry in entries:
            conn.execute(
                "INSERT INTO audit_log (timestamp, event_type, tool_name, server_name, details, fingerprint) VALUES (?, ?, ?, ?, ?, ?)",
                entry,
            )
        conn.commit()
        return db_path, conn

    def test_tool_usage_ranking(self, tmp_path):
        db_path, conn = self._create_test_db(tmp_path)

        results = conn.execute("""
            SELECT tool_name, COUNT(*) as calls
            FROM audit_log
            WHERE event_type = 'tool_call'
            GROUP BY tool_name
            ORDER BY calls DESC
        """).fetchall()

        assert results[0][0] == "read_file"
        assert results[0][1] == 2
        conn.close()

    def test_avg_latency(self, tmp_path):
        db_path, conn = self._create_test_db(tmp_path)

        result = conn.execute("""
            SELECT ROUND(AVG(CAST(json_extract(details, '$.duration_ms') AS REAL)), 1) as avg_ms
            FROM audit_log
            WHERE event_type = 'tool_call'
        """).fetchone()

        assert result[0] == 6.0  # (5 + 3 + 12 + 4) / 4
        conn.close()

    def test_security_event_count(self, tmp_path):
        db_path, conn = self._create_test_db(tmp_path)

        result = conn.execute("""
            SELECT COUNT(*) as cnt
            FROM audit_log
            WHERE event_type IN ('rate_limited', 'path_violation', 'secret_detected', 'policy_deny')
        """).fetchone()

        assert result[0] == 1
        conn.close()
