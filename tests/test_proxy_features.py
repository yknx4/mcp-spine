"""
Tests for MCP Spine proxy features.

Covers:
  - Human-in-the-loop confirmation flow
  - Background initialization
  - tools/listChanged notification
  - Meta-tool handling
"""

from __future__ import annotations

import asyncio

import pytest

from spine.config import ServerConfig, SpineConfig, StateGuardConfig
from spine.proxy import SpineProxy
from spine.security.policy import PolicyAction, SecurityPolicy, ToolPolicy
from spine.transport import ServerConnection, ServerPool

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


class TestRecallMetaTool:
    """Test spine_recall response safety."""

    def test_recall_miss_does_not_echo_raw_query(self, tmp_path):
        proxy = SpineProxy(
            SpineConfig(
                audit_db=str(tmp_path / "audit.db"),
                state_guard=StateGuardConfig(enabled=False),
            )
        )

        response = proxy._handle_recall(
            1,
            {"query": "pii-case-00-user@example.invalid", "last_n": 5},
        )

        text = response["result"]["content"][0]["text"]
        assert "No cached tool results found." in text
        assert "pii-case-00-user@example.invalid" not in text


class TestDuplicateToolNames:
    """Test duplicate backend tool names stay separately callable."""

    def test_server_pool_namespaces_duplicate_tool_names(self):
        class FakeServer:
            def __init__(self, name):
                self.name = name
                self._tools = [
                    {
                        "name": "execute_sql",
                        "_spine_original_name": "execute_sql",
                        "_spine_server": name,
                    }
                ]
                self._tool_names = set()
                self._public_to_original_tool = {}

            @property
            def is_available(self):
                return True

        pool = ServerPool([], logger=None)
        pool._servers = {
            "beanstack-production": FakeServer("beanstack-production"),
            "beanstack-readonly": FakeServer("beanstack-readonly"),
        }

        pool._rebuild_tool_index()

        tools = {tool["name"] for tool in pool.all_tools()}
        assert tools == {
            "beanstack_production_execute_sql",
            "beanstack_readonly_execute_sql",
        }
        assert pool.route_tool("beanstack_production_execute_sql").name == "beanstack-production"
        assert pool.route_tool("beanstack_readonly_execute_sql").name == "beanstack-readonly"
        assert pool.route_tool("execute_sql") is None
        assert pool.ambiguous_tool_options("execute_sql") == [
            "beanstack_production_execute_sql",
            "beanstack_readonly_execute_sql",
        ]

    def test_duplicate_original_names_do_not_get_unprefixed_alias(self):
        class FakeServer:
            def __init__(self, name):
                self.name = name
                self.config = ServerConfig(name=name, command="python")
                self._tools = [
                    {
                        "name": "list_schemas",
                        "_spine_original_name": "list_schemas",
                        "_spine_server": name,
                    }
                ]
                self._tool_names = set()
                self._public_to_original_tool = {}

            @property
            def is_available(self):
                return True

        pool = ServerPool([], logger=None)
        pool._servers = {
            "primary-a": FakeServer("primary-a"),
            "primary-b": FakeServer("primary-b"),
        }

        pool._rebuild_tool_index()

        assert pool.route_tool("list_schemas") is None
        assert pool.ambiguous_tool_options("list_schemas") == [
            "primary_a_list_schemas",
            "primary_b_list_schemas",
        ]

    def test_duplicate_normalized_server_prefixes_stay_unique(self):
        class FakeServer:
            def __init__(self, name):
                self.name = name
                self._tools = [
                    {
                        "name": "execute_sql",
                        "_spine_original_name": "execute_sql",
                        "_spine_server": name,
                    }
                ]
                self._tool_names = set()
                self._public_to_original_tool = {}

            @property
            def is_available(self):
                return True

        pool = ServerPool([], logger=None)
        pool._servers = {
            "db-prod": FakeServer("db-prod"),
            "db_prod": FakeServer("db_prod"),
        }

        pool._rebuild_tool_index()

        tools = {tool["name"] for tool in pool.all_tools()}
        assert len(tools) == 2
        assert all(tool.startswith("db_prod_") for tool in tools)
        assert all(tool.endswith("_execute_sql") for tool in tools)
        assert pool.route_tool("execute_sql") is None
        assert pool.ambiguous_tool_options("execute_sql") == sorted(tools)

    def test_duplicate_tool_names_scale_across_many_servers(self):
        class FakeServer:
            def __init__(self, name):
                self.name = name
                self._tools = [
                    {
                        "name": "execute_sql",
                        "_spine_original_name": "execute_sql",
                        "_spine_server": name,
                    }
                ]
                self._tool_names = set()
                self._public_to_original_tool = {}

            @property
            def is_available(self):
                return True

        pool = ServerPool([], logger=None)
        pool._servers = {
            f"database-{index}": FakeServer(f"database-{index}")
            for index in range(100)
        }

        pool._rebuild_tool_index()

        tools = {tool["name"] for tool in pool.all_tools()}
        assert len(tools) == 100
        assert pool.route_tool("execute_sql") is None
        assert len(pool.ambiguous_tool_options("execute_sql")) == 100
        for tool_name in tools:
            assert pool.route_tool(tool_name) is not None

    def test_multiple_servers_prefix_unique_tool_names(self):
        class FakeServer:
            def __init__(self, name, tool_name):
                self.name = name
                self._tools = [
                    {
                        "name": tool_name,
                        "_spine_original_name": tool_name,
                        "_spine_server": name,
                    }
                ]
                self._tool_names = set()
                self._public_to_original_tool = {}

            @property
            def is_available(self):
                return True

        pool = ServerPool([], logger=None)
        pool._servers = {
            "analytics-primary": FakeServer("analytics-primary", "execute_sql"),
            "metrics-primary": FakeServer("metrics-primary", "get_top_queries"),
        }

        pool._rebuild_tool_index()

        tools = {tool["name"] for tool in pool.all_tools()}
        assert tools == {
            "analytics_primary_execute_sql",
            "metrics_primary_get_top_queries",
        }
        assert pool.route_tool("execute_sql") is None
        assert pool.ambiguous_tool_options("execute_sql") == [
            "analytics_primary_execute_sql",
        ]
        assert pool.route_tool("get_top_queries") is None
        assert pool.ambiguous_tool_options("get_top_queries") == [
            "metrics_primary_get_top_queries",
        ]

    def test_partial_multi_server_tool_list_is_prefixed_before_all_servers_ready(self):
        class FakeServer:
            def __init__(self, name, available):
                self.name = name
                self._available = available
                self._tools = [
                    {
                        "name": "execute_sql",
                        "_spine_original_name": "execute_sql",
                        "_spine_server": name,
                    }
                ]
                self._tool_names = set()
                self._public_to_original_tool = {}

            @property
            def is_available(self):
                return self._available

        pool = ServerPool([], logger=None)
        pool._servers = {
            "database-0": FakeServer("database-0", True),
            "database-1": FakeServer("database-1", False),
        }

        pool._rebuild_tool_index()

        tools = {tool["name"] for tool in pool.all_tools()}
        assert tools == {"database_0_execute_sql"}
        assert pool.route_tool("execute_sql") is None
        assert pool.ambiguous_tool_options("execute_sql") == [
            "database_0_execute_sql",
        ]

    @pytest.mark.asyncio
    async def test_startup_rebuilds_public_names_as_each_server_connects(self):
        fast_listed = asyncio.Event()
        release_slow = asyncio.Event()

        class FakeServer:
            def __init__(self, name, release_event=None):
                self.name = name
                self._release_event = release_event
                self._available = False
                self._tools = []
                self._tool_names = set()
                self._public_to_original_tool = {}

            @property
            def is_available(self):
                return self._available

            async def start(self):
                return None

            async def initialize(self):
                return None

            async def list_tools(self):
                if self._release_event:
                    await self._release_event.wait()
                self._tools = [
                    {
                        "name": "get_top_queries",
                        "_spine_original_name": "get_top_queries",
                        "_spine_server": self.name,
                    }
                ]
                self._available = True
                if self.name == "database-0":
                    fast_listed.set()
                return self._tools

        pool = ServerPool([], logger=None)
        pool._servers = {
            "database-0": FakeServer("database-0"),
            "database-1": FakeServer("database-1", release_slow),
        }

        start_task = asyncio.create_task(pool.start_all())
        await fast_listed.wait()
        await asyncio.sleep(0)

        tools = {tool["name"] for tool in pool.all_tools()}
        assert tools == {"database_0_get_top_queries"}
        assert pool.route_tool("get_top_queries") is None

        release_slow.set()
        await start_task

    @pytest.mark.asyncio
    async def test_tools_list_returns_prefixed_names_for_multi_server_pool(self, tmp_path):
        class FakeServer:
            def __init__(self, name):
                self.name = name
                self._tools = [
                    {
                        "name": "get_top_queries",
                        "_spine_original_name": "get_top_queries",
                        "_spine_server": name,
                        "description": "Get top queries",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
                self._tool_names = set()
                self._public_to_original_tool = {}

            @property
            def is_available(self):
                return True

        proxy = SpineProxy(
            SpineConfig(
                audit_db=str(tmp_path / "audit.db"),
                state_guard=StateGuardConfig(enabled=False),
            )
        )
        proxy._ready = True
        proxy._router = None
        proxy._minifier = None

        pool = ServerPool([], logger=None)
        pool._servers = {
            "beanstack-production": FakeServer("beanstack-production"),
            "beanstack-readonly": FakeServer("beanstack-readonly"),
        }
        pool._rebuild_tool_index()
        proxy.pool = pool

        response = await proxy._handle_tools_list(1, {"params": {}})

        tool_names = {
            tool["name"]
            for tool in response["result"]["tools"]
        }
        assert "get_top_queries" not in tool_names
        assert {
            "beanstack_production_get_top_queries",
            "beanstack_readonly_get_top_queries",
        } <= tool_names

    @pytest.mark.asyncio
    async def test_namespaced_tool_call_uses_original_backend_name(self):
        connection = ServerConnection(
            ServerConfig(name="beanstack-readonly", command="python"),
            logger=None,
        )
        connection._public_to_original_tool = {
            "beanstack_readonly_execute_sql": "execute_sql",
        }

        sent = {}

        async def fake_send_request(method, params):
            sent["method"] = method
            sent["params"] = params
            return {"result": {"content": []}}

        connection.send_request = fake_send_request

        await connection.call_tool(
            "beanstack_readonly_execute_sql",
            {"sql": "select 1"},
        )

        assert sent == {
            "method": "tools/call",
            "params": {
                "name": "execute_sql",
                "arguments": {"sql": "select 1"},
            },
        }


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
