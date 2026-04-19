"""
Opt-in e2e tests against the user's real Spine MCP configuration.

Run with:
    RUN_REAL_SPINE_MCP_E2E=1 pytest tests/test_real_spine_mcp_e2e.py
"""

from __future__ import annotations

import json
import os
import re
import select
import shutil
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_REAL_SPINE_MCP_E2E") != "1",
    reason="set RUN_REAL_SPINE_MCP_E2E=1 to run real Spine MCP e2e tests",
)


class SpineClient:
    def __init__(self, config_path: Path):
        env = os.environ.copy()
        env.setdefault("UV_CACHE_DIR", "/tmp/mcp_spine_uv_cache")  # noqa: S108
        uv = shutil.which("uv")
        if not uv:
            raise AssertionError("uv is required to launch real Spine MCP e2e")
        self.process = subprocess.Popen(  # noqa: S603
            [
                uv,
                "--directory",
                str(Path(__file__).resolve().parents[1]),
                "run",
                "--extra",
                "pii",
                "mcp-spine",
                "serve",
                "--config",
                str(config_path),
            ],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._next_id = 1

    def close(self) -> None:
        if self.process.poll() is not None:
            return
        assert self.process.stdin is not None
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)

    def request(self, method: str, params: dict | None = None, timeout: float = 180) -> dict:
        assert self.process.stdin is not None
        msg_id = self._next_id
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": msg_id, "method": method}
        if params is not None:
            message["params"] = params

        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        return self._read_response(msg_id, timeout=timeout)

    def notify(self, method: str, params: dict | None = None) -> None:
        assert self.process.stdin is not None
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def _read_response(self, msg_id: int, timeout: float) -> dict:
        assert self.process.stdout is not None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                stderr = self.process.stderr.read() if self.process.stderr else ""
                raise AssertionError(
                    f"spine exited early with {self.process.returncode}:\n{stderr}"
                )

            readable, _, _ = select.select([self.process.stdout], [], [], 0.2)
            if not readable:
                continue

            line = self.process.stdout.readline()
            if not line:
                continue
            response = json.loads(line)
            if response.get("id") == msg_id:
                return response

        stderr = self.process.stderr.read() if self.process.stderr else ""
        raise AssertionError(f"timed out waiting for response id={msg_id}\n{stderr}")


def _response_text(response: dict) -> str:
    return json.dumps(response, sort_keys=True)


def test_real_readonly_top_queries_do_not_hide_metrics_or_sql_shape():
    config_path = Path(os.environ.get("SPINE_REAL_CONFIG", "spine.toml"))
    if not config_path.exists():
        pytest.skip(f"real Spine config not found: {config_path}")

    client = SpineClient(config_path)
    try:
        init = client.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "real-spine-mcp-e2e", "version": "1.0"},
            },
        )
        assert "error" not in init
        client.notify("notifications/initialized")

        tools = client.request("tools/list", {}, timeout=180)
        tool_names = {tool["name"] for tool in tools["result"]["tools"]}
        top_query_tools = sorted(
            name for name in tool_names if name.endswith("get_top_queries")
        )
        readonly_tools = [
            name for name in top_query_tools if "readonly" in name.lower()
        ]
        assert top_query_tools, "real Spine config has no get_top_queries tool"
        if len(top_query_tools) > 1:
            assert "get_top_queries" not in tool_names

        response = client.request(
            "tools/call",
            {
                "name": readonly_tools[0] if readonly_tools else top_query_tools[0],
                "arguments": {"limit": 10, "sort_by": "mean_time"},
            },
            timeout=180,
        )
    finally:
        client.close()

    assert "error" not in response
    text = _response_text(response)
    assert "Top 10 slowest queries by mean execution time per call" in text
    assert re.search(r"\bID\d{6,}\b", text) is None, (
        "top-query response should not use ID-style placeholders for "
        "non-PII diagnostic metrics or query shape"
    )
    assert "[spine-state" not in text


def test_real_production_explain_does_not_mangle_plan_metrics():
    config_path = Path(os.environ.get("SPINE_REAL_CONFIG", "spine.toml"))
    if not config_path.exists():
        pytest.skip(f"real Spine config not found: {config_path}")

    client = SpineClient(config_path)
    try:
        init = client.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "real-spine-mcp-e2e", "version": "1.0"},
            },
        )
        assert "error" not in init
        client.notify("notifications/initialized")

        tools = client.request("tools/list", {}, timeout=180)
        tool_names = {tool["name"] for tool in tools["result"]["tools"]}
        explain_tools = sorted(
            name for name in tool_names if name.endswith("explain_query")
        )
        production_tools = [
            name for name in explain_tools if "production" in name.lower()
        ]
        assert explain_tools, "real Spine config has no explain_query tool"
        if len(explain_tools) > 1:
            assert "explain_query" not in tool_names

        response = client.request(
            "tools/call",
            {
                "name": production_tools[0] if production_tools else explain_tools[0],
                "arguments": {
                    "analyze": True,
                    "sql": (
                        'SELECT COUNT(*) FROM "log_item_date_totals" '
                        'WHERE "log_item_date_totals"."profile_id" = 7826034'
                    ),
                },
            },
            timeout=180,
        )
    finally:
        client.close()

    assert "error" not in response
    text = _response_text(response)
    assert "Error:" not in text
    assert "Execution Time:" in text
    assert re.search(r"\bID\d{6,}\b", text) is None, (
        "explain response should not use ID-style placeholders for "
        "non-PII diagnostic plan output"
    )
    assert re.search(r"\+?1?[- .(]*\d{3}[- .)]*\d{3}[- .]*\d{4}x\d+", text) is None, (
        "explain response should not replace timings with fake phone numbers"
    )
    assert "[spine-state" not in text
