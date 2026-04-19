"""Tests for the multi-mcp config translation script."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from spine.config import load_config

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "translate_multi_mcp.py"


def _load_script_module():
    spec = importlib.util.spec_from_file_location("translate_multi_mcp", SCRIPT_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write_multi_mcp_config(path: Path) -> None:
    path.write_text(
        json.dumps({
            "mcpServers": {
                "weather": {
                    "command": "python",
                    "args": ["./tools/get_weather.py"],
                    "env": {"WEATHER_TOKEN": "${WEATHER_TOKEN}"},
                },
                "remote_docs": {
                    "url": "http://127.0.0.1:9080/sse",
                    "headers": {"Authorization": "Bearer ${DOCS_TOKEN}"},
                },
            }
        }),
        encoding="utf-8",
    )


def test_chain_mode_keeps_multi_mcp_in_middle(tmp_path: Path):
    module = _load_script_module()
    source = tmp_path / "mcp.json"
    _write_multi_mcp_config(source)

    toml = module.convert_through_multi_mcp(
        source,
        multi_mcp_dir=tmp_path / "multi-mcp",
        server_name="multi-mcp",
        command="uv",
        timeout_seconds=180,
        log_level="INFO",
    )
    output = tmp_path / "spine.toml"
    output.write_text(toml, encoding="utf-8")

    config = load_config(output)
    assert len(config.servers) == 1
    server = config.servers[0]
    assert server.name == "multi-mcp"
    assert server.command == "uv"
    assert server.args == [
        "--directory",
        str(tmp_path / "multi-mcp"),
        "run",
        "main.py",
        "--transport",
        "stdio",
        "--config",
        str(source),
        "--log-level",
        "INFO",
    ]
    assert "uv" in config.security.allowed_commands


def test_direct_mode_expands_stdio_and_sse_servers(tmp_path: Path, monkeypatch):
    module = _load_script_module()
    monkeypatch.setenv("WEATHER_TOKEN", "secret")
    monkeypatch.setenv("DOCS_TOKEN", "docs-secret")
    source = tmp_path / "mcp.json"
    _write_multi_mcp_config(source)

    output = tmp_path / "spine.toml"
    output.write_text(module.convert_direct(source, timeout_seconds=90), encoding="utf-8")

    config = load_config(output)
    assert [server.name for server in config.servers] == ["weather", "remote_docs"]

    weather = config.servers[0]
    assert weather.command == "python"
    assert weather.args == ["./tools/get_weather.py"]
    assert weather.env == {"WEATHER_TOKEN": "secret"}
    assert weather.timeout_seconds == 90

    remote_docs = config.servers[1]
    assert remote_docs.transport == "sse"
    assert remote_docs.url == "http://127.0.0.1:9080/sse"
    assert remote_docs.headers == {"Authorization": "Bearer ${DOCS_TOKEN}"}


def test_cli_writes_chain_config(tmp_path: Path):
    source = tmp_path / "mcp.json"
    _write_multi_mcp_config(source)
    output = tmp_path / "spine.toml"

    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT_PATH),
            str(source),
            "--output",
            str(output),
            "--multi-mcp-dir",
            str(tmp_path / "multi-mcp"),
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.stdout.startswith("Wrote ")
    config = load_config(output)
    assert len(config.servers) == 1
    assert config.servers[0].name == "multi-mcp"
