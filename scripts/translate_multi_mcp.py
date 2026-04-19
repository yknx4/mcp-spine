#!/usr/bin/env python3
"""
Translate kfirtoledo/multi-mcp JSON settings into an mcp-spine TOML config.

By default this keeps multi-mcp in the middle:

    MCP client -> mcp-spine -> multi-mcp -> original backend servers

Use --mode direct to expand each multi-mcp backend into native mcp-spine
[[servers]] entries instead.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

DEFAULT_ALLOWED_COMMANDS = {"python", "python3", "node", "npx", "uvx", "deno"}


def _load_multi_mcp_config(path: Path) -> dict[str, dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Failed to parse {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise SystemExit("multi-mcp config must be a JSON object")

    servers = raw.get("mcpServers")
    if not isinstance(servers, dict):
        raise SystemExit("multi-mcp config must contain an object at 'mcpServers'")

    for name, config in servers.items():
        if not isinstance(name, str) or not name:
            raise SystemExit("all mcpServers keys must be non-empty strings")
        if not isinstance(config, dict):
            raise SystemExit(f"mcpServers.{name} must be an object")

    return servers


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        items = ", ".join(
            f"{json.dumps(key)} = {_toml_value(item)}"
            for key, item in value.items()
            if isinstance(key, str)
        )
        return "{ " + items + " }"
    raise TypeError(f"cannot serialize {type(value).__name__} to TOML")


def _command_allow_name(command: str) -> str:
    windows_stem = PureWindowsPath(command).stem
    if windows_stem != command:
        return windows_stem
    return PurePosixPath(command).stem


def _server_name(name: str) -> str:
    return name.strip()


def _validate_string_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit(f"{field_name} must be a list of strings")
    return value


def _validate_string_dict(value: Any, field_name: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str)
        for key, item in value.items()
    ):
        raise SystemExit(f"{field_name} must be an object of string keys and string values")
    return value


def _base_config_lines(allowed_commands: set[str]) -> list[str]:
    return [
        "# Generated from a multi-mcp JSON config.",
        "# Validate with: mcp-spine verify --config <this-file>",
        "",
        "[spine]",
        'log_level = "info"',
        'audit_db = "spine_audit.db"',
        "",
        "[routing]",
        "max_tools = 5",
        'always_include = ["spine_set_context"]',
        "",
        "[minifier]",
        "level = 2",
        "max_description_length = 120",
        "",
        "[state_guard]",
        "enabled = true",
        'watch_paths = ["."]',
        "",
        "[security]",
        "scrub_secrets_in_logs = true",
        "scrub_secrets_in_responses = false",
        "audit_all_tool_calls = true",
        "global_rate_limit = 60",
        "per_tool_rate_limit = 30",
        f"allowed_commands = {_toml_value(sorted(allowed_commands))}",
        "",
    ]


def convert_through_multi_mcp(
    source_path: Path,
    *,
    multi_mcp_dir: Path,
    server_name: str,
    command: str,
    timeout_seconds: int,
    log_level: str,
) -> str:
    # Validate the input early even though multi-mcp still owns the downstream config.
    _load_multi_mcp_config(source_path)

    allowed_commands = {*DEFAULT_ALLOWED_COMMANDS, _command_allow_name(command)}
    lines = _base_config_lines(allowed_commands)
    args = [
        "--directory",
        str(multi_mcp_dir),
        "run",
        "main.py",
        "--transport",
        "stdio",
        "--config",
        str(source_path),
        "--log-level",
        log_level,
    ]
    lines.extend([
        "[[servers]]",
        f"name = {_toml_value(server_name)}",
        f"command = {_toml_value(command)}",
        f"args = {_toml_value(args)}",
        f"timeout_seconds = {timeout_seconds}",
        "",
    ])
    return "\n".join(lines)


def convert_direct(source_path: Path, *, timeout_seconds: int) -> str:
    servers = _load_multi_mcp_config(source_path)
    allowed_commands = set(DEFAULT_ALLOWED_COMMANDS)
    server_blocks: list[str] = []

    for raw_name, config in servers.items():
        name = _server_name(raw_name)
        block: list[str] = ["[[servers]]", f"name = {_toml_value(name)}"]

        if "url" in config:
            url = config["url"]
            if not isinstance(url, str):
                raise SystemExit(f"mcpServers.{name}.url must be a string")
            block.extend([
                'transport = "sse"',
                f"url = {_toml_value(url)}",
            ])
            headers = _validate_string_dict(config.get("headers"), f"mcpServers.{name}.headers")
            if headers:
                block.append(f"headers = {_toml_value(headers)}")
        else:
            command = config.get("command")
            if not isinstance(command, str) or not command:
                raise SystemExit(
                    f"mcpServers.{name} must define either a string 'url' "
                    "or a non-empty string 'command'"
                )
            args = _validate_string_list(config.get("args"), f"mcpServers.{name}.args")
            allowed_commands.add(_command_allow_name(command))
            block.extend([
                f"command = {_toml_value(command)}",
                f"args = {_toml_value(args)}",
            ])

            env = _validate_string_dict(config.get("env"), f"mcpServers.{name}.env")
            if env:
                block.append(f"env = {_toml_value(env)}")

        block.append(f"timeout_seconds = {timeout_seconds}")

        unsupported = sorted(set(config) - {"args", "command", "env", "headers", "url"})
        for key in unsupported:
            block.append(f"# omitted unsupported multi-mcp key: {key}")

        server_blocks.append("\n".join(block))

    lines = _base_config_lines(allowed_commands)
    lines.extend(server_blocks)
    lines.append("")
    return "\n\n".join(lines)


def _write_output(path: Path, content: str, *, force: bool) -> None:
    if path.exists() and not force:
        raise SystemExit(f"{path} already exists; pass --force to overwrite it")
    path.write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Translate multi-mcp mcp.json settings into mcp-spine TOML."
    )
    parser.add_argument("input", type=Path, help="Path to the multi-mcp JSON config")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("spine.toml"),
        help="Path for the generated mcp-spine TOML config",
    )
    parser.add_argument(
        "--mode",
        choices=["chain", "direct"],
        default="chain",
        help=(
            "chain keeps multi-mcp in the middle; direct expands each multi-mcp "
            "server into native mcp-spine servers"
        ),
    )
    parser.add_argument(
        "--multi-mcp-dir",
        type=Path,
        help="multi-mcp checkout directory; defaults to the input config directory",
    )
    parser.add_argument(
        "--multi-mcp-server-name",
        default="multi-mcp",
        help="server name to use for multi-mcp in chain mode",
    )
    parser.add_argument(
        "--multi-mcp-command",
        default="uv",
        help="command used to launch multi-mcp in chain mode",
    )
    parser.add_argument(
        "--multi-mcp-log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="multi-mcp log level in chain mode",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=180,
        help="timeout_seconds to write for generated server entries",
    )
    parser.add_argument("--force", action="store_true", help="overwrite output if it exists")
    args = parser.parse_args(argv)

    source_path = args.input.expanduser().resolve()
    if not source_path.exists():
        raise SystemExit(f"input config not found: {source_path}")

    if args.mode == "chain":
        content = convert_through_multi_mcp(
            source_path,
            multi_mcp_dir=(args.multi_mcp_dir or source_path.parent).expanduser().resolve(),
            server_name=args.multi_mcp_server_name,
            command=args.multi_mcp_command,
            timeout_seconds=args.timeout_seconds,
            log_level=args.multi_mcp_log_level,
        )
    else:
        content = convert_direct(source_path, timeout_seconds=args.timeout_seconds)

    _write_output(args.output, content, force=args.force)
    print(f"Wrote {args.output}")
    if args.mode == "chain":
        print("Generated chain: MCP client -> mcp-spine -> multi-mcp -> backend servers")
    else:
        print("Generated direct mcp-spine server entries from multi-mcp settings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
