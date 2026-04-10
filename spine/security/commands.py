"""
MCP Spine — Command Injection Guard

Validates commands and arguments used to spawn downstream MCP
server subprocesses. Prevents shell metacharacter injection
and arbitrary command execution.

IMPORTANT: Since we use create_subprocess_exec (not shell=True),
arguments are passed directly to the process without shell
interpretation. This means spaces and parentheses in paths are
safe — they're never split or interpreted. We only block characters
that could cause harm if a shell were somehow involved:
  ; & | ` $ { } ! and newlines

Explicitly ALLOWED in arguments (common in Windows paths):
  - Spaces:       C:\\Users\\John Doe\\project
  - Parentheses:  C:\\Program Files (x86)\\...
  - Quotes:       Not needed, exec doesn't use them
"""

from __future__ import annotations

import re

from spine.security.validation import ValidationError

# Only block actual shell metacharacters. Spaces and parentheses
# are safe because we never invoke a shell (create_subprocess_exec).
_DANGEROUS_CHARS = re.compile(r"[;&|`${}!\n\r]")

_DEFAULT_ALLOWED_COMMANDS = frozenset({
    "python", "python3", "node", "npx", "uvx", "deno",
    "mcp-server-filesystem", "mcp-server-github", "mcp-server-postgres",
})


def validate_server_command(
    command: str,
    args: list[str],
    allowed_commands: frozenset[str] | None = None,
) -> None:
    """
    Validate a server spawn command and its arguments.

    Prevents:
      - Shell metacharacter injection in args
      - Arbitrary command execution
      - Path traversal in command names
    """
    allowed = allowed_commands or _DEFAULT_ALLOWED_COMMANDS

    # Extract basename and strip extension.
    # Use PureWindowsPath for robust handling on all platforms —
    # PurePosixPath doesn't understand backslash separators,
    # so "C:\Program Files\python.exe" would not split correctly.
    from pathlib import PureWindowsPath, PurePosixPath
    # Try Windows-style first (handles both / and \ separators)
    cmd_basename = PureWindowsPath(command).stem
    # Fallback: if the result still has separators, try POSIX
    if "/" in cmd_basename:
        cmd_basename = PurePosixPath(command).stem

    if cmd_basename not in allowed:
        raise ValidationError(
            f"Command {command!r} (basename: {cmd_basename!r}) "
            f"not in allowed list: {sorted(allowed)}"
        )

    for i, arg in enumerate(args):
        if _DANGEROUS_CHARS.search(arg):
            raise ValidationError(
                f"Dangerous characters in argument {i}: {arg!r}"
            )
