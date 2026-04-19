"""
MCP Spine — State Guard (Stage 4)

Eliminates "Context Rot" by maintaining a content-addressed file
manifest and injecting it into LLM responses as an authoritative
state pin.

How it works:
  1. Watches project files using watchfiles (Rust-backed)
  2. On change: computes SHA-256, increments version counter
  3. Before sending tool responses to the LLM, injects a compact
     state block listing tracked files with their hashes
  4. The LLM sees "sha:a3f8b2c1" and knows to re-read if its
     cached version doesn't match

This breaks the context rot cycle where the LLM confidently
edits a stale version of a file.
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class FileState:
    """Tracked state of a single file."""
    path: str
    sha256: str
    size: int
    modified: float
    version: int
    snippet: str
    pinned_at: float


class StateGuard:
    """
    File state tracker and truth enforcer.

    Watches project files, maintains a SHA-256 manifest,
    and generates state pins for LLM injection.
    """

    def __init__(
        self,
        watch_paths: list[str] | None = None,
        ignore_patterns: list[str] | None = None,
        max_tracked_files: int = 200,
        max_pin_files: int = 20,
        snippet_length: int = 200,
    ):
        self.watch_paths = watch_paths or ["."]
        self.ignore_patterns = ignore_patterns or [
            "**/.git/**",
            "**/node_modules/**",
            "**/__pycache__/**",
            "**/.venv/**",
            "**/*.pyc",
            "**/.DS_Store",
        ]
        self.max_tracked_files = max_tracked_files
        self.max_pin_files = max_pin_files
        self.snippet_length = snippet_length

        self.manifest: dict[str, FileState] = {}
        self._version_counter: int = 0
        self._watcher_task: asyncio.Task | None = None
        self._running = False

    def _should_ignore(self, path: str) -> bool:
        """Check if a path matches any ignore pattern."""
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
            # Also check just the filename
            if fnmatch.fnmatch(Path(path).name, pattern):
                return True
        return False

    def _compute_state(self, path: str) -> FileState | None:
        """Compute the current state of a file."""
        try:
            p = Path(path)
            if not p.is_file():
                return None

            content = p.read_bytes()
            sha = hashlib.sha256(content).hexdigest()

            # Generate snippet (first N chars, UTF-8 safe)
            try:
                text = content[:self.snippet_length * 2].decode("utf-8", errors="replace")
                snippet = text[:self.snippet_length]
            except Exception:
                snippet = f"[binary, {len(content)} bytes]"

            self._version_counter += 1

            return FileState(
                path=str(p),
                sha256=sha,
                size=len(content),
                modified=p.stat().st_mtime,
                version=self._version_counter,
                snippet=snippet,
                pinned_at=time.time(),
            )
        except (OSError, PermissionError):
            return None

    def update_file(self, path: str) -> bool:
        """
        Update the manifest for a single file.

        Returns True if the file state actually changed.
        """
        if self._should_ignore(path):
            return False

        new_state = self._compute_state(path)
        if new_state is None:
            # File deleted or unreadable
            removed = self.manifest.pop(path, None)
            return removed is not None

        # Check if content actually changed
        existing = self.manifest.get(path)
        if existing and existing.sha256 == new_state.sha256:
            return False  # no content change

        # Enforce max tracked files
        if (
            path not in self.manifest
            and len(self.manifest) >= self.max_tracked_files
        ):
            # Evict oldest by version
            oldest = min(self.manifest, key=lambda k: self.manifest[k].version)
            del self.manifest[oldest]

        self.manifest[path] = new_state
        return True

    def remove_file(self, path: str) -> bool:
        """Remove a file from the manifest."""
        return self.manifest.pop(path, None) is not None

    async def start_watching(self) -> None:
        """Start the background file watcher."""
        try:
            import watchfiles
        except ImportError:
            raise ImportError(
                "State Guard requires watchfiles. "
                "Install with: pip install watchfiles"
            )

        self._running = True

        # Initial scan
        for watch_path in self.watch_paths:
            root = Path(watch_path)
            if root.is_dir():
                for p in root.rglob("*"):
                    if p.is_file() and not self._should_ignore(str(p)):
                        self.update_file(str(p))
                        if len(self.manifest) >= self.max_tracked_files:
                            break

        # Watch for changes
        try:
            async for changes in watchfiles.awatch(
                *self.watch_paths,
                recursive=True,
                step=500,  # 500ms polling interval
            ):
                if not self._running:
                    break

                for change_type, path in changes:
                    if self._should_ignore(path):
                        continue

                    if change_type.name in ("modified", "added"):
                        self.update_file(path)
                    elif change_type.name == "deleted":
                        self.remove_file(path)

        except asyncio.CancelledError:
            pass

    def stop_watching(self) -> None:
        """Stop the background file watcher."""
        self._running = False
        if self._watcher_task:
            self._watcher_task.cancel()

    def generate_pin(self) -> str:
        """
        Generate a compact state pin for LLM injection.

        This is the core anti-rot mechanism. The pin is appended
        to tool responses so the LLM has an authoritative view
        of file state.
        """
        if not self.manifest:
            return ""

        # Sort by version (most recently changed first)
        sorted_files = sorted(
            self.manifest.values(),
            key=lambda f: f.version,
            reverse=True,
        )[:self.max_pin_files]

        lines = [
            "[spine-state v" + str(self._version_counter) + "]",
            f"Snapshot: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Tracked: {len(self.manifest)} files",
            "---",
        ]

        for state in sorted_files:
            # Compact path (relative if possible)
            display_path = state.path
            for wp in self.watch_paths:
                try:
                    display_path = str(Path(state.path).relative_to(wp))
                    break
                except ValueError:
                    continue

            ts = datetime.fromtimestamp(state.modified).strftime("%H:%M:%S")
            lines.append(
                f"  {display_path} "
                f"v{state.version} "
                f"sha:{state.sha256[:8]} "
                f"{state.size}B "
                f"@ {ts}"
            )

        lines.extend([
            "---",
            "Note: file hashes above reflect the latest disk state. "
            "Re-read before editing if your cached version differs.",
        ])

        return "\n".join(lines)

    def inject_pin_into_response(
        self, response: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Inject the state pin into a tool response.

        Appends the pin as a text content block in the response.
        """
        pin = self.generate_pin()
        if not pin:
            return response

        result = response.get("result", response)
        if isinstance(result, dict):
            content = result.get("content", [])
            if isinstance(content, list):
                content.append({
                    "type": "text",
                    "text": f"\n\n{pin}",
                })
                result["content"] = content
            elif isinstance(result.get("content"), str):
                result["content"] += f"\n\n{pin}"
        elif isinstance(result, str):
            result += f"\n\n{pin}"

        return response

    def get_file_state(self, path: str) -> FileState | None:
        """Get the current tracked state of a file."""
        return self.manifest.get(path)

    def get_changed_since(self, version: int) -> list[FileState]:
        """Get all files changed since a given version number."""
        return [
            state for state in self.manifest.values()
            if state.version > version
        ]

    @property
    def current_version(self) -> int:
        """The global version counter (monotonically increasing)."""
        return self._version_counter

    def snapshot(self) -> dict[str, str]:
        """Get a {path: sha256} snapshot of the current manifest."""
        return {
            path: state.sha256
            for path, state in self.manifest.items()
        }
