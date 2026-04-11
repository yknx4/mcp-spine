"""
MCP Spine — Tool Output Memory

Caches recent tool call results so the semantic router can swap
tools between turns without losing context. The LLM can reference
previous tool output even if that tool is no longer in the
active tool set.

Design:
  - Ring buffer of last N results (default 50)
  - Keyed by tool name + argument hash
  - Injected as compact summary in tool responses
  - Queryable via spine_recall meta-tool
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CachedResult:
    """A single cached tool call result."""
    tool_name: str
    arguments: dict[str, Any]
    result_summary: str
    timestamp: float
    arg_hash: str

    @property
    def age_seconds(self) -> float:
        return time.time() - self.timestamp

    def to_compact(self) -> str:
        """Compact string representation for injection."""
        age = self.age_seconds
        if age < 60:
            age_str = f"{int(age)}s ago"
        elif age < 3600:
            age_str = f"{int(age / 60)}m ago"
        else:
            age_str = f"{int(age / 3600)}h ago"
        return f"[{self.tool_name} ({age_str}): {self.result_summary}]"


class ToolMemory:
    """
    Ring buffer cache for recent tool call results.

    Stores the last N tool results with deduplication.
    When the semantic router swaps a tool out, its previous
    output remains accessible via spine_recall.
    """

    def __init__(
        self,
        max_entries: int = 50,
        max_summary_length: int = 200,
        ttl_seconds: float = 3600.0,
    ):
        self._max_entries = max_entries
        self._max_summary = max_summary_length
        self._ttl = ttl_seconds
        self._cache: deque[CachedResult] = deque(maxlen=max_entries)
        self._by_hash: dict[str, CachedResult] = {}

    @staticmethod
    def _hash_args(tool_name: str, arguments: dict) -> str:
        """Generate a stable hash for tool name + arguments."""
        key = json.dumps(
            {"tool": tool_name, "args": arguments},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _extract_summary(self, result: dict | list | str | Any) -> str:
        """Extract a compact summary from a tool result."""
        if isinstance(result, str):
            text = result
        elif isinstance(result, dict):
            # MCP tool results have content blocks
            content = result.get("content", [])
            if isinstance(content, list):
                texts = []
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        texts.append(block.get("text", ""))
                text = " ".join(texts) if texts else json.dumps(result)
            else:
                text = json.dumps(result)
        elif isinstance(result, list):
            text = json.dumps(result)
        else:
            text = str(result)

        # Truncate to max summary length
        if len(text) > self._max_summary:
            return text[:self._max_summary - 3] + "..."
        return text

    def store(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any,
    ) -> None:
        """Cache a tool call result."""
        arg_hash = self._hash_args(tool_name, arguments)
        summary = self._extract_summary(result)

        entry = CachedResult(
            tool_name=tool_name,
            arguments=arguments,
            result_summary=summary,
            timestamp=time.time(),
            arg_hash=arg_hash,
        )

        # Remove old entry with same hash if exists
        if arg_hash in self._by_hash:
            old = self._by_hash[arg_hash]
            # Can't remove from deque efficiently, but it'll age out
            del self._by_hash[arg_hash]

        self._cache.append(entry)
        self._by_hash[arg_hash] = entry

    def recall(
        self,
        tool_name: str | None = None,
        last_n: int = 5,
    ) -> list[CachedResult]:
        """
        Recall recent tool results.

        Args:
            tool_name: Filter by tool name (None = all tools)
            last_n: Number of recent results to return
        """
        now = time.time()
        results = []

        for entry in reversed(self._cache):
            # Skip expired entries
            if now - entry.timestamp > self._ttl:
                continue

            # Skip if hash no longer current (superseded by newer call)
            if self._by_hash.get(entry.arg_hash) is not entry:
                continue

            # Filter by tool name if specified
            if tool_name and entry.tool_name != tool_name:
                continue

            results.append(entry)
            if len(results) >= last_n:
                break

        return results

    def recall_compact(
        self,
        tool_name: str | None = None,
        last_n: int = 5,
    ) -> str:
        """Return a compact string of recent tool results."""
        results = self.recall(tool_name=tool_name, last_n=last_n)
        if not results:
            return "No recent tool results cached."
        return "\n".join(r.to_compact() for r in results)

    def search(self, query: str, last_n: int = 5) -> list[CachedResult]:
        """
        Search cached results by keyword match.

        Simple substring search — not semantic. For semantic search,
        the router's embedding model would be needed.
        """
        now = time.time()
        query_lower = query.lower()
        results = []

        for entry in reversed(self._cache):
            if now - entry.timestamp > self._ttl:
                continue
            if self._by_hash.get(entry.arg_hash) is not entry:
                continue

            # Search in tool name, arguments, and summary
            searchable = (
                entry.tool_name.lower()
                + " "
                + json.dumps(entry.arguments).lower()
                + " "
                + entry.result_summary.lower()
            )
            if query_lower in searchable:
                results.append(entry)
                if len(results) >= last_n:
                    break

        return results

    @property
    def size(self) -> int:
        """Number of active (non-expired) cached entries."""
        now = time.time()
        return sum(
            1 for e in self._cache
            if now - e.timestamp <= self._ttl
            and self._by_hash.get(e.arg_hash) is e
        )

    def clear(self) -> None:
        """Clear all cached results."""
        self._cache.clear()
        self._by_hash.clear()
