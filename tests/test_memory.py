"""
Tests for MCP Spine tool output memory cache.
"""

import time
import pytest
from spine.memory import ToolMemory, CachedResult


class TestToolMemoryBasic:
    """Test basic store and recall operations."""

    def test_store_and_recall(self):
        mem = ToolMemory()
        mem.store("read_file", {"path": "/test.txt"}, {"content": [{"type": "text", "text": "hello world"}]})

        results = mem.recall()
        assert len(results) == 1
        assert results[0].tool_name == "read_file"
        assert "hello world" in results[0].result_summary

    def test_recall_empty(self):
        mem = ToolMemory()
        results = mem.recall()
        assert results == []

    def test_recall_by_tool_name(self):
        mem = ToolMemory()
        mem.store("read_file", {"path": "/a.txt"}, "content A")
        mem.store("write_file", {"path": "/b.txt"}, "ok")
        mem.store("read_file", {"path": "/c.txt"}, "content C")

        results = mem.recall(tool_name="read_file")
        assert len(results) == 2
        assert all(r.tool_name == "read_file" for r in results)

    def test_recall_last_n(self):
        mem = ToolMemory()
        for i in range(10):
            mem.store("tool", {"i": i}, f"result {i}")

        results = mem.recall(last_n=3)
        assert len(results) == 3
        # Most recent first
        assert "result 9" in results[0].result_summary

    def test_deduplication(self):
        mem = ToolMemory()
        mem.store("read_file", {"path": "/test.txt"}, "version 1")
        mem.store("read_file", {"path": "/test.txt"}, "version 2")

        results = mem.recall()
        assert len(results) == 1
        assert "version 2" in results[0].result_summary

    def test_different_args_not_deduplicated(self):
        mem = ToolMemory()
        mem.store("read_file", {"path": "/a.txt"}, "content A")
        mem.store("read_file", {"path": "/b.txt"}, "content B")

        results = mem.recall()
        assert len(results) == 2


class TestToolMemoryCapacity:
    """Test ring buffer capacity and eviction."""

    def test_max_entries(self):
        mem = ToolMemory(max_entries=5)
        for i in range(10):
            mem.store("tool", {"i": i}, f"result {i}")

        # Deque maxlen keeps last 5
        results = mem.recall(last_n=10)
        assert len(results) <= 5

    def test_size_property(self):
        mem = ToolMemory()
        assert mem.size == 0

        mem.store("tool_a", {}, "result")
        assert mem.size == 1

        mem.store("tool_b", {}, "result")
        assert mem.size == 2

    def test_clear(self):
        mem = ToolMemory()
        mem.store("tool", {}, "result")
        assert mem.size == 1

        mem.clear()
        assert mem.size == 0
        assert mem.recall() == []


class TestToolMemoryTTL:
    """Test time-to-live expiration."""

    def test_expired_entries_not_recalled(self):
        mem = ToolMemory(ttl_seconds=0.1)
        mem.store("tool", {}, "result")

        time.sleep(0.15)
        results = mem.recall()
        assert results == []

    def test_fresh_entries_recalled(self):
        mem = ToolMemory(ttl_seconds=10.0)
        mem.store("tool", {}, "result")

        results = mem.recall()
        assert len(results) == 1


class TestToolMemorySummary:
    """Test result summary extraction."""

    def test_string_result(self):
        mem = ToolMemory()
        mem.store("tool", {}, "simple string result")

        results = mem.recall()
        assert results[0].result_summary == "simple string result"

    def test_mcp_content_blocks(self):
        mem = ToolMemory()
        result = {
            "content": [
                {"type": "text", "text": "File contents here"},
                {"type": "text", "text": "More content"},
            ]
        }
        mem.store("read_file", {"path": "/test.txt"}, result)

        results = mem.recall()
        assert "File contents here" in results[0].result_summary
        assert "More content" in results[0].result_summary

    def test_long_result_truncated(self):
        mem = ToolMemory(max_summary_length=50)
        mem.store("tool", {}, "x" * 200)

        results = mem.recall()
        assert len(results[0].result_summary) == 50
        assert results[0].result_summary.endswith("...")

    def test_dict_result_without_content(self):
        mem = ToolMemory()
        mem.store("tool", {}, {"status": "ok", "count": 42})

        results = mem.recall()
        assert "ok" in results[0].result_summary


class TestToolMemorySearch:
    """Test keyword search."""

    def test_search_by_tool_name(self):
        mem = ToolMemory()
        mem.store("read_file", {"path": "/a.txt"}, "alpha")
        mem.store("write_file", {"path": "/b.txt"}, "beta")

        results = mem.search("read_file")
        assert len(results) == 1
        assert results[0].tool_name == "read_file"

    def test_search_by_content(self):
        mem = ToolMemory()
        mem.store("read_file", {"path": "/a.txt"}, "the quick brown fox")
        mem.store("read_file", {"path": "/b.txt"}, "lazy dog")

        results = mem.search("brown fox")
        assert len(results) == 1
        assert "quick brown fox" in results[0].result_summary

    def test_search_by_argument(self):
        mem = ToolMemory()
        mem.store("read_file", {"path": "/important/config.yaml"}, "data")
        mem.store("read_file", {"path": "/other/file.txt"}, "other")

        results = mem.search("config.yaml")
        assert len(results) == 1

    def test_search_no_results(self):
        mem = ToolMemory()
        mem.store("tool", {}, "result")

        results = mem.search("nonexistent")
        assert results == []

    def test_search_case_insensitive(self):
        mem = ToolMemory()
        mem.store("tool", {}, "Hello World")

        results = mem.search("hello world")
        assert len(results) == 1


class TestToolMemoryCompact:
    """Test compact string output."""

    def test_recall_compact_empty(self):
        mem = ToolMemory()
        text = mem.recall_compact()
        assert "No recent" in text

    def test_recall_compact_with_data(self):
        mem = ToolMemory()
        mem.store("read_file", {"path": "/test.txt"}, "file contents")

        text = mem.recall_compact()
        assert "read_file" in text
        assert "file contents" in text
        assert "ago" in text

    def test_compact_age_display(self):
        mem = ToolMemory()
        mem.store("tool", {}, "result")

        entry = mem.recall()[0]
        compact = entry.to_compact()
        assert "0s ago" in compact or "1s ago" in compact


class TestCachedResult:
    """Test CachedResult dataclass."""

    def test_age_seconds(self):
        entry = CachedResult(
            tool_name="test",
            arguments={},
            result_summary="result",
            timestamp=time.time() - 5,
            arg_hash="abc",
        )
        assert 4.5 < entry.age_seconds < 6.0

    def test_to_compact(self):
        entry = CachedResult(
            tool_name="read_file",
            arguments={"path": "/test.txt"},
            result_summary="hello world",
            timestamp=time.time(),
            arg_hash="abc",
        )
        compact = entry.to_compact()
        assert "read_file" in compact
        assert "hello world" in compact
