"""
MCP Spine — Streamable HTTP Transport Client

Connects to remote MCP servers using the Streamable HTTP transport
defined in MCP specification version 2025-03-26.

This replaces the legacy SSE transport (2024-11-05) with a single
endpoint that handles both POST (sending) and GET (listening).

Key differences from legacy SSE:
  - Single endpoint URL for all operations
  - POST returns either application/json or text/event-stream
  - Session management via Mcp-Session-Id header
  - GET opens optional SSE stream for server-initiated messages

Config example:
    [[servers]]
    name = "remote-api"
    transport = "streamable-http"
    url = "https://mcp.example.com/mcp"
    headers = { Authorization = "Bearer token123" }
    timeout_seconds = 30
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from spine.audit import AuditLogger, EventType


class StreamableHTTPClient:
    """
    Async client for MCP Streamable HTTP transport.

    Uses stdlib urllib — no external dependencies.
    Supports both direct JSON responses and SSE streaming.
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        logger: AuditLogger | None = None,
    ):
        self._url = url
        self._headers = headers or {}
        self._timeout = timeout
        self._logger = logger
        self._connected = False
        self._session_id: str | None = None
        self._request_id = 0
        self._listener_task: asyncio.Task | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._notification_handlers: list[Any] = []

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        """
        Establish connection by sending an initialize request.

        The server may return a Mcp-Session-Id header for session tracking.
        """
        try:
            # Send initialize via POST
            result = await self.send_request("initialize", {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-spine",
                    "version": "0.2.3",
                },
            })

            self._connected = True

            # Send initialized notification
            await self._send_notification("notifications/initialized")

            # Optionally start GET listener for server-initiated messages
            self._listener_task = asyncio.create_task(
                self._listen_for_server_messages(),
                name="streamable-http-listener",
            )

            if self._logger:
                self._logger.info(
                    EventType.SERVER_CONNECT,
                    message=f"Streamable HTTP connected to {self._url}",
                    session_id=self._session_id or "none",
                )

            return result

        except Exception as e:
            self._connected = False
            if self._logger:
                self._logger.error(
                    EventType.SERVER_CONNECT,
                    error=f"Streamable HTTP connection failed: {e}",
                )
            raise

    async def send_request(
        self, method: str, params: dict | None = None
    ) -> dict[str, Any]:
        """
        Send a JSON-RPC request via HTTP POST.

        The server may respond with:
          - application/json: single JSON-RPC response
          - text/event-stream: SSE stream with response(s)
        """
        import urllib.error
        import urllib.request

        self._request_id += 1
        msg_id = self._request_id

        request = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": method,
        }
        if params:
            request["params"] = params

        body = json.dumps(request).encode("utf-8")
        req = urllib.request.Request(
            self._url,
            data=body,
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        for key, value in self._headers.items():
            req.add_header(key, value)
        if self._session_id:
            req.add_header("Mcp-Session-Id", self._session_id)

        loop = asyncio.get_event_loop()

        try:
            response = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=self._timeout),
                ),
                timeout=self._timeout,
            )

            # Capture session ID from response headers
            session_header = response.headers.get("Mcp-Session-Id")
            if session_header:
                self._session_id = session_header

            content_type = response.headers.get("Content-Type", "")

            if "text/event-stream" in content_type:
                # SSE streaming response
                return await self._read_sse_response(response, msg_id)
            else:
                # Direct JSON response
                raw = response.read().decode("utf-8")
                result = json.loads(raw)
                return result

        except urllib.error.HTTPError as e:
            if e.code == 405:
                raise ConnectionError(
                    f"Server does not support Streamable HTTP at {self._url}"
                )
            raise ConnectionError(f"HTTP {e.code}: {e.reason}")
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Streamable HTTP request timed out after {self._timeout}s: {method}"
            )

    async def _read_sse_response(
        self, response: Any, expected_id: int
    ) -> dict[str, Any]:
        """
        Read an SSE stream from a POST response.

        Extracts the JSON-RPC response matching expected_id.
        Also handles server-initiated requests/notifications in the stream.
        """
        loop = asyncio.get_event_loop()
        result_future: asyncio.Future = loop.create_future()

        def _parse_stream():
            event_type = None
            data_lines: list[str] = []

            try:
                for raw_line in response:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\n\r")

                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line[5:].strip())
                    elif line == "":
                        if data_lines:
                            data = "\n".join(data_lines)
                            try:
                                message = json.loads(data)
                                msg_id = message.get("id")

                                if msg_id == expected_id:
                                    loop.call_soon_threadsafe(
                                        result_future.set_result, message
                                    )
                                elif msg_id is not None and msg_id in self._pending:
                                    future = self._pending.pop(msg_id)
                                    if not future.done():
                                        loop.call_soon_threadsafe(
                                            future.set_result, message
                                        )
                                # Server notifications/requests during stream
                                elif msg_id is None or "method" in message:
                                    if self._logger:
                                        self._logger.log(
                                            EventType.TOOL_RESPONSE,
                                            tool_name=message.get("method"),
                                        )
                            except json.JSONDecodeError:
                                pass
                        event_type = None
                        data_lines = []
            except Exception as e:
                if not result_future.done():
                    loop.call_soon_threadsafe(
                        result_future.set_exception,
                        ConnectionError(f"SSE stream error: {e}"),
                    )

        await loop.run_in_executor(None, _parse_stream)

        try:
            return await asyncio.wait_for(result_future, timeout=self._timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("SSE stream did not return expected response")

    async def _send_notification(
        self, method: str, params: dict | None = None
    ) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        import urllib.request

        notification = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params:
            notification["params"] = params

        body = json.dumps(notification).encode("utf-8")
        req = urllib.request.Request(
            self._url,
            data=body,
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        for key, value in self._headers.items():
            req.add_header(key, value)
        if self._session_id:
            req.add_header("Mcp-Session-Id", self._session_id)

        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=self._timeout),
            )
        except Exception:
            pass  # Notifications are fire-and-forget

    async def _listen_for_server_messages(self) -> None:
        """
        Open a GET SSE stream for server-initiated messages.

        This is optional — servers that don't support GET will return 405,
        which we handle gracefully.
        """
        import urllib.error
        import urllib.request

        req = urllib.request.Request(self._url, method="GET")
        req.add_header("Accept", "text/event-stream")
        for key, value in self._headers.items():
            req.add_header(key, value)
        if self._session_id:
            req.add_header("Mcp-Session-Id", self._session_id)

        loop = asyncio.get_event_loop()

        try:
            response = await loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=self._timeout),
            )
        except urllib.error.HTTPError as e:
            if e.code == 405:
                # Server doesn't support GET — that's fine
                return
            return
        except Exception:
            return

        content_type = response.headers.get("Content-Type", "")
        if "text/event-stream" not in content_type:
            return

        def _read_stream():
            data_lines: list[str] = []
            try:
                for raw_line in response:
                    if not self._connected:
                        break
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\n\r")

                    if line.startswith("data:"):
                        data_lines.append(line[5:].strip())
                    elif line == "":
                        if data_lines:
                            data = "\n".join(data_lines)
                            try:
                                message = json.loads(data)
                                msg_id = message.get("id")
                                if msg_id is not None and msg_id in self._pending:
                                    future = self._pending.pop(msg_id)
                                    if not future.done():
                                        loop.call_soon_threadsafe(
                                            future.set_result, message
                                        )
                            except json.JSONDecodeError:
                                pass
                        data_lines = []
            except Exception:
                pass

        await loop.run_in_executor(None, _read_stream)

    async def close(self) -> None:
        """Close the connection and clean up."""
        self._connected = False
        if self._listener_task and not self._listener_task.done():
            self._listener_task.cancel()
        for future in self._pending.values():
            if not future.done():
                future.set_exception(ConnectionError("Connection closed"))
        self._pending.clear()
