"""The MCP transports `nbrowser mcp serve` runs, on the official MCP Python SDK.

The SDK owns framing, the handshake and the protocol version on stdio and on
Streamable HTTP; `McpServer.call_tool` is the one call boundary.
"""

import socket
from typing import Any

import anyio
import mcp_types as types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from nott_netdoor.http import ApiKey, serve_app

from .mcp_server import SERVER_INSTRUCTIONS, TOOLS, McpServer

#: The largest HTTP request body the door reads.
MAX_BODY = 8 * 1024 * 1024
INTERNAL_ERROR = -32603
SDK_TOOLS = [types.Tool.model_validate(tool) for tool in TOOLS]


def build(session: McpServer) -> Server[Any]:
    """The SDK server answering for `session`."""
    # ponytail: one call at a time, as the hand-written loop answered them; the
    # browser session is not shown safe under concurrent calls.
    lock = anyio.Lock()

    async def list_tools(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=SDK_TOOLS)

    async def call_tool(
        ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        async with lock:
            try:
                result = await anyio.to_thread.run_sync(
                    session.call_tool, params.name, params.arguments or {}
                )
            except Exception as error:
                raise MCPError(INTERNAL_ERROR, str(error)) from error
        return types.CallToolResult.model_validate(result)

    return Server(
        "nbrowser",
        version="0.1.0",
        instructions=SERVER_INSTRUCTIONS,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


def serve_stdio(session: McpServer) -> None:
    """Serve one session on stdio until its peer stops talking."""
    server = build(session)

    async def run() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(run)


def serve_http(session: McpServer, listener: socket.socket, key: ApiKey) -> None:
    """Serve Streamable HTTP at `/mcp` on the loopback `listener`, behind the key.

    The Host check is off: a reverse proxy forwards the public name, and the
    bearer is what admits."""
    app = build(session).streamable_http_app(
        json_response=True,
        max_request_body_size=MAX_BODY,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        ),
    )
    serve_app(app, listener, key)
