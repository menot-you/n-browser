"""Drives the real loopback Streamable HTTP door (the MCP SDK behind the
nott_netdoor bearer) as a cold consumer."""

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PORT_CMD = [
    sys.executable,
    "-c",
    "import sys; from nbrowser.cli import main; sys.exit(main())",
    "mcp",
    "serve",
]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_listening(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"door did not listen on {port}")


def _post(
    port: int, key: str, body: bytes, session: str = ""
) -> tuple[int, bytes, str]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if key:
        headers["Authorization"] = f"Bearer {key}"
    if session:
        headers["Mcp-Session-Id"] = session
        headers["Mcp-Protocol-Version"] = "2024-11-05"
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp", data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read(), resp.headers.get("mcp-session-id", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), ""


def test_http_door_bearer_admits_and_refuses() -> None:
    key = secrets.token_hex(12)  # made at run time: no key literal in the source
    port = _free_port()
    with tempfile.NamedTemporaryFile("w", suffix=".key", delete=False) as f:
        f.write(key + "\n")
        key_file = f.name
    env = dict(os.environ)
    for k in (
        "ZAI_API_KEY",
        "MINIMAX_API_KEY",
        "TAVILY_API_KEY",
        "FIRECRAWL_API_KEY",
        "NOTT_BROKER_SOCKET",
    ):
        env.pop(k, None)
    proc = subprocess.Popen(
        PORT_CMD + ["--http-listen", f"127.0.0.1:{port}", "--api-key-file", key_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        _wait_listening(port)

        # Without the bearer: the door itself refuses (401), nothing reaches MCP.
        status, body, _ = _post(port, "", b"{}")
        assert status == 401, (status, body)

        # With the bearer: a real MCP handshake answers over HTTP.
        init = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "http-battery", "version": "0"},
                },
            }
        ).encode()
        status, body, session = _post(port, key, init)
        assert status == 200, (status, body)
        resp = json.loads(body)
        assert resp["result"]["protocolVersion"] == "2024-11-05"
        assert session

        done = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        ).encode()
        assert _post(port, key, done, session)[0] == 202
        tools = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).encode()
        status, body, _ = _post(port, key, tools, session)
        assert status == 200, (status, body)
        assert len(json.loads(body)["result"]["tools"]) == 14

        # Non-MCP path is isolated.
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/other", data=b"{}", method="POST"
        )
        req.add_header("Authorization", f"Bearer {key}")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        assert status == 404
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        os.unlink(key_file)
