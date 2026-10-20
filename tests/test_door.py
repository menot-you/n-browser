"""Drives the real stdio MCP door as a cold consumer (subprocess, JSON lines)."""

import hashlib
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

import nott_database
import pytest

from nbrowser.session import BrowserLaunchConfig, BrowserSession

PORT_CMD = [
    sys.executable,
    "-c",
    "import sys; from nbrowser.cli import main; sys.exit(main())",
    "mcp",
    "serve",
]


def drive_door(
    lines: list[str], drop: tuple[str, ...] = ()
) -> dict[int, dict[str, Any]]:
    env = dict(os.environ)
    for name in ("NOTT_BROKER_SOCKET", *drop):
        env.pop(name, None)
    # The door double must never do keyed egress: a shell carrying the real
    # grant would turn the live-refusal cells into real api.github.com calls.
    env.pop("GITHUB_TOKEN", None)
    # stdin stays open until every request is answered: a peer that closes it
    # is shutting the session down, and the SDK cancels what is still running.
    expected = sum(1 for line in lines if '"id"' in line)
    proc = subprocess.Popen(
        PORT_CMD,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    assert proc.stdin is not None and proc.stdout is not None
    responses: dict[int, dict[str, Any]] = {}
    try:
        proc.stdin.write("\n".join(lines) + "\n")
        proc.stdin.flush()
        deadline = time.monotonic() + 60
        while len(responses) < expected and time.monotonic() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            msg = json.loads(line)
            if "id" in msg:
                responses[msg["id"]] = msg
    finally:
        proc.stdin.close()
        _, errors = proc.communicate(timeout=30)
    if not responses:
        # A door that died before answering must fail with its own words,
        # never as a bare KeyError on the missing response id.
        raise AssertionError(
            f"door exited {proc.returncode} with no responses; stderr:\n{errors[-2000:]}"
        )
    return responses


def _handshake(next_id: int) -> list[str]:
    return [
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": next_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "battery", "version": "0"},
                },
            }
        ),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    ]


def test_door_lists_exactly_14_tools() -> None:
    lines = _handshake(1) + [
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    ]
    responses = drive_door(lines)
    tools = responses[2]["result"]["tools"]
    names = [t["name"] for t in tools]
    assert len(names) == 14
    assert len(set(names)) == 14
    assert "nbrowser_fixture_upload_source" not in names
    assert "nbrowser_file_upload" not in names
    assert "nbrowser_web_research" not in names


def test_door_refuses_internal_target_with_typed_envelope() -> None:
    lines = _handshake(1) + [
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "nbrowser_page_navigate",
                    "arguments": {
                        "host_url": "http://169.254.169.254/latest/meta-data"
                    },
                },
            }
        )
    ]
    responses = drive_door(lines)
    result = responses[2]["result"]
    assert result["isError"] is True
    envelope = json.loads(result["content"][0]["text"])
    assert envelope["ok"] is False
    assert envelope["code"] == "grant_required"
    assert envelope["refused_operation"] == "navigate"
    assert envelope["refused_target"] == "http://169.254.169.254/"


def test_door_refuses_unimplemented_tool_never_success() -> None:
    lines = _handshake(1) + [
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "nbrowser_web_search", "arguments": {}},
            }
        )
    ]
    responses = drive_door(lines)
    result = responses[2]["result"]
    assert result["isError"] is True
    envelope = json.loads(result["content"][0]["text"])
    assert envelope["code"] == "invalid_input"


def test_door_interact_activation_runs_supplying_refuses() -> None:
    """Two assertive branches, no skip (§31):
    - Chromium present: click on a live loopback page lands (digest changes),
      a supplying verb (type) answers grant-required at the door.
    - Chromium absent: the same door call is the typed launch refusal.
    """
    import http.server
    import threading

    from nbrowser.private_root import chromium_present

    def lines_tail(url: str, n0: int) -> list[str]:
        return [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": n0,
                    "method": "tools/call",
                    "params": {
                        "name": "nbrowser_page_navigate",
                        "arguments": {"host_url": url},
                    },
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": n0 + 1,
                    "method": "tools/call",
                    "params": {"name": "nbrowser_page_snapshot", "arguments": {}},
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": n0 + 2,
                    "method": "tools/call",
                    "params": {
                        "name": "nbrowser_page_interact",
                        "arguments": {"verb": "click", "selector": "#b"},
                    },
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": n0 + 3,
                    "method": "tools/call",
                    "params": {"name": "nbrowser_page_snapshot", "arguments": {}},
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": n0 + 4,
                    "method": "tools/call",
                    "params": {
                        "name": "nbrowser_page_interact",
                        "arguments": {
                            "verb": "upload",
                            "selector": "#i",
                            "text": "hello",
                        },
                    },
                }
            ),
        ]

    if not chromium_present():
        # Absence branch, at the door: the typed launch refusal, never a skip.
        lines = _handshake(1) + lines_tail("http://127.0.0.1:1/", 2)
        responses = drive_door(lines)
        result = responses[2]["result"]
        assert result["isError"] is True
        envelope = json.loads(result["content"][0]["text"])
        assert envelope["code"] == "engine_failure"
        return

    html = (
        "<html><body><h1>Fixture</h1>"
        "<button id='b' onclick=\"document.getElementById('x').textContent='clicked'\">go</button>"
        "<span id='x'>init</span>"
        "<input id='i'></body></html>"
    )

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/"
    try:
        lines = _handshake(1) + lines_tail(url, 2)
        responses = drive_door(lines)

        assert responses[2]["result"].get("isError") is not True
        digest_before = json.loads(responses[3]["result"]["content"][0]["text"])[
            "digest"
        ]
        assert responses[4]["result"].get("isError") is not True
        assert responses[4]["result"]["content"][0]["text"].find("applied") >= 0
        digest_after = json.loads(responses[5]["result"]["content"][0]["text"])[
            "digest"
        ]

        # The click actually landed: the page changed between snapshots.
        assert digest_before != digest_after

        # Unapproved verb on a live page: typed refusal, never applied.
        result = responses[6]["result"]
        assert result["isError"] is True
        envelope = json.loads(result["content"][0]["text"])
        assert envelope["code"] == "grant_required"
        assert envelope["refused_operation"] == "upload"
    finally:
        server.shutdown()


def test_door_scrape_inline_ref_and_single_resolve() -> None:
    """Small text scrapes inline; oversized text spills into a session-owned
    ref (apply_text_artifacts) that nbrowser_content_show resolves once."""
    import hashlib
    import http.server
    import threading

    from nbrowser.private_root import chromium_present

    if not chromium_present():
        # Absence branch, typed: no Chromium, typed refusal.
        lines = _handshake(1) + [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "nbrowser_page_scrape",
                        "arguments": {"host_url": "http://127.0.0.1:1/x"},
                    },
                }
            )
        ]
        responses = drive_door(lines)
        envelope = json.loads(responses[2]["result"]["content"][0]["text"])
        assert responses[2]["result"]["isError"] is True
        assert envelope["code"] in ("engine_failure", "no_active_session")
        return

    paragraph = "lorem ipsum dolor sit amet " * 6000
    small = "<html><body><h1>Small</h1><p>tiny page</p></body></html>"
    big = f"<html><body><h1>Big</h1><p>{paragraph}</p></body></html>"
    expected_markdown = "# Big\n\n" + paragraph.strip()
    expected_ref = hashlib.sha256(expected_markdown.encode("utf-8")).hexdigest()

    pages = {"/small": small, "/big": big}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = pages.get(self.path, "<html><body></body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:

        def call(msg_id: int, name: str, args: dict[str, Any]) -> str:
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": args},
                }
            )

        lines = _handshake(1) + [
            call(
                2,
                "nbrowser_page_scrape",
                {"host_url": base + "/small", "format": "markdown"},
            ),
            call(
                3,
                "nbrowser_page_scrape",
                {"host_url": base + "/big", "format": "markdown"},
            ),
            call(
                4, "nbrowser_content_show", {"ref": expected_ref, "max_chars": 200000}
            ),
            call(5, "nbrowser_content_show", {"ref": expected_ref}),
        ]
        responses = drive_door(lines)

        small_payload = json.loads(responses[2]["result"]["content"][0]["text"])
        assert small_payload["truncated"] is False
        assert "Small" in small_payload["markdown"]
        assert small_payload["estimated_tokens"]["markdown"] > 0

        big_payload = json.loads(responses[3]["result"]["content"][0]["text"])
        artifact = big_payload["artifacts"]["markdown"]
        assert artifact["ref"] == expected_ref
        assert "markdown" not in big_payload

        first = json.loads(responses[4]["result"]["content"][0]["text"])
        assert "lorem ipsum" in first["content"]

        second = responses[5]["result"]
        assert second["isError"] is True
        envelope = json.loads(second["content"][0]["text"])
        assert envelope["code"] == "content_unavailable"
    finally:
        server.shutdown()


def test_door_capture_pixels_never_ride_stdio(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOTT_NBROWSER_CAPTURE_KEEP", "1")
    """Capture returns a quarantine ref (taint pixel_derived), never inline
    pixels; managed persistence refuses at the door."""
    import http.server
    import threading

    from nbrowser.private_root import chromium_present

    if not chromium_present():
        # Absence branch, typed: no Chromium, no pixels, typed refusal.
        lines = _handshake(1) + [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "nbrowser_page_capture", "arguments": {}},
                }
            )
        ]
        responses = drive_door(lines)
        envelope = json.loads(responses[2]["result"]["content"][0]["text"])
        assert responses[2]["result"]["isError"] is True
        assert envelope["code"] in ("engine_failure", "no_active_session")
        return

    html = "<html><head><title>Cap</title></head><body><p>cap page</p></body></html>"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/"
    try:
        lines = _handshake(1) + [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "nbrowser_page_navigate",
                        "arguments": {"host_url": url},
                    },
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "nbrowser_page_capture", "arguments": {}},
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "nbrowser_page_capture",
                        "arguments": {"retention": "managed_purgeable"},
                    },
                }
            ),
        ]
        responses = drive_door(lines)

        assert responses[2]["result"].get("isError") is not True
        payload = json.loads(responses[3]["result"]["content"][0]["text"])
        assert payload["taint"] == "pixel_derived"
        assert payload["bytes"] > 0
        assert "data" not in payload and "png" not in payload["ref"]
        assert payload["ref"] == "capture:" + payload["sha256"]
        assert len(payload["sha256"]) == 64  # raw digest, not pixels

        # The door inherits this test's NOTT_DATABASE_DIR, as a NOTT host passes it.
        managed = responses[4]["result"]
        assert managed.get("isError") is not True, managed
        kept = json.loads(managed["content"][0]["text"])
        assert kept["retention"] == "managed_purgeable"
        assert kept["source"]["retention"] == "managed_purgeable"
        path = nott_database.directory().parent / "captures" / f"{kept['sha256']}.png"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == kept["sha256"]
    finally:
        server.shutdown()


# --- nbrowser-surface-close: one Chromium door test per group -----------------


def _serve(
    pages: dict[str, str], redirects: dict[str, str] | None = None
) -> tuple[http.server.HTTPServer, str]:
    """One loopback fixture site, path -> HTML; a path in `redirects` answers
    302 to its target; every unknown path answers 404 with a small HTML body.
    Loopback is admitted by the kernel."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = self.path.split("?")[0]
            if redirects and path in redirects:
                self.send_response(302)
                self.send_header("Location", redirects[path])
                self.end_headers()
                return
            body = pages.get(path, "<html><body><p>missing</p></body></html>")
            self.send_response(200 if path in pages else 404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _payload(result: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(result["content"][0]["text"])
    return payload


def _absence_refuses(name: str, args: dict[str, Any]) -> None:
    """Chromium absent: the same door call is the typed launch refusal, never a skip."""
    lines = _handshake(1) + [
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": name, "arguments": args},
            }
        )
    ]
    responses = drive_door(lines)
    result = responses[2]["result"]
    assert result["isError"] is True
    assert _payload(result)["code"] == "engine_failure"


class DoorDriver:
    """One live door process, one request at a time — so a later call can be
    built from an earlier answer."""

    def __init__(self) -> None:
        env = dict(os.environ)
        env.pop("NOTT_BROKER_SOCKET", None)
        # Same hygiene as drive_door: a live door carrying the real grant would
        # turn any future live-cell call into real api.github.com egress.
        env.pop("GITHUB_TOKEN", None)
        # stderr goes to a file, never DEVNULL or PIPE: a door that dies must fail
        # with its own words (mirror of drive_door), and PIPE deadlocks on Chromium noise.
        fd, self._stderr_path = tempfile.mkstemp(prefix="door-stderr-")
        self.stderr = os.fdopen(fd, "w+", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(
            PORT_CMD,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            text=True,
            env=env,
        )
        self.next_id = 2
        for line in _handshake(1):
            self._write(line)
        first = self._read()
        assert first["id"] == 1

    def _write(self, line: str) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def _read(self) -> dict[str, Any]:
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                self.stderr.seek(0)
                tail = self.stderr.read()[-2000:]
                raise AssertionError(
                    f"door exited {self.proc.poll()} before answering; stderr:\n{tail}"
                )
            if line.strip():
                msg: dict[str, Any] = json.loads(line)
                return msg

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        msg_id = self.next_id
        self.next_id += 1
        self._write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": args},
                }
            )
        )
        msg = self._read()
        assert msg["id"] == msg_id
        result: dict[str, Any] = msg["result"]
        return result

    def close(self) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        self.proc.wait(timeout=60)
        self.stderr.close()
        os.unlink(self._stderr_path)


def test_door_interact_uses_declared_parameters() -> None:
    from nbrowser.private_root import chromium_present

    if not chromium_present():
        _absence_refuses("nbrowser_page_interact", {"verb": "click", "selector": "#b"})
        return
    site, base = _serve(
        {
            "/": "<html><head><title>Schema witness</title></head><body>"
            "<button id='b' onclick=\"document.title='clicked'\">go</button>"
            "</body></html>"
        }
    )
    calls = [
        ("nbrowser_page_navigate", {"host_url": base + "/"}),
        ("nbrowser_page_snapshot", {}),
        ("nbrowser_page_interact", {"verb": "click", "selector": "#b"}),
        ("nbrowser_page_snapshot", {}),
    ]
    lines = _handshake(1) + [
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    ]
    lines += [
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": name, "arguments": args},
            }
        )
        for i, (name, args) in enumerate(calls, 3)
    ]
    try:
        responses = drive_door(lines)
        schemas = {
            tool["name"]: tool["inputSchema"]
            for tool in responses[2]["result"]["tools"]
        }
        for i, (name, args) in enumerate(calls, 3):
            assert set(args) <= set(schemas[name]["properties"]), name
            assert set(schemas[name].get("required", [])) <= set(args), name
            assert responses[i]["result"].get("isError") is not True, responses[i]
        assert _payload(responses[4]["result"])["view"]["title"] == "Schema witness"
        assert _payload(responses[5]["result"])["status"] == "applied"
        assert _payload(responses[6]["result"])["view"]["title"] == "clicked"
    finally:
        site.shutdown()
        site.server_close()


def test_door_tab_list_reports_the_navigated_origin() -> None:
    from nbrowser.private_root import chromium_present

    if not chromium_present():
        _absence_refuses("nbrowser_tab_list", {})
        return
    site, base = _serve({"/": "<html><body><h1>Tabs</h1></body></html>"})
    door = DoorDriver()
    try:
        assert (
            door.call("nbrowser_page_navigate", {"host_url": base + "/"}).get("isError")
            is not True
        )
        tabs = _payload(door.call("nbrowser_tab_list", {}))["tabs"]
        assert [t["origin"] for t in tabs] == [base]
    finally:
        door.close()
        site.shutdown()


def test_door_session_show_counts_the_tab_a_page_left_state_in() -> None:
    from nbrowser.private_root import chromium_present

    if not chromium_present():
        door = DoorDriver()
        try:
            result = door.call("nbrowser_session_show", {})
            assert result.get("isError") is not True
            assert _payload(result) == {"active": False, "tabs_count": 0}
        finally:
            door.close()
        return
    show = (
        "<html><body><p id='out'></p><script>"
        "document.getElementById('out').textContent = 'cookie [' + document.cookie + "
        "'] storage [' + (localStorage.getItem('k') || '') + ']';"
        "</script></body></html>"
    )
    site, base = _serve(
        {
            "/set": (
                "<html><body><p>set</p><script>document.cookie = 'nb=1; path=/'; "
                "localStorage.setItem('k', 'v');</script></body></html>"
            ),
            "/show": show,
        }
    )
    door = DoorDriver()
    try:
        assert (
            door.call("nbrowser_page_navigate", {"host_url": base + "/set"}).get(
                "isError"
            )
            is not True
        )
        door.call("nbrowser_page_navigate", {"host_url": base + "/show"})
        before = _payload(door.call("nbrowser_page_scrape", {"format": "markdown"}))[
            "markdown"
        ]
        assert "cookie [nb=1] storage [v]" in before
        assert _payload(door.call("nbrowser_session_show", {})) == {
            "active": True,
            "tabs_count": 1,
        }
    finally:
        door.close()
        site.shutdown()


def test_door_console_network_group_reads_engine_frames() -> None:
    from nbrowser.private_root import chromium_present

    if not chromium_present():
        _absence_refuses("nbrowser_page_navigate", {"host_url": "http://127.0.0.1:1/"})
        return
    site, base = _serve(
        {
            "/": (
                "<html><body><p>obs</p><script>console.log('a'); console.warn('b'); "
                "console.error('c'); fetch('/api');</script></body></html>"
            ),
            "/api": '{"ok": true}',
        }
    )
    door = DoorDriver()
    try:
        assert (
            door.call("nbrowser_page_navigate", {"host_url": base + "/"}).get("isError")
            is not True
        )
        time.sleep(0.5)
        entries = _payload(door.call("nbrowser_console_show", {}))["entries"]
        assert {"level": "info", "category": "log"} in entries
        assert {"level": "warning", "category": "log"} in entries
        assert {"level": "error", "category": "log"} in entries
        requests = _payload(door.call("nbrowser_network_show", {}))["requests"]
        assert any(
            r["method"] == "get" and r["location"] == base + "/api" for r in requests
        )
        assert any(r["location"] == base + "/" for r in requests)
    finally:
        door.close()
        site.shutdown()


def test_door_capture_signs_the_frame_and_content_show_refuses_its_bytes() -> None:
    from nbrowser.private_root import chromium_present

    if not chromium_present():
        _absence_refuses("nbrowser_page_capture", {"retention": "no_store"})
        return
    site, base = _serve(
        {"/": "<html><head><title>init</title></head><body><p>go</p></body></html>"}
    )
    door = DoorDriver()
    try:
        assert (
            door.call("nbrowser_page_navigate", {"host_url": base + "/"}).get("isError")
            is not True
        )
        shot = _payload(door.call("nbrowser_page_capture", {"retention": "no_store"}))
        assert shot["ref"] == "capture:" + shot["sha256"]
        assert len(shot["sha256"]) == 64
        source = shot["source"]
        assert source["origin"]["kind"] == "browser_capture"
        assert source["origin"]["locator"] == base
        frame = source["origin"]["capture_frame"]
        assert frame["viewport_width_css_px"] > 0
        assert frame["viewport_height_css_px"] > 0
        refused = door.call("nbrowser_content_show", {"ref": shot["ref"]})
        assert refused["isError"] is True
        assert _payload(refused)["code"] == "content_unavailable"
        assert "capture" in _payload(refused)["message"]
        assert "PNG" not in json.dumps(refused)
    finally:
        door.close()
        site.shutdown()


# --- nbrowser-crawl-frontier: the isolated context, engine in process ---------


def test_isolated_context_has_its_own_cookie_jar() -> None:
    from nbrowser.private_root import chromium_present

    if not chromium_present():
        _absence_refuses("nbrowser_page_navigate", {"host_url": "http://127.0.0.1:1/"})
        return
    show = (
        "<html><body><p id='out'></p><script>"
        "document.getElementById('out').textContent = 'cookie [' + document.cookie + ']';"
        "</script></body></html>"
    )
    site, base = _serve(
        {
            "/set": "<html><body><p>set</p><script>document.cookie = 'nb=1; path=/';</script></body></html>",
            "/show": show,
        }
    )
    sess = BrowserSession(BrowserLaunchConfig(headless=True))
    try:
        default_tab = sess.tabs_open(base + "/set")
        sess.navigate(default_tab, base + "/show")
        read = "document.getElementById('out').textContent"
        assert sess.evaluate(default_tab, read) == "cookie [nb=1]"
        ctx = sess.context_open()
        try:
            tab = sess.tabs_open(base + "/show", ctx)
            assert sess.evaluate(tab, read) == "cookie []"
            assert tab in sess.tabs_list()
        finally:
            sess.context_dispose(ctx)
        assert tab not in sess.tabs_list()
        assert tab not in sess._tab_sessions
        assert default_tab in sess.tabs_list()
    finally:
        sess.close_session()
        site.shutdown()


# --- nbrowser-crawl-frontier: the crawl group through the door ---------------


def test_door_crawl_group_walks_pages_resumes_cursor_and_records_off_origin() -> None:
    from nbrowser.private_root import chromium_present

    if not chromium_present():
        _absence_refuses("nbrowser_site_crawl", {"host_url": "http://127.0.0.1:1/"})
        return
    other, other_base = _serve(
        {"/": "<html><body><h1>Other</h1><a href='/evil'>evil</a></body></html>"}
    )
    site, base = _serve(
        {
            "/": "<html><body><h1>Home</h1><a href='/a'>a</a><a href='/b'>b</a><a href='/r'>r</a></body></html>",
            "/a": "<html><body><p>page a</p><a href='/'>home</a></body></html>",
            "/b": "<html><body><p>page b</p><a href='/a#x'>a again</a></body></html>",
            "/cookie-set": "<p>set</p><script>document.cookie='nb=1; path=/';</script>",
            "/cookie-show": "<p id='out'></p><script>document.getElementById('out').textContent='cookie ['+document.cookie+']';</script>",
            "/cookie-call": "<p>set in call</p><script>document.cookie='nc=1; path=/';</script><a href='/cookie-show'>show</a>",
        },
        redirects={"/r": other_base + "/"},
    )
    door = DoorDriver()
    try:
        first = _payload(
            door.call("nbrowser_site_crawl", {"host_url": base + "/", "max_pages": 2})
        )
        assert [p["url"] for p in first["pages"]] == [base + "/", base + "/a"]
        assert first["pages"][0]["markdown"].startswith("# Home")
        assert first["stop_reason"] == "max_pages"
        cursor = first["cursor"]
        assert isinstance(cursor, str)
        second = _payload(door.call("nbrowser_site_crawl", {"cursor": cursor}))
        assert [p["url"] for p in second["pages"]] == [base + "/b", base + "/r"]
        assert second["pages"][0]["markdown"] == "page b\n\n[a again](" + base + "/a#x)"
        assert second["pages"][1] == {
            "url": base + "/r",
            "markdown": "",
            "off_origin": other_base,
        }
        assert second["stop_reason"] == "exhausted" and second["cursor"] is None
        gone = door.call("nbrowser_site_crawl", {"cursor": cursor})
        assert (
            gone["isError"] is True and _payload(gone)["code"] == "content_unavailable"
        )
        assert _payload(door.call("nbrowser_session_show", {})) == {
            "active": True,
            "tabs_count": 0,
        }
        assert (
            door.call("nbrowser_page_navigate", {"host_url": base + "/cookie-set"}).get(
                "isError"
            )
            is not True
        )
        door.call("nbrowser_page_navigate", {"host_url": base + "/cookie-show"})
        assert (
            _payload(door.call("nbrowser_page_scrape", {"format": "markdown"}))[
                "markdown"
            ]
            == "cookie [nb=1]"
        )
        isolated = _payload(
            door.call("nbrowser_site_crawl", {"host_url": base + "/cookie-show"})
        )
        assert isolated["pages"][0]["markdown"] == "cookie []"
        within = _payload(
            door.call("nbrowser_site_crawl", {"host_url": base + "/cookie-call"})
        )
        assert [page["url"] for page in within["pages"]] == [
            base + "/cookie-call",
            base + "/cookie-show",
        ]
        assert within["pages"][1]["markdown"] == "cookie [nc=1]"
        next_call = _payload(
            door.call("nbrowser_site_crawl", {"host_url": base + "/cookie-show"})
        )
        assert next_call["pages"][0]["markdown"] == "cookie []"
        door.call("nbrowser_page_navigate", {"host_url": base + "/cookie-show"})
        assert (
            _payload(door.call("nbrowser_page_scrape", {"format": "markdown"}))[
                "markdown"
            ]
            == "cookie [nb=1]"
        )
    finally:
        door.close()
        site.shutdown()
        other.shutdown()


def test_door_extract_malformed_href_preserves_readable_document() -> None:
    site, base = _serve(
        {"/": '<p>readable document</p><a href="http://[broken">link</a>'}
    )
    try:
        response = drive_door(
            _handshake(1)
            + [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "nbrowser_page_extract",
                            "arguments": {"urls": [base + "/"], "mode": "static"},
                        },
                    }
                )
            ]
        )[2]
        assert "error" not in response
        assert response["result"].get("isError") is not True
        document = _payload(response["result"])["documents"][0]
        assert "readable document" in document["markdown"]
        assert document["mode_used"] == "static"
    finally:
        site.shutdown()
        site.server_close()


def test_door_extract_auto_falls_to_browser_on_a_js_shell_and_never_on_404() -> None:
    from unittest.mock import patch

    from nbrowser.private_root import chromium_present

    if not chromium_present():
        _absence_refuses(
            "nbrowser_page_extract",
            {"urls": ["http://127.0.0.1:1/"], "mode": "browser"},
        )
        return
    plain = "<html><body><h1>Title</h1><p>Hello <b>bold</b> world</p><ul><li>one</li></ul><a href='/next'>Next</a></body></html>"
    shell = (
        "<html><body><noscript>Enable JS</noscript><div id=root></div>"
        "<script>document.body.innerHTML='<p>hi</p>'</script></body></html>"
    )
    site, base = _serve(
        {
            "/plain": plain,
            "/shell": shell,
            "/target": plain,
            "/unclosed": "<p>Hello",
            "/siblings": "<p>a<p>b<ul><li>c<li>d</ul>",
        },
        redirects={"/r": "/target"},
    )
    traced_command = """import sys
from nbrowser.session import CdpPipeClient
from nbrowser.cli import main
original_send = CdpPipeClient.send
def traced_send(self, method, params=None, session_id=None, timeout=30.0):
    if method == "Page.navigate":
        print("TEST_CDP_NAVIGATE", file=sys.stderr, flush=True)
    return original_send(self, method, params, session_id, timeout)
CdpPipeClient.send = traced_send
sys.exit(main())
"""
    with patch(
        __name__ + ".PORT_CMD", [sys.executable, "-c", traced_command, "mcp", "serve"]
    ):
        door = DoorDriver()

    def navigation_count() -> int:
        with open(door._stderr_path, encoding="utf-8", errors="replace") as log:
            return log.read().count("TEST_CDP_NAVIGATE")

    try:
        auto = _payload(
            door.call(
                "nbrowser_page_extract", {"urls": [base + "/shell"], "mode": "auto"}
            )
        )
        assert auto["documents"] == [
            {"url": base + "/shell", "mode_used": "browser", "markdown": "hi"}
        ]
        static = _payload(
            door.call(
                "nbrowser_page_extract", {"urls": [base + "/plain"], "mode": "static"}
            )
        )
        browser = _payload(
            door.call(
                "nbrowser_page_extract", {"urls": [base + "/plain"], "mode": "browser"}
            )
        )
        assert static["documents"][0]["mode_used"] == "static"
        assert browser["documents"][0]["mode_used"] == "browser"
        assert static["documents"][0]["markdown"] == browser["documents"][0]["markdown"]
        assert static["documents"][0]["markdown"].startswith(
            "# Title\n\nHello bold world\n\none\n\n[Next]("
        )
        redirected = _payload(
            door.call("nbrowser_page_extract", {"urls": [base + "/r"], "mode": "auto"})
        )
        assert redirected["documents"][0]["mode_used"] == "browser"
        assert redirected["documents"][0]["markdown"].startswith("# Title")
        for path, expected in (
            ("/unclosed", "Hello"),
            ("/siblings", "a\n\nb\n\nc\n\nd"),
        ):
            static_open = _payload(
                door.call(
                    "nbrowser_page_extract", {"urls": [base + path], "mode": "static"}
                )
            )
            browser_open = _payload(
                door.call(
                    "nbrowser_page_extract", {"urls": [base + path], "mode": "browser"}
                )
            )
            assert static_open["documents"][0]["markdown"] == expected
            assert browser_open["documents"][0]["markdown"] == expected
        before_missing = navigation_count()
        assert before_missing > 0  # the tracer witnessed real prior browser calls
        missing = door.call(
            "nbrowser_page_extract", {"urls": [base + "/missing"], "mode": "auto"}
        )
        assert (
            missing["isError"] is True
            and _payload(missing)["code"] == "content_unavailable"
        )
        assert navigation_count() == before_missing  # zero CDP navigation for this 404
        shown_error = _payload(
            door.call(
                "nbrowser_page_extract",
                {"urls": [base + "/missing"], "mode": "browser"},
            )
        )
        assert shown_error["documents"][0]["mode_used"] == "browser"
        assert shown_error["documents"][0]["markdown"] == "missing"
        assert navigation_count() == before_missing + 1
        assert _payload(door.call("nbrowser_session_show", {}))["tabs_count"] == 0
    finally:
        door.close()
        site.shutdown()
