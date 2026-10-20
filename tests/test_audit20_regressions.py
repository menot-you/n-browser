"""Regressions for audit corrections 17, 18, and 20."""

import io
import json
import socket
import ssl
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any, Self

import pytest
from cdp_double import CdpDouble, FakePage
from test_ssrf_runtime import _Engine

from nbrowser import egress_proxy, transfer
from nbrowser.errors import BrowserError, ClosedFailure, FailureCode
from nbrowser.mcp_server import McpServer
from nbrowser.session import BrowserLaunchConfig, BrowserSession


class _Socket:
    def __init__(self, connections: list[tuple[Any, ...]]) -> None:
        self.connections = connections

    def settimeout(self, timeout: object) -> None:
        pass

    def setsockopt(self, *args: object) -> None:
        pass

    def connect(self, address: tuple[Any, ...]) -> None:
        self.connections.append(address)

    def sendall(self, data: bytes) -> None:
        pass

    def makefile(self, *args: object) -> io.BytesIO:
        return io.BytesIO(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            b"Content-Type: text/plain\r\nConnection: close\r\n\r\nok"
        )

    def close(self) -> None:
        pass


def _transport(
    monkeypatch: pytest.MonkeyPatch, answers: list[str]
) -> tuple[list[tuple[Any, ...]], list[str]]:
    connections: list[tuple[Any, ...]] = []
    lookups: list[str] = []

    def resolve(host: str, port: int, *args: object, **kwargs: object) -> list[Any]:
        lookups.append(host)
        return [
            (
                socket.AF_INET6 if ":" in ip else socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (ip, port, 0, 0) if ":" in ip else (ip, port),
            )
            for ip in answers
        ]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: _Socket(connections))
    monkeypatch.setattr(
        transfer,
        "_OPENER",
        urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            *[
                handler
                for handler in transfer._OPENER.handlers
                if not isinstance(handler, urllib.request.ProxyHandler)
            ],
        ),
    )
    return connections, lookups


@pytest.mark.parametrize(
    "answers",
    [
        ["10.0.0.5"],
        ["169.254.169.254"],
        ["100.64.0.1"],
        ["fd00::1"],
        ["::ffff:10.0.0.5"],
        ["127.0.0.1"],
        ["::1"],
        ["93.184.216.34", "10.0.0.5"],
        ["10.0.0.5", "93.184.216.34"],
    ],
)
def test_downloader_refuses_private_and_mixed_dns_before_connect(
    monkeypatch: pytest.MonkeyPatch, answers: list[str]
) -> None:
    connections, lookups = _transport(monkeypatch, answers)
    with pytest.raises(BrowserError) as error:
        transfer.download_host_page("http://fetch.example/secret")
    assert error.value.code is FailureCode.GRANT_REQUIRED
    assert connections == []
    assert lookups == ["fetch.example"]


def test_downloader_rechecks_dns_and_pins_each_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = ["93.184.216.34"]
    connections, lookups = _transport(monkeypatch, answers)
    assert transfer.download_host_page("http://fetch.example/")[0] == b"ok"
    assert connections == [("93.184.216.34", 80)]
    assert lookups == ["fetch.example"]
    answers[:] = ["10.0.0.5"]
    with pytest.raises(BrowserError) as error:
        transfer.download_host_page("http://fetch.example/next")
    assert error.value.code is FailureCode.GRANT_REQUIRED
    assert connections == [("93.184.216.34", 80)]
    assert lookups == ["fetch.example", "fetch.example"]


@pytest.mark.parametrize("host", ["localhost", "localhost.", "127.0.0.1", "[::1]"])
def test_downloader_keeps_explicit_loopback(
    monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    ip = "::1" if host == "[::1]" else "127.0.0.1"
    connections, _ = _transport(monkeypatch, [ip])
    assert transfer.download_host_page(f"http://{host}/")[0] == b"ok"
    assert connections[0][0] == ip


def test_https_keeps_the_hostname_for_tls_after_pinning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connections, lookups = _transport(monkeypatch, ["93.184.216.34"])
    names: list[str] = []

    def wrap(context: Any, connection: Any, **kwargs: Any) -> Any:
        names.append(kwargs["server_hostname"])
        return connection

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    assert transfer.download_host_page("https://fetch.example/")[0] == b"ok"
    assert names == ["fetch.example"]
    assert connections == [("93.184.216.34", 443)]
    assert lookups == ["fetch.example"]


class _Wire:
    def __init__(self, incoming: bytes) -> None:
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.closed = False

    def recv(self, count: int) -> bytes:
        # Fragment every read to exercise the SOCKS frame reader.
        data = bytes(self.incoming[:1])
        del self.incoming[:1]
        return data

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def settimeout(self, timeout: float) -> None:
        pass

    def shutdown(self, direction: int) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("encoded", "host"),
    [
        (b"\x03\x0epublic.example", "public.example"),
        (b"\x01\x5d\xb8\xd8\x22", "93.184.216.34"),
        (
            b"\x04" + socket.inet_pton(socket.AF_INET6, "2606:4700:4700::1111"),
            "2606:4700:4700::1111",
        ),
    ],
)
def test_proxy_resolves_and_pins_before_tunneling(
    monkeypatch: pytest.MonkeyPatch, encoded: bytes, host: str
) -> None:
    connections, lookups = _transport(monkeypatch, ["93.184.216.34"])
    client = _Wire(b"\x05\x01\x00\x05\x01\x00" + encoded + b"\x01\xbb")
    upstream = _Wire(b"reply")
    destinations: list[tuple[str, int]] = []
    original = egress_proxy.connect_admitted

    def connect(address: tuple[str, int]) -> _Wire:
        destinations.append(address)
        original(address).close()
        return upstream

    monkeypatch.setattr(egress_proxy, "connect_admitted", connect)
    monkeypatch.setattr(
        egress_proxy.select, "select", lambda *args: ([upstream], [], [])
    )
    server = SimpleNamespace(lock=threading.Lock(), stopping=False, connections=set())
    egress_proxy._Handler(client, ("127.0.0.1", 1), server)
    assert destinations == [(host, 443)]
    assert lookups == [host]
    assert connections == [("93.184.216.34", 443)]
    assert bytes(client.sent) == b"\x05\x00\x05\x00\x00\x01" + b"\x00" * 6 + b"reply"
    assert upstream.closed
    assert server.connections == set()


@pytest.mark.parametrize("answers", [["10.0.0.5"], ["93.184.216.34", "10.0.0.5"]])
def test_proxy_refuses_dns_before_a_tunnel_opens(
    monkeypatch: pytest.MonkeyPatch, answers: list[str]
) -> None:
    connections, _ = _transport(monkeypatch, answers)
    client = _Wire(b"\x05\x01\x00\x05\x01\x00\x03\x0epublic.example\x01\xbb")
    server = SimpleNamespace(lock=threading.Lock(), stopping=False, connections=set())
    egress_proxy._Handler(client, ("127.0.0.1", 1), server)
    assert bytes(client.sent) == b"\x05\x00\x05\x02\x00\x01" + b"\x00" * 6
    assert connections == []


def test_proxy_keeps_the_response_after_the_client_finishes_writing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _Wire(b"request")
    upstream = _Wire(b"response")
    ready = iter([[client]] * 8 + [[upstream]] * 9)
    monkeypatch.setattr(
        egress_proxy.select, "select", lambda *args: (next(ready), [], [])
    )
    handler = egress_proxy._Handler.__new__(egress_proxy._Handler)
    handler.request = client
    handler.server = SimpleNamespace(stopping=False)
    handler._relay(upstream)
    assert bytes(upstream.sent) == b"request"
    assert bytes(client.sent) == b"response"


def test_proxy_keeps_the_connection_after_an_idle_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _Wire(b"")
    upstream = _Wire(b"response")
    ready = iter([[]] + [[upstream]] * 9)
    monkeypatch.setattr(
        egress_proxy.select, "select", lambda *args: (next(ready), [], [])
    )
    handler = egress_proxy._Handler.__new__(egress_proxy._Handler)
    handler.request = client
    handler.server = SimpleNamespace(stopping=False)
    handler._relay(upstream)
    assert bytes(client.sent) == b"response"


@pytest.mark.parametrize(
    "frame",
    [
        b"\x04\x01\x00",
        b"\x05\x01\x02",
        b"\x05\x01\x00\x05\x02\x00\x03",
        b"\x05\x01\x00\x05\x03\x00\x03",
        b"\x05\x01\x00\x05\x01\x01\x03",
        b"\x05\x01\x00\x05\x01\x00\x09",
        b"\x05\x01\x00\x05\x01\x00\x03\x00",
        b"\x05\x01\x00\x05\x01\x00\x03\x01\x00",
        b"\x05\x01\x00\x05\x01\x00\x03\x01\xff",
        b"\x05\x01\x00\x05\x01\x00\x01\x7f",
    ],
)
def test_proxy_refuses_unsupported_and_incomplete_frames(
    monkeypatch: pytest.MonkeyPatch, frame: bytes
) -> None:
    connections, lookups = _transport(monkeypatch, ["93.184.216.34"])
    server = SimpleNamespace(lock=threading.Lock(), stopping=False, connections=set())
    client = _Wire(frame)
    egress_proxy._Handler(client, ("127.0.0.1", 1), server)
    assert connections == []
    assert lookups == []
    assert bytes(client.sent) in (
        b"\x05\xff",
        b"\x05\x00\x05\x02\x00\x01" + b"\x00" * 6,
    )


def test_native_launch_requires_the_proxy_and_closes_it_after_launch_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nbrowser import session as module

    closed: list[str] = []

    class Proxy:
        address = "127.0.0.1:12345"

        def close(self) -> None:
            closed.append("proxy")

    profile = SimpleNamespace(
        path="/disposable/profile", close=lambda: closed.append("profile")
    )
    monkeypatch.setattr(module, "EgressProxy", Proxy)
    monkeypatch.setattr(module, "BrowserProfile", lambda: profile)
    monkeypatch.setattr(module, "get_chromium_executable", lambda: "/fixture/chromium")
    monkeypatch.setattr(module.Path, "is_socket", lambda path: True)

    def launch(arguments: list[str], **kwargs: Any) -> None:
        for flag in (
            "--proxy-server=socks5://127.0.0.1:12345",
            "--proxy-bypass-list=<-loopback>",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
            "--disable-quic",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ):
            assert flag in arguments
        raise OSError("Disposable launch failure")

    monkeypatch.setattr(module.subprocess, "Popen", launch)
    with pytest.raises(BrowserError) as error:
        BrowserSession(BrowserLaunchConfig())
    assert error.value.code is ClosedFailure.LAUNCH
    assert closed == ["profile", "proxy"]


def test_proxy_close_releases_each_socket() -> None:
    connection = _Wire(b"")
    closed: list[str] = []
    proxy = egress_proxy.EgressProxy.__new__(egress_proxy.EgressProxy)
    proxy.server = SimpleNamespace(
        lock=threading.Lock(),
        stopping=False,
        connections={connection},
        shutdown=lambda: closed.append("stop"),
        server_close=lambda: closed.append("listener"),
    )
    proxy.thread = SimpleNamespace(join=lambda: closed.append("thread"))
    proxy.close()
    assert connection.closed
    assert proxy.server.stopping
    assert closed == ["stop", "listener", "thread"]


def test_proxy_threads_cannot_keep_an_exiting_consumer_alive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    modes: list[bool] = []
    worker_daemon = egress_proxy._Server.daemon_threads
    server = SimpleNamespace(
        server_address=("127.0.0.1", 12345), serve_forever=lambda: None
    )

    def thread(*, target: Any, daemon: bool = False) -> Any:
        modes.append(daemon)
        return SimpleNamespace(start=lambda: None)

    monkeypatch.setattr(egress_proxy, "_Server", lambda: server)
    monkeypatch.setattr(egress_proxy.threading, "Thread", thread)
    egress_proxy.EgressProxy()
    assert modes == [True]
    assert worker_daemon is True


@pytest.mark.parametrize("mode", ["browser", "auto", "static"])
@pytest.mark.parametrize(
    "url",
    [
        "data:text/html,<p>private</p>",
        "file:///disposable/secret.html",
        "javascript:document.body.textContent",
        "about:blank",
        "blob:https://example.com/id",
        "ftp://example.com/",
        "ws://example.com/",
        "http://10.0.0.5/",
    ],
)
def test_extraction_admits_the_whole_batch_before_any_effect(
    monkeypatch: pytest.MonkeyPatch, mode: str, url: str
) -> None:
    server = McpServer()
    effects: list[str] = []
    double = CdpDouble([])
    session = BrowserSession(BrowserLaunchConfig(), client_factory=lambda: double)

    def get_session() -> BrowserSession:
        effects.append("browser")
        return session

    def static(*args: object, **kwargs: object) -> tuple[str, bool]:
        effects.append("download")
        return "fixture", False

    monkeypatch.setattr(server, "get_session", get_session)
    monkeypatch.setattr("nbrowser.extract._extract_static", static)
    try:
        result = server.call_tool(
            "nbrowser_page_extract",
            {"urls": ["https://example.com/", url], "mode": mode},
        )
        assert result.get("isError") is True
        assert json.loads(result["content"][0]["text"])["code"] == "grant_required"
        assert effects == []
        assert double.sent == []
    finally:
        session.close_session()
        server.close()


def test_evaluation_exception_is_typed_and_does_not_echo_page_text() -> None:
    session = SimpleNamespace(
        client=SimpleNamespace(
            send=lambda *args: {
                "result": {"type": "object", "subtype": "error"},
                "exceptionDetails": {"text": "private-page-value"},
            }
        ),
        mark_active=lambda: None,
        _session_for=lambda tab: "s1",
    )
    with pytest.raises(BrowserError) as error:
        BrowserSession.evaluate(session, "t1", "throw new Error()")
    assert error.value.code is ClosedFailure.PROTOCOL
    assert "private-page-value" not in str(error.value)


def test_cdp_exception_frame_returns_a_tool_failure_over_real_pipes() -> None:
    engine = _Engine()
    server = McpServer()
    server.session = BrowserSession(
        BrowserLaunchConfig(), client_factory=lambda: engine.client
    )
    replies = [
        ("Target.getTargets", {"targetInfos": [{"targetId": "t1", "type": "page"}]}),
        ("Target.attachToTarget", {"sessionId": "s1"}),
        ("Fetch.enable", {}),
        ("Runtime.enable", {}),
        (
            "Runtime.evaluate",
            {
                "result": {"type": "object", "subtype": "error"},
                "exceptionDetails": {"text": "private-page-value"},
            },
        ),
    ]

    def respond() -> None:
        for method, payload in replies:
            frame = engine.frame()
            assert frame["method"] == method
            engine.emit({"id": frame["id"], "result": payload})

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            response = pool.submit(respond)
            result = server.call_tool("nbrowser_page_snapshot", {})
            response.result(timeout=5)
        assert result.get("isError") is True
        assert json.loads(result["content"][0]["text"])["code"] == "engine_failure"
        assert server.last_snapshot is None
        assert "private-page-value" not in json.dumps(result)
    finally:
        server.close()
        engine.close()
        engine.client.reader_thread.join(timeout=2)
        assert not engine.client.reader_thread.is_alive()


@pytest.mark.parametrize("tool", ["nbrowser_page_snapshot", "nbrowser_page_scrape"])
def test_failed_evaluation_preserves_the_last_snapshot(tool: str) -> None:
    class EvaluationFailure(CdpDouble):
        fail = False

        def send(self, method: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
            if method == "Runtime.evaluate" and self.fail:
                return {
                    "result": {"type": "object", "subtype": "error"},
                    "exceptionDetails": {"text": "private-page-value"},
                }
            return super().send(method, *args, **kwargs)

    double = EvaluationFailure([FakePage("https://example.com/", "Fixture", "hello")])
    server = McpServer()
    server.session = BrowserSession(
        BrowserLaunchConfig(), client_factory=lambda: double
    )
    try:
        assert "isError" not in server.call_tool("nbrowser_page_snapshot", {})
        previous = server.last_snapshot
        double.fail = True
        result = server.call_tool(tool, {"format": "markdown"})
        assert result.get("isError") is True
        assert json.loads(result["content"][0]["text"])["code"] == "engine_failure"
        assert server.last_snapshot is previous
        assert "private-page-value" not in json.dumps(result)
    finally:
        server.close()
