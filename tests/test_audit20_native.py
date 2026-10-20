"""Native connection proof. Run on a host with Chromium and loopback sockets."""

import http.server
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from nbrowser import egress_proxy
from nbrowser.errors import BrowserError
from nbrowser.mcp_server import McpServer
from nbrowser.session import BrowserLaunchConfig, BrowserSession, CdpPipeClient
from nbrowser.transfer import download_host_page

PUBLIC_IP = "93.184.216.34"
PRIVATE_IP = "10.0.0.5"


@pytest.fixture
def site(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[int, list[tuple[str, str]], dict[str, list[str]]]]:
    hits: list[tuple[str, str]] = []
    answers = {
        "public.example": [PUBLIC_IP],
        "other.example": [PUBLIC_IP],
        "private.example": [PRIVATE_IP],
        "mixed.example": [PUBLIC_IP, PRIVATE_IP],
        "rebind.example": [PUBLIC_IP],
        "popup.example": [PRIVATE_IP],
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hits.append((self.headers.get("Host", ""), self.path))
            if self.path.startswith("/redirect-"):
                host = self.path.removeprefix("/redirect-")
                self.send_response(302)
                self.send_header(
                    "Location", f"http://{host}:{self.server.server_port}/landing"
                )
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            if self.path == "/nested-public":
                self.wfile.write(
                    (
                        "<html><body><script>const child = document.createElement('iframe');"
                        "child.onload = () => { const image = child.contentDocument.createElement('img');"
                        "image.referrerPolicy = 'no-referrer';"
                        f"image.src = 'http://127.0.0.1:{self.server.server_port}/landing';"
                        "child.contentDocument.body.append(image); };"
                        "child.src = 'about:blank'; document.body.append(child);</script></body></html>"
                    ).encode()
                )
                return
            self.wfile.write(
                b"<html><head><link rel='icon' href='data:,'></head>"
                b"<body><p>Public control</p></body></html>"
            )

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    original_resolve = socket.getaddrinfo
    original_connect = socket.socket.connect

    def resolve(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        if host in answers:
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))
                for ip in answers[host]
            ]
        return original_resolve(host, port, *args, **kwargs)

    def connect(sock: socket.socket, address: Any) -> None:
        # Only the test transport maps fixture addresses to the disposable server.
        if address[0] in (PUBLIC_IP, PRIVATE_IP):
            address = ("127.0.0.1", address[1])
        original_connect(sock, address)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket.socket, "connect", connect)
    try:
        yield server.server_port, hits, answers
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


def test_downloader_uses_only_admitted_dns_at_the_local_service(
    site: tuple[int, list[tuple[str, str]], dict[str, list[str]]],
) -> None:
    port, hits, answers = site
    assert b"Public control" in download_host_page(f"http://public.example:{port}/")[0]
    for host in ("private.example", "mixed.example"):
        with pytest.raises(BrowserError):
            download_host_page(f"http://{host}:{port}/secret")
    assert b"Public control" in download_host_page(f"http://rebind.example:{port}/")[0]
    answers["rebind.example"] = [PRIVATE_IP]
    with pytest.raises(BrowserError):
        download_host_page(f"http://rebind.example:{port}/secret")
    with pytest.raises(BrowserError):
        download_host_page(f"http://public.example:{port}/redirect-private.example")
    assert all(path not in ("/secret", "/landing") for _, path in hits)
    assert any(host == f"public.example:{port}" for host, _ in hits)


def test_chromium_guards_dns_subresources_redirects_and_new_targets(
    site: tuple[int, list[tuple[str, str]], dict[str, list[str]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port, hits, answers = site
    popup_refused = threading.Event()
    original_connect = egress_proxy.connect_admitted

    def connect(address: tuple[str, int]) -> socket.socket:
        try:
            return original_connect(address)
        except BrowserError:
            if address[0] == "popup.example":
                popup_refused.set()
            raise

    monkeypatch.setattr(egress_proxy, "connect_admitted", connect)
    session = BrowserSession(BrowserLaunchConfig(headless=True))
    try:
        tab = session.tabs_open(f"http://public.example:{port}/")
        assert "Public control" in session.evaluate(tab, "document.body.textContent")
        for host in ("private.example", "mixed.example"):
            result = session.evaluate(
                tab,
                f"fetch('http://{host}:{port}/secret').then(() => 'sent', () => 'blocked')",
                await_promise=True,
            )
            assert result == "blocked"
        session.navigate(tab, f"http://public.example:{port}/redirect-other.example")
        assert session.evaluate(tab, "location.hostname") == "other.example"
        for host in ("private.example", "mixed.example", "127.0.0.1"):
            with pytest.raises(BrowserError):
                session.navigate(tab, f"http://public.example:{port}/redirect-{host}")
        session.navigate(tab, f"http://rebind.example:{port}/")
        answers["rebind.example"] = [PRIVATE_IP]
        with pytest.raises(BrowserError):
            session.navigate(tab, f"http://rebind.example:{port}/secret")
        session.navigate(tab, f"http://public.example:{port}/")
        targets = set(session.tabs_list())
        assert session.client is not None
        popup = session.client.send(
            "Runtime.evaluate",
            {
                "expression": f"window.open('http://popup.example:{port}/secret', '_blank') !== null",
                "userGesture": True,
                "returnByValue": True,
            },
            session._session_for(tab),
        )
        assert popup["result"]["value"] is True, "The page did not open a popup"
        assert set(session.tabs_list()) - targets, "The popup has no page target"
        assert popup_refused.wait(timeout=5), (
            "The new target did not reach the connection gate"
        )
        # A later admitted navigation proves the proxy can still complete requests.
        session.tabs_open(f"http://other.example:{port}/control")
        assert all(path != "/secret" for _, path in hits)
        assert not any(
            host.startswith(
                ("private.example:", "mixed.example:", "popup.example:", "127.0.0.1:")
            )
            for host, _ in hits
        )
        assert any(host == f"public.example:{port}" for host, _ in hits)
        assert any(host == f"other.example:{port}" for host, _ in hits)
    finally:
        session.close_session()


def test_native_extraction_refuses_a_local_file_and_keeps_public_documents(
    site: tuple[int, list[tuple[str, str]], dict[str, list[str]]], tmp_path: Path
) -> None:
    port, hits, _ = site
    secret = tmp_path / "secret.html"
    secret.write_text("<p>Disposable private text</p>")
    server = McpServer()
    try:
        result = server.call_tool(
            "nbrowser_page_extract", {"urls": [secret.as_uri()], "mode": "browser"}
        )
        assert result.get("isError") is True
        assert server.session is None
        assert hits == []
        result = server.call_tool(
            "nbrowser_page_extract",
            {"urls": [f"http://public.example:{port}/"], "mode": "browser"},
        )
        assert not result.get("isError")
        assert "Public control" in result["content"][0]["text"]
    finally:
        server.close()


@pytest.mark.parametrize(
    "path", ["/preview", "/a/../preview", "/%2e/preview", "/a/../preview#owner"]
)
def test_local_navigation_keeps_browser_url_normalization(
    site: tuple[int, list[tuple[str, str]], dict[str, list[str]]], path: str
) -> None:
    port, hits, _ = site
    session = BrowserSession(BrowserLaunchConfig(headless=True))
    try:
        tab = session.tabs_open(f"http://127.0.0.1:{port}{path}")
        assert "Public control" in session.evaluate(tab, "document.body.textContent")
        assert (f"127.0.0.1:{port}", "/preview") in hits
    finally:
        session.close_session()


@pytest.mark.parametrize("effect", ["popup", "image", "iframe", "nested"])
def test_public_redirect_cannot_reach_loopback(
    site: tuple[int, list[tuple[str, str]], dict[str, list[str]]],
    monkeypatch: pytest.MonkeyPatch,
    effect: str,
) -> None:
    port, hits, _ = site
    refused = threading.Event()
    blocked_requests: set[str] = set()
    original_resolve = CdpPipeClient._resolve_paused
    original_post = CdpPipeClient._post
    original_connect = socket.socket.connect
    local_connections: list[Any] = []

    def connect(sock: socket.socket, address: Any) -> None:
        if address == ("127.0.0.1", port):
            local_connections.append(address)
        original_connect(sock, address)

    def resolve(client: CdpPipeClient, event: dict[str, Any]) -> None:
        if event["params"]["request"]["url"] == f"http://127.0.0.1:{port}/landing":
            blocked_requests.add(event["params"]["requestId"])
        original_resolve(client, event)

    def post(
        client: CdpPipeClient,
        method: str,
        params: dict[str, Any] | None,
        session_id: str | None,
    ) -> int:
        result = original_post(client, method, params, session_id)
        if (
            method == "Fetch.failRequest"
            and params
            and params["requestId"] in blocked_requests
        ):
            refused.set()
        return result

    monkeypatch.setattr(CdpPipeClient, "_resolve_paused", resolve)
    monkeypatch.setattr(CdpPipeClient, "_post", post)
    monkeypatch.setattr(socket.socket, "connect", connect)
    session = BrowserSession(BrowserLaunchConfig(headless=True))
    try:
        host = "127.0.0.1" if effect == "nested" else "public.example"
        tab = session.tabs_open(f"http://{host}:{port}/")
        assert "Public control" in session.evaluate(tab, "document.body.textContent")
        initial_hits = len(hits)
        initial_connections = len(local_connections)
        targets = set(session.tabs_list())
        path = "/nested-public" if effect == "nested" else "/redirect-127.0.0.1"
        url = f"http://public.example:{port}{path}"
        if effect == "popup":
            expression = f"window.open('{url}', '_blank') !== null"
        else:
            tag = "img" if effect == "image" else "iframe"
            expression = (
                f"(() => {{ const element = document.createElement('{tag}');"
                "element.referrerPolicy = 'no-referrer';"
                f"element.src = '{url}'; document.body.append(element); return true; }})()"
            )
        assert session.client is not None
        result = session.client.send(
            "Runtime.evaluate",
            {"expression": expression, "userGesture": True, "returnByValue": True},
            session._session_for(tab),
        )
        assert result["result"]["value"] is True
        if effect == "popup":
            assert set(session.tabs_list()) - targets, "The popup has no page target"
        observed_refusal = refused.wait(timeout=5)
        assert (f"public.example:{port}", path) in hits
        assert not any(
            host == f"127.0.0.1:{port}" for host, _ in hits[initial_hits:]
        ), hits
        assert len(local_connections) == initial_connections
        assert observed_refusal, "The redirect did not reach the request gate"
        session.navigate(tab, f"http://127.0.0.1:{port}/explicit-local")
        assert "Public control" in session.evaluate(tab, "document.body.textContent")
        assert (f"127.0.0.1:{port}", "/explicit-local") in hits
        assert local_connections
        session.navigate(tab, f"http://public.example:{port}/public-control")
        assert "Public control" in session.evaluate(tab, "document.body.textContent")
        session.navigate(tab, f"http://127.0.0.1:{port}#preview")
        assert "Public control" in session.evaluate(tab, "document.body.textContent")
    finally:
        session.close_session()
