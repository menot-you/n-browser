"""A session-owned SOCKS5 connection gate for Chromium."""

import select
import socket
import socketserver
import threading
from typing import Any

from .egress_guard import connect_admitted
from .errors import BrowserError


def _read(connection: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise ConnectionError("Proxy peer closed")
        data.extend(chunk)
    return bytes(data)


class _Handler(socketserver.BaseRequestHandler):
    server: _Server
    request: socket.socket

    def handle(self) -> None:
        self.request.settimeout(12.0)
        try:
            version, count = _read(self.request, 2)
            methods = _read(self.request, count)
            if version != 5 or 0 not in methods:
                self.request.sendall(b"\x05\xff")
                return
            self.request.sendall(b"\x05\x00")
            version, command, reserved, kind = _read(self.request, 4)
            if version != 5 or command != 1 or reserved != 0:
                raise ValueError("Proxy command refused")
            if kind == 1:
                host = socket.inet_ntop(socket.AF_INET, _read(self.request, 4))
            elif kind == 4:
                host = socket.inet_ntop(socket.AF_INET6, _read(self.request, 16))
            elif kind == 3:
                host = _read(self.request, _read(self.request, 1)[0]).decode("ascii")
                if not host or "\x00" in host:
                    raise ValueError("Proxy hostname refused")
            else:
                raise ValueError("Proxy address refused")
            port = int.from_bytes(_read(self.request, 2), "big")
            with connect_admitted((host, port)) as upstream:
                with self.server.lock:
                    if self.server.stopping:
                        return
                    self.server.connections.add(upstream)
                try:
                    self.request.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
                    self._relay(upstream)
                finally:
                    with self.server.lock:
                        self.server.connections.discard(upstream)
        except OSError, ValueError, BrowserError:
            try:
                self.request.sendall(b"\x05\x02\x00\x01" + b"\x00" * 6)
            except OSError:
                pass

    def _relay(self, upstream: socket.socket) -> None:
        peers = {self.request: upstream, upstream: self.request}
        sources = list(peers)
        while not self.server.stopping:
            ready, _, _ = select.select(sources, [], [], 30.0)
            for source in ready:
                data = source.recv(65536)
                if not data:
                    if source is upstream:
                        return
                    upstream.shutdown(socket.SHUT_WR)
                    sources.remove(source)
                    continue
                peers[source].sendall(data)


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.connections: set[socket.socket] = set()
        self.slots = threading.BoundedSemaphore(32)
        self.stopping = False
        super().__init__(("127.0.0.1", 0), _Handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self.lock:
            if self.stopping:
                self.slots.release()
                self.shutdown_request(request)
                return
            self.connections.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.lock:
                self.connections.discard(request)
            self.slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.lock:
                self.connections.discard(request)
            self.slots.release()


class EgressProxy:
    def __init__(self) -> None:
        self.server = _Server()
        self.address = f"127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        try:
            self.thread.start()
        except BaseException:
            self.server.server_close()
            raise

    def close(self) -> None:
        with self.server.lock:
            self.server.stopping = True
            for connection in self.server.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
