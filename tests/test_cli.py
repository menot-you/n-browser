"""Tests for the nbrowser CLI commands.

Commands:
- page snapshot
- page scrape
- mcp serve
"""

from __future__ import annotations

from io import StringIO
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from nott_netdoor.http import NotLoopbackError

from nbrowser import auth
from nbrowser.cli import main
from nbrowser.content_custody import FixtureContentResolver


def test_cli_snapshot_subcommand() -> None:
    fake_snap = {
        "view": {"url": "https://example.com", "title": "Example Title"},
        "digest": "snap-digest-123",
    }
    with (
        patch("nbrowser.cli.McpServer") as mock_server_cls,
        patch("sys.stdout", new_callable=StringIO) as mock_stdout,
    ):
        mock_server = MagicMock()
        mock_server.handle_tool_call.side_effect = [
            {"status": "navigated"},
            fake_snap,
        ]
        mock_server_cls.return_value = mock_server
        rc = main(["page", "snapshot", "https://example.com"])
        assert rc == 0
        out = mock_stdout.getvalue()
        assert "snap-digest-123" in out
        assert "Example Title" in out


def test_cli_scrape_subcommand() -> None:
    fake_scrape = {
        "format": "markdown",
        "markdown": "# Example Title\n\nPage text",
    }
    with (
        patch("nbrowser.cli.McpServer") as mock_server_cls,
        patch("sys.stdout", new_callable=StringIO) as mock_stdout,
    ):
        mock_server = MagicMock()
        mock_server.handle_tool_call.return_value = fake_scrape
        mock_server_cls.return_value = mock_server
        rc = main(["page", "scrape", "https://example.com", "--format", "markdown"])
        assert rc == 0
        out = mock_stdout.getvalue()
        assert "Example Title" in out


def test_cli_serve_subcommand() -> None:
    with (
        patch("nbrowser.cli.McpServer") as mock_server_cls,
        patch("nbrowser.cli.serve_stdio") as mock_stdio,
    ):
        mock_server = MagicMock()
        mock_server_cls.return_value = mock_server
        rc = main(["mcp", "serve"])
        assert rc == 0
        mock_stdio.assert_called_once()


def test_cli_empty_args_serve_nothing() -> None:
    """A bare `nbrowser` is a usage error: the server is `mcp serve`, by name."""
    with (
        patch("nbrowser.cli.McpServer") as mock_server_cls,
        patch("nbrowser.cli.serve_stdio") as mock_stdio,
        patch("sys.stderr", new_callable=StringIO) as mock_stderr,
    ):
        rc = main([])
        assert rc == 2
        assert "usage: nbrowser" in mock_stderr.getvalue()
        mock_server_cls.assert_not_called()
        mock_stdio.assert_not_called()


def test_cli_http_listen_missing_key() -> None:
    with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        rc = main(["mcp", "serve", "--http-listen", "127.0.0.1:9999"])
        assert rc == 1
        assert "--http-listen requires --api-key-file" in mock_stderr.getvalue()


def test_cli_http_listen_serves(tmp_path: Any) -> None:
    keyfile = tmp_path / "key.txt"
    keyfile.write_text("secret_test_key\n", encoding="utf-8")
    with (
        patch("nbrowser.cli.McpServer") as mock_server_cls,
        patch("nbrowser.cli.serve_http") as mock_http,
        patch("sys.stderr", new_callable=StringIO),
    ):
        rc = main(
            [
                "mcp",
                "serve",
                "--http-listen",
                "127.0.0.1:0",
                "--api-key-file",
                str(keyfile),
            ]
        )
        assert rc == 0
        mock_http.assert_called_once()
        listener = mock_http.call_args.args[1]
        assert listener.getsockname()[0] == "127.0.0.1"
        mock_server_cls.return_value.close.assert_called_once()


def test_cli_http_listen_refuses_a_public_address(tmp_path: Any) -> None:
    keyfile = tmp_path / "key.txt"
    keyfile.write_text("secret_test_key\n", encoding="utf-8")
    with pytest.raises(NotLoopbackError):
        main(
            [
                "mcp",
                "serve",
                "--http-listen",
                "0.0.0.0:8888",
                "--api-key-file",
                str(keyfile),
            ]
        )


def test_credential_add_refuses_an_empty_stdin_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty stdin read (</dev/null) is an input failure: non-zero exit, nothing stored."""
    store_dir = tmp_path / "db"
    store_dir.mkdir(mode=0o700)
    monkeypatch.setenv("NOTT_DATABASE_DIR", str(store_dir))
    with patch("sys.stdin", StringIO("")):
        rc = main(
            [
                "credential",
                "add",
                "my-app",
                "--url",
                "https://app.example.com/login",
                "--username",
                "alice",
            ]
        )
    # A refused input is exit 2 under the D18 codes, not a generic failure.
    assert rc == 2
    assert "password on stdin" in capsys.readouterr().err
    assert auth.list_profiles() == []


def test_text_artifact_pages_decode_exactly_once() -> None:
    """A 1 MiB text artifact read at 20 000 characters must decode once, not per page."""

    class CountingBytes(bytes):
        decodes = 0

        def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
            CountingBytes.decodes += 1
            return super().decode(encoding, errors)

    resolver = FixtureContentResolver()
    body = CountingBytes(("a" * (1024 * 1024)).encode("utf-8"))
    resolver.store_bytes("artifact:1mib", body, "text")
    offset = 0
    pages = 0
    while True:
        _, next_offset, _ = resolver.resolve_text_page("artifact:1mib", offset, 20000)
        pages += 1
        if next_offset is None:
            break
        offset = next_offset
    assert pages == 53
    assert CountingBytes.decodes == 1
