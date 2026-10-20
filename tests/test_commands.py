"""The command table: `nbrowser <noun> <verb>`, one literal COMMANDS dict.

`tools/organization.py` reads COMMANDS by AST; these tests hold what the guard cannot:
every command has its own handler, every handler has a command, the help is derived
from the table, and the pre-table spellings (`browse`, `snapshot`, `scrape`, `serve`, the
root-level `--http-listen`, the flags of the former separate relay program, and the
retired `pilot run` and `relay serve`) are unknown commands rather than aliases. A bare `nbrowser` no longer serves MCP on stdio: it is a
usage error, and `mcp serve` is the server.
"""

from __future__ import annotations

import inspect

import pytest

from nbrowser import cli


def handlers_in_module() -> set[str]:
    return {
        name
        for name, value in vars(cli).items()
        if name.startswith("cmd_") and inspect.isfunction(value)
    }


def test_the_table_is_the_declared_grammar() -> None:
    assert set(cli.COMMANDS) == {
        ("page", "snapshot"),
        ("page", "scrape"),
        ("mcp", "serve"),
        ("credential", "add"),
        ("credential", "list"),
        ("credential", "remove"),
    }


def test_every_command_has_its_own_handler() -> None:
    for (noun, verb), command in cli.COMMANDS.items():
        assert command.handler.__name__ == f"cmd_{noun}_{verb}", (noun, verb)
        assert command.handler is getattr(cli, command.handler.__name__)


def test_every_handler_has_a_command() -> None:
    bound = {command.handler.__name__ for command in cli.COMMANDS.values()}
    assert handlers_in_module() == bound


def test_a_handler_without_a_command_is_seen(monkeypatch: pytest.MonkeyPatch) -> None:
    """Falsifier of the test above: an orphan handler breaks the equality."""

    def cmd_page_orphan(args: list[str]) -> int:
        return 0

    monkeypatch.setattr(cli, "cmd_page_orphan", cmd_page_orphan, raising=False)
    bound = {command.handler.__name__ for command in cli.COMMANDS.values()}
    assert handlers_in_module() != bound


def test_a_command_without_a_handler_is_refused() -> None:
    with pytest.raises(TypeError):
        cli.Command("<x>", "no handler")  # type: ignore[call-arg]


def test_help_is_rendered_from_the_table(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    for (noun, verb), command in cli.COMMANDS.items():
        assert f"nbrowser {noun} {verb} {command.synopsis}".rstrip() in out
        assert command.summary in out


@pytest.mark.parametrize(
    "argv",
    [
        ["browse", "https://example.com"],
        ["snapshot", "https://example.com"],
        ["scrape", "https://example.com"],
        ["serve"],
        ["--http-listen", "127.0.0.1:1", "--api-key-file", "/nonexistent"],
        ["--port", "8080", "--no-qr"],
        ["pilot", "run", "https://example.com"],
        ["relay", "serve"],
    ],
)
def test_the_old_spellings_are_unknown(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("unknown command: nbrowser"), captured.err


def test_bare_nbrowser_is_a_usage_error_not_a_server(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main([]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage: nbrowser" in captured.err


def test_the_member_declares_one_executable() -> None:
    import tomllib
    from pathlib import Path

    member = Path(__file__).resolve().parents[1]
    scripts = tomllib.loads((member / "pyproject.toml").read_text())["project"][
        "scripts"
    ]
    assert scripts == {"nbrowser": "nbrowser.cli:main"}
