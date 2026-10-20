"""nbrowser: `nbrowser <noun> <verb>`; `mcp serve` is the MCP server, stdio or HTTP.

`COMMANDS` is the only list of commands. `tools/organization.py` reads its keys by AST
against the declared grammar, the help is rendered from it, and every handler is a
`cmd_<noun>_<verb>` bound in it exactly once (`tests/test_commands.py`). A spelling that
is not in the table is an unknown command: there are no aliases, and a bare `nbrowser`
is a usage error rather than a server.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from typing import Final, NamedTuple

from nott_netdoor.http import ApiKey, bind, parse

from . import auth
from .errors import InputFailure
from .main import serve_http, serve_stdio
from .mcp_server import McpServer


def _flags(noun: str, verb: str) -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog=f"nbrowser {noun} {verb}", description=COMMANDS[(noun, verb)].summary
    )


def cmd_page_snapshot(args: list[str]) -> int:
    parser = _flags("page", "snapshot")
    parser.add_argument("url", help="Target URL")
    options = parser.parse_args(args)
    server = McpServer()
    server.handle_tool_call("nbrowser_page_navigate", {"host_url": options.url})
    snap_res = server.handle_tool_call("nbrowser_page_snapshot", {})
    print(json.dumps(snap_res, indent=2, ensure_ascii=False))
    server.close()
    return 0


def cmd_page_scrape(args: list[str]) -> int:
    parser = _flags("page", "scrape")
    parser.add_argument("url", help="Target URL")
    parser.add_argument(
        "--format",
        choices=["prompt", "markdown", "design", "components"],
        default="markdown",
        help="Output format",
    )
    parser.add_argument(
        "--max-content-bytes", type=int, default=65536, help="Byte ceiling"
    )
    options = parser.parse_args(args)
    server = McpServer()
    scrape_res = server.handle_tool_call(
        "nbrowser_page_scrape",
        {
            "host_url": options.url,
            "format": options.format,
            "max_content_bytes": options.max_content_bytes,
        },
    )
    print(json.dumps(scrape_res, indent=2, ensure_ascii=False))
    server.close()
    return 0


def cmd_mcp_serve(args: list[str]) -> int:
    parser = _flags("mcp", "serve")
    parser.add_argument("--http-listen", help="loopback host:port for the HTTP door")
    parser.add_argument("--api-key-file", help="bearer key file for the HTTP door")
    options = parser.parse_args(args)
    if options.http_listen and not options.api_key_file:
        print("--http-listen requires --api-key-file", file=sys.stderr)
        return 1
    server = McpServer()
    try:
        if options.http_listen:
            key = ApiKey.load(options.api_key_file)
            listener = bind(parse(options.http_listen))
            print(f"nbrowser serving http on {options.http_listen}", file=sys.stderr)
            serve_http(server, listener, key)
        else:
            serve_stdio(server)
    finally:
        server.close()
    return 0


def cmd_credential_add(args: list[str]) -> int:
    parser = _flags("credential", "add")
    parser.add_argument("name", help="Profile name")
    parser.add_argument("--url", required=True, help="Login URL")
    parser.add_argument("--username", required=True, help="Username")
    options = parser.parse_args(args)
    password = sys.stdin.read().rstrip("\r\n")
    if not password:
        print(
            f"credential add: {InputFailure.OPERATION.value}: password on stdin is empty",
            file=sys.stderr,
        )
        return 2
    saved = auth.save_profile(
        name=options.name,
        url=options.url,
        username=options.username,
        password=password,
        allow_live_store=True,
    )
    print(json.dumps(saved, indent=2, ensure_ascii=False))
    return 0


def cmd_credential_list(args: list[str]) -> int:
    parser = _flags("credential", "list")
    parser.parse_args(args)
    profiles = auth.list_profiles(allow_live_store=True)
    print(json.dumps({"profiles": profiles}, indent=2, ensure_ascii=False))
    return 0


def cmd_credential_remove(args: list[str]) -> int:
    parser = _flags("credential", "remove")
    parser.add_argument("name", help="Profile name")
    options = parser.parse_args(args)
    removed = auth.remove_profile(options.name, allow_live_store=True)
    print(
        json.dumps(
            {"name": options.name, "removed": removed}, indent=2, ensure_ascii=False
        )
    )
    return 0 if removed else 1


# --- the table ---------------------------------------------------------------------


class Command(NamedTuple):
    synopsis: str
    summary: str
    handler: Callable[[list[str]], int]


COMMANDS: Final[dict[tuple[str, str], Command]] = {
    ("page", "snapshot"): Command(
        "<url>",
        "navigate to a URL and print its semantic snapshot",
        cmd_page_snapshot,
    ),
    ("page", "scrape"): Command(
        "<url> [--format prompt|markdown|design|components] [--max-content-bytes N]",
        "scrape a URL as markdown, design, components or prompt",
        cmd_page_scrape,
    ),
    ("mcp", "serve"): Command(
        "[--http-listen <host:port> --api-key-file <path>]",
        "serve the MCP tools on stdio, or over HTTP behind a bearer key",
        cmd_mcp_serve,
    ),
    ("credential", "add"): Command(
        "<name> --url <url> --username <user>",
        "encrypt and store a login credential profile in the vault",
        cmd_credential_add,
    ),
    ("credential", "list"): Command(
        "",
        "list stored credential profiles without exposing passwords",
        cmd_credential_list,
    ),
    ("credential", "remove"): Command(
        "<name>",
        "remove a stored credential profile from the vault",
        cmd_credential_remove,
    ),
}

USAGE: Final = (
    "usage: nbrowser <noun> <verb> [arguments]   (nbrowser --help lists every command)"
)


def render_help() -> str:
    """The help, generated from COMMANDS in table order."""
    lines = [USAGE, ""]
    for (noun, verb), command in COMMANDS.items():
        head = f"nbrowser {noun} {verb} {command.synopsis}".rstrip()
        lines.append(f"  {head}\n      {command.summary}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    match args:
        case ["--help" | "-h" | "help"]:
            print(render_help())
            return 0
        case [noun, verb, *rest] if (noun, verb) in COMMANDS:
            return COMMANDS[(noun, verb)].handler(rest)
        case []:
            sys.stderr.write(f"nbrowser: {USAGE}\n")
            return 2
        case _:
            sys.stderr.write(
                f"unknown command: nbrowser {' '.join(args[:2])}\n{USAGE}\n"
            )
            return 2


if __name__ == "__main__":
    sys.exit(main())
