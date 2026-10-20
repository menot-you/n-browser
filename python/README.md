# nbrowser (Python Distribution)

Python distribution package for **nBrowser**: compact browser evidence and fixture-proven effects.

## Requirements

- **Python**: `>= 3.14`
- **uv**: `>= 0.12.0` (recommended workspace package manager)

## Installation

Within a `uv` project or workspace:

```bash
uv add nbrowser
```

Or via standard Python package installation:

```bash
pip install nbrowser
```

## CLI & Entrypoints

The package exposes one console script, `nbrowser`. Commands read `nbrowser <noun> <verb>`;
`nbrowser --help` renders them from the one `COMMANDS` table in `nbrowser/cli.py`, and any
other spelling, including a bare `nbrowser`, is a usage error (exit 2):

- `nbrowser page snapshot <url>`: print the semantic snapshot.
- `nbrowser page scrape <url> [--format markdown|design|components|prompt]`
- `nbrowser mcp serve [--http-listen <host:port> --api-key-file <path>]`: the MCP server.

## Architecture

1. **Inner Ring**: Observation and DOM analysis with zero host side-effects.
2. **Effect Ring**: Navigation, page activation and host egress gated behind `AuthoritySeam`.
3. **SSRF Guard**: Strict kernel protection preventing private IP and link-local egress.
