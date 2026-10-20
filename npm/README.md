# @nott/nbrowser

Node.js wrapper for [nBROWSER](https://github.com/menot-you/n-browser).
Use the source wrapper after you install the Python workspace.

## Prerequisites

- Node.js `>= 18.0.0`.
- Python `>= 3.14` and `uv`.
- An approved source checkout or archive with its root lockfile.

## Installation

Follow the installation guide linked from the [component guide](../README.md).
Run these commands from the public source repository root:

```bash
uv sync --group dev
uv run nbrowser --help
node npm/bin/nbrowser.js --help
```

Keep the root layout and lockfile intact.
Source installation does not register an MCP server or supply a browser engine.

## Binaries

This package exposes one executable wrapper, `nbrowser`.
It forwards arguments to `uv run nbrowser`.
If `uv` is absent, it searches PATH for `nbrowser`.

`nbrowser mcp serve` starts the MCP server.
`nbrowser --help` lists every command.
