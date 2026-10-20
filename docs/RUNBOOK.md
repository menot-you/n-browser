# nBROWSER runbook

Read a web page as compact evidence with explicit browser and network boundaries.
Search credentials are optional. They do not supply the browser runtime.

## Setup

Read [installation](INSTALLATION.md).
Run from the public repository root:

```bash
uv sync --group dev
uv run nbrowser --help
uv run nbrowser mcp serve
```

Register the absolute `.venv/bin/nbrowser` executable with arguments `mcp serve` in the MCP client.
Restart the client. Compare `tools/list` with the [reference](REFERENCE.md).

## Browser prerequisites and configuration

The [runtime selector](../nbrowser/private_root.py) selects the newest regular executable under `~/.cache/nbrowser/fortress/*/tilion`.
There is no system Chromium fallback.
`NOTT_NBROWSER_CHROME_BIN` can select an explicit executable engine.
This override does not prove equivalent behavior for another engine.
The [session launcher](../nbrowser/session.py) requires a user session bus and its service-manager scope.
A source package does not supply those host prerequisites or a browser binary.
If the launcher reports a missing bus or engine, resolve that prerequisite before browser operations.

Static URL extraction can use `mode: static` without Chromium.
The MCP session still checks the URL through the network boundary.
The [provider declarations](../nbrowser/providers/merge.py) name optional search variables:
`ZAI_API_KEY`, `MINIMAX_API_KEY`, `TAVILY_API_KEY`, and `FIRECRAWL_API_KEY`.
Every configured keyed provider can receive the query.
Keep keys in the process environment. Do not place values in commands or reports.
Read [privacy](PRIVACY.md) before enabling a provider.

## First useful result

Choose a public documentation URL that you may access.
Call `nbrowser_page_extract` with `urls` containing that URL and `mode: static`.
Read the returned Markdown and source URL.
For browser evidence, call `nbrowser_page_navigate` with `host_url` set to that URL.
Call `nbrowser_page_snapshot` with `include_cards: true`.
Check its `doc_gen`, element references, and page text.
References belong to that document generation. Read a new snapshot after navigation.
For a CLI scrape, run:

```bash
uv run nbrowser page scrape https://example.com --format markdown
```

The browser CLI requires the browser prerequisites above.
A typed network or engine refusal is not page evidence.

## Operation and failure diagnosis

Use `nbrowser_tab_list` and `nbrowser_session_show` for session state.
Use `nbrowser_console_show` and `nbrowser_network_show` for sanitized metadata.
Use `nbrowser_content_show` with `next_offset` to continue a text artifact.
The last page consumes the reference. Capture references do not expose inline text bytes.

`nbrowser_site_crawl` stays on the seed's scheme, host, and port.
It checks robots rules with user-agent `*` through the SSRF boundary.
A cursor resumes once in the same process.
Each call uses an isolated context and closes it after the call.
The frontier limits navigation. The runtime interceptor judges subresources separately.
The crawl has no Crawl-delay or per-host rate control.

The SSRF guard permits admitted public or loopback hosts.
It refuses private networks, link-local metadata addresses, and rebinding targets.
Do not bypass a refused origin.
For browser failures, check the executable, session bus, and named error.
For search failures, inspect provider status before assuming that the query returned no matches.
See [troubleshooting](TROUBLESHOOTING.md).

## Credentials, backup, and restoration

`nbrowser credential add NAME --url URL --username USER` reads the password from stdin.
The vault encrypts passwords with AES-256-GCM.
`auth_login` fills a profile only on its recorded origin.
The request gate prevents password transmission to another origin for the rest of the session.
This boundary does not authorize a login or form submission.

Close browser sessions before a backup.
Preserve `nbrowser.sqlite3` and `nbrowser.key` together from the account-owned database directory.
Keep their directory private and their files owner-only.
The vault creates its storage when needed. There is no browser database snapshot CLI.
Use a consistent file copy after all vault users stop.
Preserve retained captures separately if their host grant permits them.
Temporary profiles and session references do not form a persistent browser history.

Restore the vault and its original key into an owned disposable account first.
Use the matching runtime. Check `nbrowser credential list` without printing a password.
An encrypted vault without its key cannot restore the login profiles.
Do not overwrite an active account until this check passes.
Keep its previous vault and key until restoration succeeds.
The [vault source](../nbrowser/auth.py) owns the exact file checks.
