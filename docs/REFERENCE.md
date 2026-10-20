# nBROWSER reference

The source declarations own argument types, bounds, defaults, and refusal rules.
Use the installed executable's `--help` and MCP `tools/list` for its effective version.
A declared operation can refuse a missing prerequisite or denied grant.

## CLI commands

Source: [cli.py](../nbrowser/cli.py), `COMMANDS`.
All commands use the executable from the public repository's root workspace.

| Command | Arguments |
| --- | --- |
| `nbrowser page snapshot` | `<url>` |
| `nbrowser page scrape` | `<url> [--format prompt\|markdown\|design\|components] [--max-content-bytes N]` |
| `nbrowser mcp serve` | `[--http-listen <host:port> --api-key-file <path>]` |
| `nbrowser credential add` | `<name> --url <url> --username <user>` |
| `nbrowser credential list` | `None` |
| `nbrowser credential remove` | `<name>` |

## MCP tools

Source: [mcp_server.py](../nbrowser/mcp_server.py), `TOOL_NAMES` and `INPUT_SCHEMAS`.

## MCP Tools (14 declared, 14 with a handler)

14 declared, **14 with a handler**, 0 declared and not implemented.

A handler can return evidence or a typed refusal. A handler does not prove that its host prerequisites exist.

1. `nbrowser_page_snapshot` — Read the document generation, element references, and optional delta.
2. `nbrowser_page_extract` — Extract snapshot text or selected URLs.
3. `nbrowser_page_scrape` — Read Markdown, prompt text, design data, or components.
4. `nbrowser_site_crawl` — Crawl a bounded same-origin frontier with robots checks.
5. `nbrowser_page_interact` — Perform an admitted interaction with flat arguments.
6. `nbrowser_token_extract` — Read design tokens.
7. `nbrowser_console_show` — Read redacted console metadata.
8. `nbrowser_network_show` — Read sanitized network metadata.
9. `nbrowser_page_capture` — Capture PNG under the explicit retention choice.
10. `nbrowser_session_show` — Read local session state.
11. `nbrowser_tab_list` — List tabs with origin-only locations.
12. `nbrowser_page_navigate` — Navigate to an admitted URL.
13. `nbrowser_content_show` — Page session-owned text references.
14. `nbrowser_web_search` — Search the configured keyed providers.

### Input fields

The linked schema gives the complete constraints for these fields.
Conditional requirements still apply when the required column is empty.

| Tool | Required fields | All input fields |
| --- | --- | --- |
| `nbrowser_page_navigate` | host_url | host_url |
| `nbrowser_page_snapshot` | None at the top level | include_cards, delta |
| `nbrowser_page_capture` | retention | retention |
| `nbrowser_content_show` | ref | ref, offset, max_chars |
| `nbrowser_site_crawl` | None at the top level | cursor, host_url, max_content_bytes, max_pages |
| `nbrowser_page_extract` | None at the top level | limit, max_content_bytes, mode, urls, what, outline, filter, content_boundaries |
| `nbrowser_page_interact` | verb | verb, selector, ref, text, value, key, x, y, human, seed |
| `nbrowser_page_scrape` | None at the top level | format, host_url, max_content_bytes, content_boundaries |
| `nbrowser_web_search` | query | max_results, query |

## Evidence and retention

A snapshot returns `view` with `doc_gen`, `@eN` references, and optional delta data.
Content references belong to the session and producer kind.
`nbrowser_content_show` uses character offsets and returns `next_offset` until the last page consumes the reference.
Its default page size is 20000 characters. The maximum is 200000.
Invalid paging preserves the reference. A capture reference returns `content_unavailable` instead of inline bytes.

Capture retention choices are `no_store`, `ephemeral_session`, and `managed_purgeable`.
Managed retention requires the host's explicit capture grant and a safe account-owned capture root.
A grant failure returns `grant_required`. An unsafe capture destination returns `capture_export_failed`.
Do not configure a persistent database override to obtain a retention grant.

Crawl pages default to 25 with a ceiling of 100.
A crawl ends with `exhausted`, `max_pages`, or `deadline`.
Its cursor resumes once in the same process.
The [runbook](RUNBOOK.md) describes robots, origin, subresource, and rate-control limits.

[seam.py](../nbrowser/seam.py) owns the effect boundary.
[egress_guard.py](../nbrowser/egress_guard.py) owns network admission.
[auth.py](../nbrowser/auth.py) owns the encrypted vault and origin checks.
The [runbook](RUNBOOK.md) covers prerequisites, operation, and restoration.
