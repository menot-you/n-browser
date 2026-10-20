"""Surface contract of the nBROWSER MCP door — a DESCENDING RATCHET.

Both fractions below are MEASURED on this tree, not desired. The file lands
GREEN on purpose: the day a tool gains a real handler or a real input schema,
this test turns RED and forces whoever implemented it to delete that name here
and lower the number. Red is progress, never a block.
"""

import ast
from pathlib import Path
from typing import Any, cast

import pytest

from nbrowser import mcp_server
from nbrowser.errors import BrowserError, failure_envelope
from nbrowser.mcp_server import INPUT_SCHEMAS, TOOL_NAMES, TOOLS, McpServer

# Measured: 0 of the 14 declared tools refuse not_implemented. The symbol stays
# so the ratchet has a place to name the next declared-but-unbuilt tool.
UNIMPLEMENTED_TOOLS: frozenset[str] = frozenset()

# Measured: 5 of the 14 announce `inputSchema.properties == {}`, because their
# dispatch branches read no parameters.
EMPTY_SCHEMA_TOOLS = frozenset(
    {
        "nbrowser_console_show",
        "nbrowser_network_show",
        "nbrowser_session_show",
        "nbrowser_tab_list",
        "nbrowser_token_extract",
    }
)

ANNOUNCED: dict[str, dict[str, Any]] = {
    str(t["name"]): cast(dict[str, Any], t["inputSchema"]) for t in TOOLS
}


def test_zero_of_fourteen_tools_are_declared_but_not_implemented() -> None:
    assert len(TOOL_NAMES) == 14
    assert len(UNIMPLEMENTED_TOOLS) == 0
    assert UNIMPLEMENTED_TOOLS <= set(TOOL_NAMES)

    server = McpServer()
    measured: dict[str, object] = {}
    for name in sorted(UNIMPLEMENTED_TOOLS):
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call(name, {})
        measured[name] = failure_envelope(exc.value)["code"]

    # A caller must read "this tool does not exist yet", never "your arguments
    # are wrong" — the two collapsed into invalid_input before this contract.
    assert measured == {name: "not_implemented" for name in sorted(UNIMPLEMENTED_TOOLS)}


def test_five_of_fourteen_tools_announce_an_empty_input_schema() -> None:
    assert len(EMPTY_SCHEMA_TOOLS) == 5
    assert set(TOOL_NAMES) - EMPTY_SCHEMA_TOOLS == {
        "nbrowser_page_capture",
        "nbrowser_content_show",
        "nbrowser_site_crawl",
        "nbrowser_page_extract",
        "nbrowser_page_interact",
        "nbrowser_page_navigate",
        "nbrowser_page_scrape",
        "nbrowser_page_snapshot",
        "nbrowser_web_search",
    }
    assert {
        name: ANNOUNCED[name]["properties"] for name in sorted(EMPTY_SCHEMA_TOOLS)
    } == {name: {} for name in sorted(EMPTY_SCHEMA_TOOLS)}
    # The other jaw: a schema DELETED from INPUT_SCHEMAS falls back to the
    # empty announcement and neither assertion above would notice.
    assert all(
        ANNOUNCED[name]["properties"] for name in set(TOOL_NAMES) - EMPTY_SCHEMA_TOOLS
    )


def test_snapshot_returns_the_whole_view_not_only_its_url() -> None:
    """MEASURED DEFECT: the handler answered `{"view": evidence.view.url}` —
    a caller asking for a semantic snapshot was handed an address."""
    from cdp_double import CdpDouble, FakePage

    from nbrowser.session import BrowserLaunchConfig, BrowserSession

    server = McpServer()
    pages = [FakePage("http://fixture.test/a", "T", "double text")]
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True),
        client_factory=lambda: CdpDouble(pages),
    )
    view = cast(
        dict[str, Any], server.handle_tool_call("nbrowser_page_snapshot", {})["view"]
    )
    assert view["url"] == "http://fixture.test/a"
    assert view["title"] == "T"
    assert view["visible_text"] == "double text"
    assert view["text_blocks"] == ["double text"]
    assert view["state"] == "ready"
    assert [e["selector"] for e in view["elements"]] == ["#x"]


# Every announced top-level parameter must have a reader in its dispatch
# branch, and every parameter read there must be announced.
def _fields_the_handler_reads(tool: str, *, source: str | None = None) -> set[str]:
    """Literal parameter reads in the selected branch and its tool handler."""
    tree = ast.parse(
        Path(mcp_server.__file__).read_text(encoding="utf-8")
        if source is None
        else source
    )
    handler = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "handle_tool_call"
    )
    reads: set[str] = set()
    for branch in handler.body:
        if (
            not isinstance(branch, ast.If)
            or ast.unparse(branch.test) != f"name == {tool!r}"
        ):
            continue
        selected: list[ast.AST] = [branch]
        for node in ast.walk(branch):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "self"
                and node.func.attr.startswith("_tool_")
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "params"
            ):
                selected.append(
                    next(
                        candidate
                        for candidate in ast.walk(tree)
                        if isinstance(candidate, ast.FunctionDef)
                        and candidate.name == node.func.attr
                    )
                )
        for node in (node for root in selected for node in ast.walk(root)):
            match node:
                case (
                    ast.Call(
                        func=ast.Attribute(value=ast.Name(id="params"), attr="get"),
                        args=[ast.Constant(value=str(key)), *_],
                    )
                    | ast.Subscript(
                        value=ast.Name(id="params"), slice=ast.Constant(value=str(key))
                    )
                ):
                    reads.add(key)
    return reads


def test_zero_tools_announce_fields_their_handler_never_reads() -> None:
    mismatches = {}
    for name in sorted(ANNOUNCED):
        declared = set(ANNOUNCED[name].get("properties", {}))
        reads = _fields_the_handler_reads(name)
        if declared != reads:
            mismatches[name] = {
                "declared_minus_read": sorted(declared - reads),
                "read_minus_declared": sorted(reads - declared),
            }
    assert not mismatches, "\n".join(
        f"{name}: {fields}" for name, fields in mismatches.items()
    )


def test_content_get_schema_matches_paging_handler_in_both_directions() -> None:
    schema = INPUT_SCHEMAS["nbrowser_content_show"]
    fields = {"ref", "offset", "max_chars"}
    assert set(schema["properties"]) == fields
    assert _fields_the_handler_reads("nbrowser_content_show") == fields
    assert schema["required"] == ["ref"]
    assert schema["properties"]["offset"]["default"] == 0
    assert schema["properties"]["max_chars"]["default"] == 20000


@pytest.mark.parametrize("delegated", [False, True])
def test_field_reader_follows_only_selected_handler(delegated: bool) -> None:
    body = (
        "return self._tool_selected(params)"
        if delegated
        else 'return params.get("expected")'
    )
    source = f"""
class Door:
    def handle_tool_call(self, name, params):
        if name == 'selected':
            {body}
        if name == 'other':
            return self._tool_other(params)
    def _tool_selected(self, params):
        return params.get("expected")
    def _tool_other(self, params):
        return params.get("undeclared")
"""
    assert _fields_the_handler_reads("selected", source=source) == {"expected"}
    assert _fields_the_handler_reads("other", source=source) == {"undeclared"}
    assert _fields_the_handler_reads("absent", source=source) == set()


def test_field_reader_sees_delegated_undeclared_and_removed_reads() -> None:
    source = """
class Door:
    def handle_tool_call(self, name, params):
        if name == 'selected':
            return self._tool_selected(params)
    def _tool_selected(self, params):
        return params.get("expected"), params["undeclared"]
"""
    assert _fields_the_handler_reads("selected", source=source) == {
        "expected",
        "undeclared",
    }
    changed = source.replace('params.get("expected")', "None")
    assert _fields_the_handler_reads("selected", source=changed) == {"undeclared"}
