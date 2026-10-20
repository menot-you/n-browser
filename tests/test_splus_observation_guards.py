"""Native observation guards."""

import pytest
from nott_spine import ReceiptRung, TaintClass

from nbrowser.extract import SnapshotEvidence
from nbrowser.sanitize import redact_asset_url_keep_path
from nbrowser.semantic import SemanticView


@pytest.mark.parametrize(
    "value,expected",
    [
        ("[inline-data-redacted]", "[inline-data-redacted]"),
        ("data:image/png,secret", "[inline-data-redacted]"),
        ("https://[", "[invalid-url]"),
    ],
)
def test_asset_url_preflight(value: str, expected: str) -> None:
    assert redact_asset_url_keep_path(value) == expected


def test_tools_list_is_wire_visible() -> None:
    from nbrowser.main import SDK_TOOLS
    from nbrowser.mcp_server import TOOL_NAMES, McpServer

    server = McpServer()
    server.last_snapshot = SnapshotEvidence(
        SemanticView(url="https://fixture.test", title="T", visible_text="body"),
        "digest",
        TaintClass.PageDerived,
        ReceiptRung.UnwitnessedLocal,
        "tainted",
    )
    try:
        assert {tool.name for tool in SDK_TOOLS} == set(TOOL_NAMES)
    finally:
        server.close()
