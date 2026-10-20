"""Check the public tool count, numbered catalog, and unimplemented markers."""

import re
from pathlib import Path

from nbrowser.mcp_server import CAMPAIGN_B_TOOLS, TOOL_NAMES

MEMBER = Path(__file__).resolve().parent.parent


def test_docs_state_the_measured_surface() -> None:
    declared = len(TOOL_NAMES)
    unimplemented = len(CAMPAIGN_B_TOOLS)
    with_handler = declared - unimplemented
    reference = next(
        path
        for path in (
            MEMBER / "docs/REFERENCE.md",
            MEMBER.parents[1] / "docs/components/nbrowser/REFERENCE.md",
        )
        if path.is_file()
    )
    reference_text = reference.read_text(encoding="utf-8")
    assert (
        f"{declared} declared, **{with_handler} with a handler**, "
        f"{unimplemented} declared and not implemented"
    ) in reference_text
    assert (
        f"## MCP Tools ({declared} declared, {with_handler} with a handler)"
        in reference_text
    )
    marked = set(re.findall(r"`(nbrowser_[a-z_]+)` — not implemented", reference_text))
    assert marked == set(CAMPAIGN_B_TOOLS)
    listed = re.findall(r"^\d+\. `([a-z_]+)`", reference_text, flags=re.MULTILINE)
    assert listed == list(TOOL_NAMES)
    assert "nbrowser_fixture_upload_source" not in reference_text
