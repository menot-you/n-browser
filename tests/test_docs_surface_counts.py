"""Check the public tool count and numbered catalog."""

import re
from pathlib import Path

from nbrowser.mcp_server import TOOL_NAMES

MEMBER = Path(__file__).resolve().parent.parent


def test_docs_state_the_measured_surface() -> None:
    declared = len(TOOL_NAMES)
    reference = next(
        path
        for path in (
            MEMBER / "docs/REFERENCE.md",
            MEMBER.parents[1] / "docs/components/nbrowser/REFERENCE.md",
        )
        if path.is_file()
    )
    reference_text = reference.read_text(encoding="utf-8")
    assert f"{declared} declared, **{declared} with a handler**." in reference_text
    assert (
        f"## MCP Tools ({declared} declared, {declared} with a handler)"
        in reference_text
    )
    listed = re.findall(r"^\d+\. `([a-z_]+)`", reference_text, flags=re.MULTILINE)
    assert listed == list(TOOL_NAMES)
    assert "nbrowser_fixture_upload_source" not in reference_text
