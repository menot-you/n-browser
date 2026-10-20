"""The instructions the MCP serves say WHEN to use this, not only what it is.

Measured 2026-09-16 over 87,551 calls in the owner's real sessions: nMEMORY, whose
description opens with triggers, got 5,064 calls across 189 sessions; this server,
whose description was 61 bytes saying what it is, got 17 across 9 — with 36
installed tools eating context budget for the whole session.

What these tests pin is not the wording: it is the SHAPE the measurement says works
— triggers early, and each trigger naming the tool that resolves the moment. A
trigger without a tool name is advice, and advice did not move these numbers.
"""

from __future__ import annotations

import re

from nbrowser import main
from nbrowser.mcp_server import SERVER_INSTRUCTIONS, TOOL_NAMES, McpServer

#: The tools the triggers must name. Each answers a different moment; a trigger
#: that omits them leaves the reader knowing they should use something and not
#: what.
FERRAMENTAS_DOS_GATILHOS = (
    "nbrowser_page_extract",
    "nbrowser_page_scrape",
    "nbrowser_web_search",
)


def test_initialize_serves_the_constant() -> None:
    """`initialize` serves the constant, not a parallel string that drifts from it."""
    assert main.build(McpServer()).instructions == SERVER_INSTRUCTIONS


def test_triggers_come_early() -> None:
    """Early, because what comes late is not read. nMEMORY uses 2048 B; less is
    enough here."""
    b = SERVER_INSTRUCTIONS.encode("utf-8")
    assert b"Triggers" in b[:512], "the triggers do not appear in the first 512 bytes"


def test_every_trigger_names_its_tool() -> None:
    for nome in FERRAMENTAS_DOS_GATILHOS:
        assert nome in SERVER_INSTRUCTIONS, f"no trigger names `{nome}`"


def test_every_tool_the_instructions_name_is_served() -> None:
    """A tool the instructions route to is one tools/list serves. The tool rename
    left `search or research` here, two names nothing answered to; a renamed or
    retired `nbrowser_*` name now fails this instead of reaching a model. Bare
    words are not caught."""
    named = set(re.findall(r"nbrowser_[a-z_]+", SERVER_INSTRUCTIONS))
    assert named, "the instructions name no nbrowser tool"
    assert named <= set(TOOL_NAMES), sorted(named - set(TOOL_NAMES))


def test_instructions_fit_the_budget() -> None:
    """A 2048 B ceiling, the same as nMEMORY's: this enters EVERY session."""
    assert len(SERVER_INSTRUCTIONS.encode("utf-8")) <= 2048
