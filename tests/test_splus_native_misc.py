"""Socket-free lifecycle and pure preflight contracts."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from nbrowser.errors import BrowserError, InputFailure
from nbrowser.mcp_server import McpServer


def test_module_entrypoint_help_is_native_and_does_not_launch_browser() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "nbrowser.cli", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env={**os.environ, "UV_NO_SYNC": "1"},
    )
    assert result.returncode == 0
    assert "nbrowser" in result.stdout
    assert result.stderr == ""


def test_small_snippet_and_approved_provider_urls_are_pure() -> None:
    from nbrowser.egress_guard import is_cross_origin_internal
    from nbrowser.providers.base import validate_provider_url
    from nbrowser.providers.merge import clamp_snippet
    from nbrowser.sanitize import redact_asset_url_keep_path

    assert clamp_snippet("x" * 2048) == "x" * 2048
    assert clamp_snippet("") == ""
    for host in ("api.z.ai", "api.minimax.io", "api.tavily.com", "api.firecrawl.dev"):
        assert validate_provider_url("https://" + host + "/a") is None
    assert redact_asset_url_keep_path("file:///tmp/a") == "[invalid-url]"
    assert not is_cross_origin_internal(
        "https://fixture.test/a", "https://fixture.test/b"
    )


def test_scrape_named_private_destination_refuses_before_browser() -> None:
    from nbrowser.errors import FailureCode

    server = McpServer()
    try:
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call(
                "nbrowser_page_scrape", {"host_url": "http://169.254.169.254/latest"}
            )
        assert exc.value.code is FailureCode.GRANT_REQUIRED
        assert server.session is None
    finally:
        server.close()


RETIRED_TOOLS = [
    "nbrowser_file_upload",
    "nbrowser_script_run",
    "nbrowser_page_monitor",
    "nbrowser_design_crawl",
    "nbrowser_site_map",
    "nbrowser_json_query",
    "nbrowser_page_assert",
    "nbrowser_page_diff",
    "nbrowser_page_audit",
    "nbrowser_page_wait",
    "nbrowser_page_touch",
    "nbrowser_fixture_mark",
    "nbrowser_evidence_record",
    "nbrowser_tab_open",
    "nbrowser_tab_switch",
    "nbrowser_tab_close",
    "nbrowser_session_clear",
    "nbrowser_session_close",
    "nbrowser_file_download",
    "nbrowser_usage_show",
    "nbrowser_github_query",
]


@pytest.mark.parametrize("tool", RETIRED_TOOLS)
def test_a_retired_tool_is_refused_as_unknown_and_never_listed(tool: str) -> None:
    from nbrowser.mcp_server import TOOL_NAMES

    server = McpServer()
    try:
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call(tool, {})
        assert exc.value.code is InputFailure.OPERATION
        assert exc.value.message == f"Tool {tool} not found"
        assert tool not in TOOL_NAMES
        assert server.session is None
    finally:
        server.close()


def test_module_main_guard_executes_help(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import importlib
    import runpy

    importlib.import_module("nbrowser.cli")
    monkeypatch.setattr(sys, "argv", ["nbrowser", "--help"])
    with (
        pytest.warns(RuntimeWarning, match="found in sys.modules"),
        pytest.raises(SystemExit) as exc,
    ):
        runpy.run_module("nbrowser.cli", run_name="__main__")
    assert exc.value.code == 0
    assert "nbrowser" in capsys.readouterr().out


def test_profile_owns_and_removes_disposable_directory() -> None:
    from nbrowser.profile import BrowserProfile

    profile = BrowserProfile()
    root = Path(profile.path)
    try:
        (root / "fixture.txt").write_text("fixture")
        assert root.is_dir()
    finally:
        profile.close()
    assert not root.exists()
    profile.close()


def test_chromium_presence_is_a_filesystem_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nbrowser import private_root

    executable = tmp_path / "fixture-engine"
    executable.write_text("unused resolver fixture")
    executable.chmod(0o700)
    monkeypatch.setenv("NOTT_NBROWSER_CHROME_BIN", str(executable))
    monkeypatch.setattr(
        private_root, "FORTRESS_SLOTS", str(tmp_path / "empty-slots" / "*" / "tilion")
    )
    assert private_root.chromium_present()
    executable.unlink()
    assert not private_root.chromium_present()
