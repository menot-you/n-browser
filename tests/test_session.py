"""Session lifecycle observed through the §31 protocol double — the same
calls the real CDP answers, driven on any host — plus the absence branch
asserted as a typed refusal (never a skip)."""

import time

import pytest
from cdp_double import CdpDouble, FakePage

from nbrowser.errors import BrowserError, ClosedFailure
from nbrowser.private_root import get_chromium_executable
from nbrowser.session import BrowserLaunchConfig, BrowserSession


def _double_session() -> tuple[BrowserSession, CdpDouble]:
    pages = [FakePage("http://fixture.test/page-a", "Fixture", "hello fixture")]
    double = CdpDouble(pages)
    session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: CdpDouble(pages)
    )
    return session, double


def test_session_lifecycle_via_double() -> None:
    session, _ = _double_session()

    assert session.client is not None
    tabs = session.tabs_list()
    assert len(tabs) >= 1

    tab1 = tabs[0]
    session.navigate(tab1, "http://fixture.test/page-b")
    assert session.evaluate(tab1, "location.href") is not None

    tab2 = session.tabs_open("about:blank")
    assert tab2 in session.tabs_list()


def test_idle_reap_and_transparent_relaunch_via_double() -> None:
    session, _ = _double_session()
    first_client = session.client

    # Force the idle window closed; the next driving command relaunches.
    session.last_active_time = time.time() - 400
    session.mark_active()
    assert session.client is not None
    assert session.client is not first_client  # a fresh endpoint answered


def test_terminal_close_refuses_typed() -> None:
    session, _ = _double_session()
    session.close_session()
    assert session.closed
    assert session.client is None

    with pytest.raises(BrowserError) as exc_info:
        session.tabs_list()
    assert exc_info.value.code == ClosedFailure.BROWSER_CLOSED


def test_missing_chromium_is_a_typed_launch_refusal() -> None:
    """The absence branch, observed as the typed refusal it is (§31): no
    Chromium on this host means BrowserError(launch), never a skip."""
    import os

    saved = os.environ.pop("NOTT_NBROWSER_CHROME_BIN", None)
    try:
        # `get_chromium_executable` RAISES on absence (private_root.py:39) and never returns
        # None: probing it with `is not None` only ever ran on a host that had the slot.
        # Measured 2026-09-03 as the gate's executor, whose home has no engine release:
        # the probe itself raised, outside the `pytest.raises` below, and the absence branch
        # this test exists to assert was reported as a failure.
        try:
            get_chromium_executable()
        except BrowserError as absent:
            assert absent.code == ClosedFailure.LAUNCH
            return
        # A host WITH Chromium: the same call proves the real launch path.
        session = BrowserSession(BrowserLaunchConfig(headless=True))
        assert session.client is not None
        session.close_session()
    finally:
        if saved is not None:
            os.environ["NOTT_NBROWSER_CHROME_BIN"] = saved
