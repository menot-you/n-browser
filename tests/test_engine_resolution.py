"""Engine resolution: Fortress is the only engine nBROWSER launches.

The port had dropped the stealth engine and silently fell back to whatever
system Chromium the box happened to carry — a different browser than the one
the fingerprint patches were measured against, chosen without a word. These
cases pin the whole order: override wins, else the newest regular-file Fortress
slot (never a symlink to system Chromium), else a typed refusal that never returns.

Every case runs against a fake HOME. Planting a slot under the real
``~/.cache/nbrowser/fortress`` would leave a newer fake behind and
redirect the product's own resolution on this box.
"""

import os
from pathlib import Path

import pytest

from nbrowser.errors import BrowserError, ClosedFailure
from nbrowser.private_root import get_chromium_executable


def _slot(home: Path, tag: str, *, executable: bool, mtime: float) -> Path:
    tilion = home / ".cache" / "nbrowser" / "fortress" / tag / "tilion"
    tilion.parent.mkdir(parents=True)
    tilion.write_text("#!/bin/sh\n")
    tilion.chmod(0o755 if executable else 0o644)
    os.utime(tilion, (mtime, mtime))
    return tilion


def test_resolves_newest_usable_fortress_slot_never_system_chromium(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("NOTT_NBROWSER_CHROME_BIN", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    _slot(tmp_path, "fortress-v152", executable=True, mtime=1_000_000.0)
    newest = _slot(tmp_path, "fortress-v153", executable=True, mtime=2_000_000.0)
    # Newest of all, but not a regular file with the execute bit: form is what
    # admits a slot, exactly as the donor validates it.
    _slot(tmp_path, "fortress-v154", executable=False, mtime=3_000_000.0)

    resolved = get_chromium_executable()

    assert resolved == str(newest)
    assert not resolved.startswith(("/usr/bin", "/opt/google", "/Applications"))


def test_symlink_slot_to_system_chromium_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("NOTT_NBROWSER_CHROME_BIN", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    regular = _slot(tmp_path, "fortress-v152", executable=True, mtime=1_000_000.0)
    fake_system_chrome = tmp_path / "usr-lib-chromium"
    fake_system_chrome.write_text("#!/bin/sh\n")
    fake_system_chrome.chmod(0o755)
    os.utime(fake_system_chrome, (3_000_000.0, 3_000_000.0))
    link_slot = (
        tmp_path / ".cache" / "nbrowser" / "fortress" / "fortress-v153" / "tilion"
    )
    link_slot.parent.mkdir(parents=True)
    link_slot.symlink_to(fake_system_chrome)

    assert get_chromium_executable() == str(regular)

    regular.unlink()
    with pytest.raises(BrowserError) as caught:
        get_chromium_executable()

    assert caught.value.code is ClosedFailure.LAUNCH


def test_env_override_beats_the_slot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    _slot(tmp_path, "fortress-v153", executable=True, mtime=2_000_000.0)
    override = tmp_path / "my-chrome"
    override.write_text("#!/bin/sh\n")
    override.chmod(0o755)
    monkeypatch.setenv("NOTT_NBROWSER_CHROME_BIN", str(override))

    assert get_chromium_executable() == str(override)


@pytest.mark.parametrize("gone_at_look", [1, 2])
def test_a_slot_removed_mid_resolution_is_never_an_untyped_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, gone_at_look: int
) -> None:
    """A release replaced while a launch resolves it: the installer removes a
    slot after the listing named it. The first slot the resolver looks at,
    whatever the listing's order, is removed for real at that look, so the stat
    fails the way the kernel fails it. A second look at the same slot raised
    FileNotFoundError, which `chromium_present` does not catch and the door
    reports as internal."""
    monkeypatch.delenv("NOTT_NBROWSER_CHROME_BIN", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    slots = {
        str(_slot(tmp_path, "fortress-v152", executable=True, mtime=1_000_000.0)),
        str(_slot(tmp_path, "fortress-v153", executable=True, mtime=2_000_000.0)),
    }
    real_lstat = os.lstat
    doomed: str | None = None
    looks = 0

    def stand_in(path: object, *args: object, **kwargs: object) -> os.stat_result:
        nonlocal doomed, looks
        if doomed is None and str(path) in slots:
            doomed = str(path)
        if str(path) == doomed:
            looks += 1
            if looks == gone_at_look:
                os.unlink(doomed)
        return real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "lstat", stand_in)

    resolved = get_chromium_executable()
    monkeypatch.setattr(os, "lstat", real_lstat)  # the checks below look too

    assert resolved in slots
    assert os.path.isfile(resolved)


def test_no_slot_and_no_override_is_a_typed_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("NOTT_NBROWSER_CHROME_BIN", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))

    with pytest.raises(BrowserError) as caught:
        get_chromium_executable()

    assert caught.value.code is ClosedFailure.LAUNCH
    assert "fortress" in caught.value.message
    assert "NOTT_NBROWSER_CHROME_BIN" in caught.value.message
