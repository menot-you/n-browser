"""A set old variable name is refused by name, before an engine is chosen."""

from __future__ import annotations

import pytest

from nbrowser.errors import ClosedFailure
from nbrowser.private_root import get_chromium_executable
from nbrowser.renamed import RENAMED, RenamedVariableError, env


@pytest.mark.parametrize("new", sorted(RENAMED))
def test_every_renamed_variable_is_refused_by_its_old_name(
    monkeypatch: pytest.MonkeyPatch, new: str
) -> None:
    old = RENAMED[new]
    monkeypatch.setenv(new, "/bin/true")
    monkeypatch.setenv(old, "/bin/true")
    with pytest.raises(RenamedVariableError) as refused:
        env(new)
    assert (refused.value.old, refused.value.new) == (old, new)
    assert refused.value.code is ClosedFailure.LAUNCH


def test_engine_resolution_refuses_an_old_engine_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    new = "NOTT_NBROWSER_CHROME_BIN"
    monkeypatch.setenv(new, "/bin/true")
    monkeypatch.setenv(RENAMED[new], "/bin/true")
    with pytest.raises(RenamedVariableError, match=new):
        get_chromium_executable()
