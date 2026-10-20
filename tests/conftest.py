"""The suite never inherits a renamed variable's old spelling from the host."""

import pytest

from nbrowser.renamed import RENAMED as NBROWSER_RENAMED


@pytest.fixture(autouse=True)
def _no_old_spelling(monkeypatch: pytest.MonkeyPatch) -> None:
    # A host that still exports an old spelling makes every read refuse by name; the
    # suite measures the transport, not the host's migration. A case that needs an old
    # spelling sets it itself.
    for old in NBROWSER_RENAMED.values():
        monkeypatch.delenv(old, raising=False)
