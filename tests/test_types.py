import pytest

from nbrowser.errors import BrowserError, FailureCode
from nbrowser.seam import AuthoritySeam
from nbrowser.types import EffectOperation


def test_authority_seam() -> None:
    seam = AuthoritySeam(None)
    with pytest.raises(BrowserError) as exc_info:
        seam.authorize_host(EffectOperation.click, "http://192.168.1.1")
    assert exc_info.value.code == FailureCode.GRANT_REQUIRED
