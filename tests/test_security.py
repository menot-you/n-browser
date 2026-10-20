import pytest

from nbrowser.content_custody import FixtureContentResolver
from nbrowser.egress_guard import is_cross_origin_internal, is_public_safe
from nbrowser.errors import BrowserError, FailureCode
from nbrowser.private_root import PrivateRootContext
from nbrowser.sanitize import redact_url_keep_path


def test_ssrf_denial_matrix() -> None:
    assert not is_public_safe("http://192.168.1.1")
    assert not is_public_safe("http://169.254.169.254/latest/meta-data/")
    assert not is_public_safe("http://100.64.10.1")
    assert not is_public_safe("http://[fc00::1]")
    assert is_public_safe("http://example.com")
    assert is_public_safe("http://127.0.0.1")

    # Public -> loopback redirect rejection
    assert is_cross_origin_internal("http://127.0.0.1/admin", "https://example.com")
    assert not is_cross_origin_internal("https://example2.com", "https://example.com")


def test_private_root_containment() -> None:
    ctx = PrivateRootContext()
    path = ctx.get_profile_path()
    import os

    assert os.path.exists(path)
    ctx.close()
    assert not os.path.exists(path)


def test_fixture_content_resolver_single_resolve() -> None:
    resolver = FixtureContentResolver()
    resolver.store_bytes("hash123", b"data")
    assert resolver.resolve_once("hash123") == b"data"
    with pytest.raises(BrowserError) as exc_info:
        resolver.resolve_once("hash123")
    assert exc_info.value.code == FailureCode.CONTENT_UNAVAILABLE


def test_credential_stripping_urls() -> None:
    assert (
        redact_url_keep_path("https://example.com/?token=secret&q=search")
        == "https://example.com/?token=%5Bredacted%5D&q=search"
    )


def test_private_root_close_retries_a_tree_still_being_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A late write makes one rmtree pass fail with ENOTEMPTY; that must not leak."""
    import errno
    import os
    import shutil

    ctx = PrivateRootContext()
    path = ctx.get_profile_path()
    real = shutil.rmtree
    calls: list[str] = []

    def late_writer(target: str, *args: object, **kwargs: object) -> None:
        calls.append(target)
        if len(calls) == 1:
            raise OSError(errno.ENOTEMPTY, "Directory not empty", target)
        real(target)

    monkeypatch.setattr(shutil, "rmtree", late_writer)
    ctx.close()

    assert len(calls) == 2
    assert not os.path.exists(path)
