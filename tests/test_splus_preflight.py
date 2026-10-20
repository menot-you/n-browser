"""Transport preflight failures and pure provider evidence, without egress."""

import pytest

from nbrowser.errors import BrowserError, FailureCode
from nbrowser.providers.base import (
    LaneReport,
    ProviderKey,
    ProviderTransportError,
    SearchHit,
    redact,
    validate_provider_url,
)
from nbrowser.providers.merge import clamp_snippet, merge_search
from nbrowser.transfer import (
    TextArtifactCandidate,
    apply_text_artifacts,
    download_host_page,
)


@pytest.mark.parametrize(
    "url,error",
    [
        ("https:///a", "missing_host"),
        ("http://api.z.ai/a", "unapproved_scheme: only https is allowed"),
        ("https://outside.test/a", "unapproved_host: outside.test"),
    ],
)
def test_provider_url_preflight(url: str, error: str) -> None:
    assert validate_provider_url(url) == error


def test_provider_evidence_omits_absence_and_preserves_empty_values() -> None:
    assert SearchHit("T", "https://fixture.test").to_dict() == {
        "title": "T",
        "url": "https://fixture.test",
        "providers": [],
    }
    assert SearchHit("T", "https://fixture.test", "", "").to_dict() == {
        "title": "T",
        "url": "https://fixture.test",
        "providers": [],
        "snippet": "",
        "date": "",
    }
    assert LaneReport("p", "error", "").to_dict() == {
        "provider": "p",
        "status": "error",
        "ms": 0,
        "results": 0,
        "detail": "",
    }
    assert redact("") == "transport_error"
    assert redact("first\nsecond") == "first"
    assert redact("x" * 121) == "x" * 120


def test_merge_clones_and_limits_utf8_without_duplicate_provider() -> None:
    snippet = "€" * 1000
    assert clamp_snippet(snippet) == "€" * 682 + "…"
    original = SearchHit("A", "https://fixture.test/a", snippet, providers=["one"])
    duplicate = SearchHit("B", "https://fixture.test/a#fragment")
    merged = merge_search([[original, duplicate], [duplicate]], ["one", "two"], 1)
    assert len(merged) == 1
    assert merged[0].providers == ["one", "two"]
    assert merged[0].snippet == "€" * 682 + "…"
    assert original.providers == ["one"]
    assert original.snippet == snippet
    assert merge_search([], [], 1) == []


def test_artifact_spill_requires_staging_but_empty_input_is_unchanged() -> None:
    payload: dict[str, object] = {"text": "long"}
    with pytest.raises(BrowserError) as exc:
        apply_text_artifacts(payload, [TextArtifactCandidate("text", "long")], 1)
    assert exc.value.code is FailureCode.CONTENT_UNAVAILABLE
    assert payload == {"text": "long"}
    apply_text_artifacts(payload, [], 1)
    assert payload == {"text": "long"}


@pytest.mark.parametrize(
    "url",
    [
        "https://169.254.169.254/latest",
        "file:///tmp/local",
        "https://internal.nip.io/a",
    ],
)
def test_host_download_denies_before_open(url: str) -> None:
    with pytest.raises(BrowserError) as exc:
        download_host_page(url)
    assert exc.value.code is FailureCode.GRANT_REQUIRED


def test_bearer_transport_refuses_unapproved_origin_before_building_request() -> None:
    from nbrowser.providers.base import bearer_post

    key = ProviderKey("fixture-not-a-real-key")
    with pytest.raises(ProviderTransportError, match="unapproved_host: fixture.test"):
        bearer_post("https://fixture.test", "/a", key, {"query": "fixture"})
