from unittest.mock import MagicMock, patch
from urllib.parse import quote

from nbrowser.sanitize import (
    _ends_with_unescaped_quote,
    _is_secret_pattern,
    _redact_param_string,
    _unquote_fixed_point,
    is_secret_token,
    redact_diagnostic,
    redact_url_keep_path,
)


def test_unquote_fixed_point_exhaustion_and_secret_token_invalid_url() -> None:
    s = "%"
    for _ in range(35):
        s = quote(s)
    assert _unquote_fixed_point(s) == "[invalid-url]"
    assert is_secret_token(s) is True
    assert _is_secret_pattern(s) is True
    assert _unquote_fixed_point("clean_value") == "clean_value"


def test_is_secret_token_prefix_lowercase_fallback() -> None:
    assert is_secret_token("Live_12345") is True
    assert is_secret_token("unrelated_safe_text") is False


def test_redact_param_string_empty_params_and_delimiters() -> None:
    assert _redact_param_string("&&&") == "&&&"
    assert _redact_param_string("page=1") == "page=1"


def test_redact_param_string_matrix_parameters() -> None:
    qs = ";;token:sub=123;sk-secret;token=myval;safe=public;unrelated"
    res = _redact_param_string(qs)
    assert (
        res
        == ";;[redacted]=[redacted];[redacted];token=[redacted];safe=public;unrelated"
    )
    assert _redact_param_string("safe=1;safe=2") == "safe=1;safe=2"


def test_redact_url_keep_path_relative_and_invalid_host_and_netloc() -> None:
    assert redact_url_keep_path("/api/v1/resource") == "/api/v1/resource"
    assert redact_url_keep_path("https:///missing-host") == "[invalid-url]"

    class FlipHost(str):
        def __init__(self, val: str = "") -> None:
            self._cnt = 0

        def strip(self, chars: str | None = None) -> FlipHost:
            return self

        def __bool__(self) -> bool:
            self._cnt += 1
            return self._cnt < 3

        def __contains__(self, item: object) -> bool:
            return False

    with patch("nbrowser.sanitize.urlparse") as mock_urlparse:
        mock_obj = MagicMock()
        mock_obj.scheme = "https"
        mock_obj.hostname = FlipHost("host")
        mock_obj.port = None
        mock_urlparse.return_value = mock_obj
        assert redact_url_keep_path("https://example.com") == "[invalid-url]"


def test_redact_url_keep_path_fragments() -> None:
    assert (
        redact_url_keep_path("https://example.com/p#token=abc")
        == "https://example.com/p#token=%5Bredacted%5D"
    )
    assert (
        redact_url_keep_path("https://example.com/p#sk-1234567890abcdef")
        == "https://example.com/p#[redacted]"
    )
    assert (
        redact_url_keep_path("https://example.com/p#section1")
        == "https://example.com/p#section1"
    )


def test_ends_with_unescaped_quote() -> None:
    assert _ends_with_unescaped_quote('hello"', '"') is True
    assert _ends_with_unescaped_quote('hello\\"', '"') is False
    assert _ends_with_unescaped_quote('hello\\\\"', '"') is True
    assert _ends_with_unescaped_quote("hello", '"') is False
    assert _ends_with_unescaped_quote('"', '"') is True


def test_redact_diagnostic_empty_lines_and_cookie_header_variants() -> None:
    diag = redact_diagnostic("First line\n\nSecond line")
    assert diag == "First line\n\nSecond line"

    assert (
        redact_diagnostic("Cookie : session_id_123")
        == "[REDACTED] [REDACTED] [REDACTED]"
    )
    assert redact_diagnostic("Cookie: session_id_123") == "[REDACTED] [REDACTED]"


def test_redact_diagnostic_operator_single_and_multi_quoted_secret() -> None:
    assert (
        redact_diagnostic('password = "single_token_secret" and following')
        == "password = [REDACTED] and following"
    )
    assert (
        redact_diagnostic('password = "multi token secret" and following')
        == "password = [REDACTED] [REDACTED] [REDACTED] and following"
    )


def test_redact_diagnostic_hybrid_assignment_variants() -> None:
    assert (
        redact_diagnostic('password ="single_token" and following')
        == "password = [REDACTED] and following"
    )
    assert (
        redact_diagnostic('password ="multi token" and following')
        == "password = [REDACTED] [REDACTED] and following"
    )
    assert (
        redact_diagnostic("password =unquoted_secret and following")
        == "password = [REDACTED] [REDACTED] and following"
    )
    assert redact_diagnostic("password =unquoted_to_eol") == "password = [REDACTED]"


def test_redact_diagnostic_key_delimiter_next_word_variants() -> None:
    assert (
        redact_diagnostic('password= "single_token" and following')
        == "[REDACTED] [REDACTED] and following"
    )
    assert (
        redact_diagnostic('password= "first middle last" and following')
        == "[REDACTED] [REDACTED] [REDACTED] [REDACTED] and following"
    )
    assert (
        redact_diagnostic("password= unquoted_secret and following")
        == "[REDACTED] [REDACTED] [REDACTED] and following"
    )


def test_redact_diagnostic_attached_secret_and_bearer_token() -> None:
    assert redact_diagnostic("foo.bar=baz,password=secret123") == "[REDACTED]"
    assert redact_diagnostic("foo.bar:baz,password:secret123") == "[REDACTED]"

    assert redact_diagnostic('token="unclosed_secret') == "[REDACTED]"
    assert (
        redact_diagnostic('token="multi word" and more')
        == "[REDACTED] [REDACTED] and more"
    )
    assert (
        redact_diagnostic('token="closed_secret" and following')
        == "[REDACTED] and following"
    )

    assert redact_diagnostic("Prefix Bearer") == "Prefix [REDACTED]"
    assert redact_diagnostic("Prefix Bearer token123") == "Prefix [REDACTED] [REDACTED]"
