"""Secret redaction in the live sanitizers that extract, network, design and
tokens call. These cases moved here from the retired pilot/run tests, which
were the only ones that reached these lines."""

import pytest

from nbrowser.sanitize import is_secret_token, redact_diagnostic, redact_url_keep_path


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://alice:hunter2@example.com:bad/app", "[invalid-url]"),
        ("https://alice:hunter2@example.com/app", "https://example.com/app"),
        (
            "https://example.com/app#/checkout/step2",
            "https://example.com/app#/checkout/step2",
        ),
        ("https://example.com/app#/dashboard", "https://example.com/app#/dashboard"),
        ("https://[2001:db8::1]:8080/app", "https://[2001:db8::1]:8080/app"),
        ("https://[2001:db8::1]/app", "https://[2001:db8::1]/app"),
        (
            "https://example.com/reset/ghp_11AABBCCDDEEFFGG/finish",
            "https://example.com/reset/[redacted]/finish",
        ),
        (
            "https://example.com/login?pw=hunter2",
            "https://example.com/login?pw=%5Bredacted%5D",
        ),
        (
            "https://example.com/password/hunter2",
            "https://example.com/[redacted]/[redacted]",
        ),
        (
            "https://example.com/reset;token=ghp_DEMO",
            "https://example.com/reset;token=%5Bredacted%5D",
        ),
        (
            "https://example.com/app/#/route/password/secretval",
            "https://example.com/app/#/route/[redacted]/[redacted]",
        ),
        (
            "https://example.com/?ghp_SECRET=val",
            "https://example.com/?%5Bredacted%5D=%5Bredacted%5D",
        ),
        (
            "https://example.com/?%25252567hp_AABB=val",
            "https://example.com/?%5Bredacted%5D=%5Bredacted%5D",
        ),
        (
            "https://example.com/?" + "%25" * 34 + "67hp_AABB=secretval",
            "https://example.com/?%5Bredacted%5D=%5Bredacted%5D",
        ),
        (
            "https://example.com/?q=" + "%25" * 66 + "67hp_AABB",
            "https://example.com/?q=%5Bredacted%5D",
        ),
        (
            "https://example.com/oauth/callback?code=hunter2&state=xyz",
            "https://example.com/oauth/callback?code=%5Bredacted%5D&state=xyz",
        ),
        (
            "https://example.com/api?signature=1234abcd&user=alice",
            "https://example.com/api?signature=%5Bredacted%5D&user=alice",
        ),
        (
            "https://example.com/login?password%3Dhunter2",
            "https://example.com/login?%5Bredacted%5D=%5Bredacted%5D",
        ),
    ],
)
def test_redact_url_keep_path(url: str, expected: str) -> None:
    assert redact_url_keep_path(url) == expected


@pytest.mark.parametrize(
    ("url", "secrets", "kept"),
    [
        (
            "https://example.com/api?session=s123&"
            + "pass"
            + "wd=p123"
            + "&cookie=c123&token=t123&page=2",
            ["s123", "p123", "c123", "t123"],
            "page=2",
        ),
        (
            "https://example.com/app#/checkout?token=secret123&session=sess1&other=val",
            ["secret123", "sess1"],
            "other=val",
        ),
        (
            "https://example.com/oauth#access_token=secret456&token_type=bearer&scope=read",
            ["secret456"],
            "scope=read",
        ),
        ("https://example.com/?otp=654321", ["654321"], "example.com"),
    ],
)
def test_redact_url_keep_path_drops_secret_values(
    url: str, secrets: list[str], kept: str
) -> None:
    clean = redact_url_keep_path(url)
    assert kept in clean
    for secret in secrets:
        assert secret not in clean


def test_is_secret_token() -> None:
    for token in (
        "pw",
        "pwd",
        "pass",
        "AKIA1234567890ABCDEF",
        "npm_1234567890abcdef",
        "ghp%5FDEMO",
        "otp-654321",
    ):
        assert is_secret_token(token), token
    for benign in (
        "testing",
        "section",
        "keyboard",
        "path",
        "turkey",
        "Turkey",
        "passion",
    ):
        assert not is_secret_token(benign), benign


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Authorization: Bearer ghp_1122334455", "[REDACTED] [REDACTED] [REDACTED]"),
        ("password = hunter2", "password = [REDACTED]"),
        ("token : secret123", "token : [REDACTED]"),
        ("Authorization:Bearer hunter2", "[REDACTED] [REDACTED]"),
        ("Authorization: Basic dXNlcjpodW50ZXIy", "[REDACTED] [REDACTED] [REDACTED]"),
        ("Set-Cookie: sid=hunter2; secure", "[REDACTED] [REDACTED] [REDACTED]"),
        (
            "Authorization : Basic dXNlcjpodW50ZXIy",
            "[REDACTED] [REDACTED] [REDACTED] [REDACTED]",
        ),
        ("Set-Cookie: sid=hunter2; other=secret", "[REDACTED] [REDACTED] [REDACTED]"),
        (
            "This action requires authorization to proceed",
            "This action requires authorization to proceed",
        ),
    ],
)
def test_redact_diagnostic_exact(text: str, expected: str) -> None:
    assert redact_diagnostic(text) == expected


@pytest.mark.parametrize(
    ("text", "secrets", "kept"),
    [
        ("`Authorization:` Basic dXNlcjpwYXNz", ["dXNlcjpwYXNz", "Basic"], ""),
        ("`Set-Cookie`: sid=1234; path=/", ["1234", "sid"], ""),
        ("`password`: hunter2", ["hunter2"], ""),
        ("`Bearer` secret_token_value_123", ["secret_token_value_123"], ""),
        ("(Authorization): Basic dXNlcjpwYXNz", ["dXNlcjpwYXNz"], ""),
        (
            "Authorization: secret123\nWelcome to our page!",
            ["secret123"],
            "Welcome to our page!",
        ),
        (
            'password="correct users\' and battery staple" and continue',
            ["users", "battery", "staple"],
            "and continue",
        ),
        (
            'password = " correct horse " and continue',
            ["correct", "horse"],
            "and continue",
        ),
        (
            'password=("correct horse and battery") then continue',
            ["correct", "battery"],
            "then continue",
        ),
        (
            'password = ("correct horse and battery") then continue',
            ["correct", "battery"],
            "then continue",
        ),
        (
            'password ="correct horse and battery" then continue',
            ["correct", "battery"],
            "then continue",
        ),
        (
            "password = `correct horse and battery` then continue",
            ["correct", "battery"],
            "then continue",
        ),
        ("db_password = hunter2 and continue", ["hunter2"], "[REDACTED]"),
    ],
)
def test_redact_diagnostic_drops_secret_values(
    text: str, secrets: list[str], kept: str
) -> None:
    clean = redact_diagnostic(text)
    assert kept in clean
    for secret in secrets:
        assert secret not in clean


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Spaced operator branch: value words start at index i + 2.
        (
            "password = hunter2 and continue",
            "password = [REDACTED] [REDACTED] and continue",
        ),
        (
            'password = "a and b" c',
            "password = [REDACTED] [REDACTED] [REDACTED] c",
        ),
        (
            'password = "a and b c',
            "password = [REDACTED] [REDACTED] [REDACTED] [REDACTED]",
        ),
        ("password = a:b c", "password = [REDACTED] [REDACTED]"),
        # Hybrid branch: value words start at index i + 1 after the operator split.
        ("password =x and continue", "password = [REDACTED] [REDACTED] and continue"),
        (
            'password ="a and b" c',
            "password = [REDACTED] [REDACTED] [REDACTED] c",
        ),
        (
            'password ="a and b c',
            "password = [REDACTED] [REDACTED] [REDACTED] [REDACTED]",
        ),
        # Key= branch: the key word redacts and value words start at index i + 1.
        (
            "password= hunter2 and continue",
            "[REDACTED] [REDACTED] [REDACTED] and continue",
        ),
        ('password= "a and b" c', "[REDACTED] [REDACTED] [REDACTED] [REDACTED] c"),
        (
            'password= "a and b c',
            "[REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED]",
        ),
        ("password= a:b c", "[REDACTED] [REDACTED] [REDACTED]"),
    ],
)
def test_redact_diagnostic_value_loop_characterization(
    text: str, expected: str
) -> None:
    """One case per copy of the quote-tracking loop in redact_diagnostic.
    Each records the current output: a break word after the first value word
    stops the run, a break word inside an open quote does not, and an unclosed
    quote redacts to the end of the line."""
    assert redact_diagnostic(text) == expected


def test_wrap_content_boundaries_uses_csprng_nonce_and_origin() -> None:
    from nbrowser.sanitize import get_boundary_nonce, wrap_content_boundaries

    nonce = get_boundary_nonce()
    assert len(nonce) == 32
    assert all(c in "0123456789abcdef" for c in nonce)
    wrapped = wrap_content_boundaries("hello world", "https://example.com")
    assert wrapped == (
        f"--- NBROWSER_PAGE_CONTENT nonce={nonce} origin=https://example.com ---\n"
        "hello world\n"
        f"--- END_NBROWSER_PAGE_CONTENT nonce={nonce} ---"
    )
