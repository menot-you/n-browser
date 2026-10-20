"""The static projection has the shape of MARKDOWN_WALKER and the empty
predicate that decides `auto`; links pass a scheme gate only — origin is the
frontier's decision."""

from __future__ import annotations

import gzip

import pytest

from nbrowser.errors import BrowserError, FailureCode
from nbrowser.static_extract import MAX_STATIC_BYTES, decode_body, project

BASE = "http://127.0.0.1:8765/dir/page.html"
SHELL = (
    "<html><body><noscript>Enable JS</noscript><div id=root></div>"
    "<script>document.body.innerHTML='<p>hi</p>'</script></body></html>"
)
PLAIN = (
    "<html><head><title>T</title><style>p{color:red}</style></head><body>"
    "<h1>Title  one</h1><p>Hello <b>bold</b>\n world</p>"
    "<ul><li>one</li><li><p>two</p></li></ul>"
    "<pre>  a\n  b </pre><blockquote>q</blockquote><h3>Sub</h3>"
    "<template><p>never</p></template>"
    '<a href="/next">Next</a><a href="x.html">  </a>'
    '<a href="https://example.com/">Ext</a></body></html>'
)


def test_projection_has_the_walker_shape() -> None:
    page = project(PLAIN, BASE)
    assert page.markdown == (
        "# Title one\n\n### Sub\n\n"
        "Hello bold world\n\none\n\ntwo\n\ntwo\n\na b\n\nq\n\n"
        "[Next](http://127.0.0.1:8765/next)\n\n[Ext](https://example.com/)"
    )
    assert page.links == [
        "http://127.0.0.1:8765/next",
        "http://127.0.0.1:8765/dir/x.html",
        "https://example.com/",
    ]
    assert page.empty is False


def test_noscript_shell_is_empty_and_scripts_never_leak() -> None:
    page = project(SHELL, BASE)
    assert page.empty is True
    assert page.markdown == ""
    assert page.links == []
    styled = project("<style>p{}</style><script>var x='<p>y</p>'</script>", BASE)
    assert styled.empty is True and styled.markdown == ""
    links_only = project('<a href="/a">A</a>', BASE)
    assert links_only.empty is True
    assert links_only.markdown == "[A](http://127.0.0.1:8765/a)"
    noscript_block = project("<noscript><p>Enable JS</p></noscript>", BASE)
    assert noscript_block.empty is True
    assert noscript_block.markdown == ""


def test_link_scheme_gate_and_base_href() -> None:
    html = (
        '<a href="javascript:void(0)">j</a><a href="data:text/html,x">d</a>'
        '<a href="file:///etc/passwd">f</a><a href="ftp://h/x">ftp</a>'
        '<a href="//evil.com/x">e</a><a href="http://localhost:8765/x">l</a>'
        '<a href="http://127.0.0.1:9222/json">p</a><a href="/a#frag">a</a>'
        '<a href="/a#frag">again</a><a href="HTTPS://Example.com/">u</a>'
    )
    page = project(html, BASE)
    assert page.links == [
        "http://evil.com/x",
        "http://localhost:8765/x",
        "http://127.0.0.1:9222/json",
        "http://127.0.0.1:8765/a#frag",
        "HTTPS://Example.com/",
    ]
    assert "javascript:" not in page.markdown and "file:" not in page.markdown
    based = project('<base href="https://other.example/root/"><a href="x">x</a>', BASE)
    assert based.links == ["https://other.example/root/x"]


def test_decode_body_handles_gzip_and_garbage() -> None:
    assert decode_body(gzip.compress("<p>é</p>".encode()), "gzip") == "<p>é</p>"
    assert decode_body(b"<p>plain</p>", None) == "<p>plain</p>"
    assert decode_body(b"\xff\xfe<p>x</p>", "identity") == "��<p>x</p>"
    assert decode_body(b"\x1f\x8b\x08\x00trunc", "gzip") == ""
    assert (
        project(decode_body(gzip.compress(b"<h1>gz</h1>"), "gzip"), BASE).markdown
        == "# gz"
    )


def test_declared_non_utf8_charset_skips_one_document_and_keeps_the_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nbrowser import extract
    from nbrowser.mcp_server import McpServer

    def fake_download(url: str, **kwargs: object) -> tuple[bytes, str, str, str | None]:
        if url.endswith("/latin.html"):
            return "café".encode("iso-8859-1"), "text/html", "", "iso-8859-1"
        return b"<p>plain page</p>", "text/html", "", None

    monkeypatch.setattr(extract, "download_host_page", fake_download)
    server = McpServer()
    try:
        result = server.handle_tool_call(
            "nbrowser_page_extract",
            {
                "urls": [
                    "http://docs.example/latin.html",
                    "http://docs.example/plain.html",
                ],
                "mode": "static",
            },
        )
    finally:
        server.close()
    assert result["documents"] == [
        {
            "url": "http://docs.example/latin.html",
            "mode_used": "static",
            "markdown": "",
            "skipped": "content_type",
        },
        {
            "url": "http://docs.example/plain.html",
            "mode_used": "static",
            "markdown": "plain page",
        },
    ]


def test_decode_body_bounds_highly_compressible_output() -> None:
    assert (
        decode_body(gzip.compress(b"x" * MAX_STATIC_BYTES), "gzip")
        == "x" * MAX_STATIC_BYTES
    )
    bomb = gzip.compress(b"x" * (MAX_STATIC_BYTES * 8))
    assert len(bomb) < MAX_STATIC_BYTES
    for body, encoding in ((bomb, "gzip"), (b"x" * (MAX_STATIC_BYTES + 1), None)):
        with pytest.raises(BrowserError) as exc:
            decode_body(body, encoding)
        assert exc.value.code == FailureCode.CONTENT_BUDGET_EXCEEDED


def test_projection_flushes_optional_end_tags_and_eof() -> None:
    for html, expected in (
        ("<p>Hello", "Hello"),
        ("<p>a<p>b", "a\n\nb"),
        ("<ul><li>a<li>b</ul>", "a\n\nb"),
        ("<ul><li><p>a<li>b</ul>", "a\n\na\n\nb"),
    ):
        page = project(html, BASE)
        assert page.markdown == expected
        assert page.empty is False


def test_invalid_deflate_is_an_empty_projection() -> None:
    assert (
        decode_body(bytes.fromhex("1f8b080000000000000307000000000000000000"), "gzip")
        == ""
    )


def test_valid_deflate_still_enforces_decoded_byte_ceiling() -> None:
    with pytest.raises(BrowserError) as exc:
        decode_body(gzip.compress(b"x" * (MAX_STATIC_BYTES + 1)), "gzip")
    assert exc.value.code == FailureCode.CONTENT_BUDGET_EXCEEDED


def test_malformed_href_preserves_readable_document() -> None:
    page = project(
        '<p>readable document</p><a href="http://[broken">link</a>',
        "http://127.0.0.1:8765/",
    )
    assert "readable document" in page.markdown
    assert page.links == []


def test_malformed_base_preserves_original_base() -> None:
    page = project(
        '<base href="http://[broken"><p>x</p><a href="/n">N</a>',
        "http://127.0.0.1:8765/",
    )
    assert page.links == ["http://127.0.0.1:8765/n"]


def test_markdown_outline_and_section_filtering() -> None:
    from nbrowser.static_extract import (
        ancestor_llms_urls,
        extract_markdown_outline,
        filter_markdown_sections,
        parse_llms_txt_links,
    )

    doc = (
        "# Guide\n\nIntro paragraph.\n\n"
        "## Authentication\n\nUse tokens carefully.\n\n"
        "### OAuth Flow\n\nRedirect URI details.\n\n"
        "## Billing\n\nInvoices and plans."
    )
    assert extract_markdown_outline(doc) == (
        "# Guide\n## Authentication\n### OAuth Flow\n## Billing"
    )
    assert filter_markdown_sections(doc, "auth") == (
        "## Authentication\n\nUse tokens carefully.\n\n"
        "### OAuth Flow\n\nRedirect URI details."
    )
    assert filter_markdown_sections(doc, "oauth") == (
        "### OAuth Flow\n\nRedirect URI details."
    )
    assert filter_markdown_sections(doc, "nonexistent") == ""

    assert ancestor_llms_urls("https://docs.example.com/a/b/page.html") == [
        "https://docs.example.com/a/b/llms.txt",
        "https://docs.example.com/a/llms.txt",
        "https://docs.example.com/llms.txt",
    ]
    llms_body = (
        "# Docs\n"
        "- [Broken Port](https://docs.example.com:bad/broken.md)\n"
        "- [Auth Guide](/a/b/auth.md): Auth docs\n"
        "- [Off Origin](https://evil.example/x.md)\n"
        "- [Loopback](http://127.0.0.1/secret.md)\n"
    )
    assert parse_llms_txt_links(llms_body, "https://docs.example.com/llms.txt") == [
        ("Auth Guide", "https://docs.example.com/a/b/auth.md")
    ]

    html_sections = (
        "<html><body>"
        "<h2>Setup</h2><p>Install package.</p>"
        "<h2>Login</h2><p>Use token.</p>"
        "</body></html>"
    )
    projected = project(html_sections, "https://docs.example.com/guide")
    assert filter_markdown_sections(projected.ordered_markdown, "setup") == (
        "## Setup\n\nInstall package."
    )
    assert filter_markdown_sections(projected.ordered_markdown, "login") == (
        "## Login\n\nUse token."
    )


@pytest.mark.parametrize(
    "html,markdown,links,empty",
    [
        (
            '<base><base href="/base/"><a href="next">Next</a>',
            "[Next](http://127.0.0.1:8765/base/next)",
            ["http://127.0.0.1:8765/base/next"],
            True,
        ),
        (
            "<ul><li>outer <ul><li>inner</li></ul></li></ul>",
            "outer inner\n\ninner",
            [],
            False,
        ),
        ("<blockquote><pre>x</blockquote></pre>", "x\n\nx", [], False),
        ("<p></p><h2></h2>", "", [], True),
    ],
)
def test_projection_handles_empty_base_nested_lists_and_unmatched_end_tags(
    html: str, markdown: str, links: list[str], empty: bool
) -> None:
    page = project(html, BASE)
    assert page.markdown == markdown
    assert page.links == links
    assert page.empty is empty


def test_ordered_projection_keeps_each_link_in_its_section() -> None:
    from nbrowser.static_extract import filter_markdown_sections, project

    html = (
        "<h1>Docs</h1><h2>Setup</h2>"
        '<p>Setup body <a href="https://example.com/setup">setup link</a></p>'
        '<h2>Login</h2><p>Login body <a href="https://example.com/login">login link</a></p>'
    )
    login = filter_markdown_sections(
        project(html, "https://example.com/doc").ordered_markdown, "Login"
    )
    assert "[login link](https://example.com/login)" in login
    assert "setup" not in login


def test_a_link_after_a_heading_inside_one_block_stays_under_that_heading() -> None:
    from nbrowser.static_extract import filter_markdown_sections, project

    html = (
        '<ul><li><h2>Login</h2><a href="/login">Login link</a></li>'
        '<li><h2>Setup</h2><a href="/setup">Setup link</a></li></ul>'
    )
    ordered = project(html, "https://example.com/doc").ordered_markdown
    login = filter_markdown_sections(ordered, "Login")
    assert "[Login link](https://example.com/login)" in login
    assert "Setup" not in login
    # Text after a heading inside one block follows that heading.
    body = project(
        "<li><h2>Login</h2>Login body</li>", "https://e.com/"
    ).ordered_markdown
    assert body == "## Login\n\nLogin body"
