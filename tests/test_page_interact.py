"""nbrowser_page_interact end to end over the protocol double: the verbs it
applies, the seam refusal in front of them, and the origin guard in each
script it sends."""

import json
from typing import Any

import pytest
from cdp_double import CdpDouble, FakePage

from nbrowser.errors import AuthorityRequired
from nbrowser.interact import Interaction, interact, is_local_activation
from nbrowser.mcp_server import McpServer
from nbrowser.session import BrowserLaunchConfig, BrowserSession

PUBLIC = "https://93.184.216.34/app"


def _server(url: str) -> McpServer:
    page = FakePage(url, "Fixture", '<input id="x" type="text"><div id="menu">')
    server = McpServer()
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: CdpDouble([page])
    )
    return server


@pytest.mark.parametrize(
    "params",
    [
        {"verb": "hover", "selector": "#menu"},
        {"verb": "focus", "selector": "#x"},
        {"verb": "click", "selector": "#x"},
    ],
)
def test_activation_verbs_apply_on_a_public_page(params: dict[str, Any]) -> None:
    server = _server(PUBLIC)
    try:
        out = server.handle_tool_call("nbrowser_page_interact", params)
    finally:
        server.close()
    assert out == {
        "status": "applied",
        "verb": params["verb"],
        "url": PUBLIC,
        "observed_state": "succeeded",
    }


@pytest.mark.parametrize("verb", ["back", "refresh", "dialog", "touch", "upload"])
def test_non_local_verbs_are_refused_by_the_seam(verb: str) -> None:
    server = _server(PUBLIC)
    try:
        with pytest.raises(AuthorityRequired) as refused:
            server.handle_tool_call(
                "nbrowser_page_interact", {"verb": verb, "selector": "#x", "text": "t"}
            )
    finally:
        server.close()
    assert refused.value.target == PUBLIC


def test_overlay_interception_and_human_seed_trajectory_and_select_options() -> None:
    rec = _Recorder({"error": "intercepted:div#cookie-banner"})
    with pytest.raises(Exception) as exc_info:
        interact(
            rec,  # type: ignore[arg-type]
            Interaction(
                verb="click",
                selector="#buy",
                expected_origin="https://a.example",
            ),
            "t0",
        )
    assert "cookie-banner" in str(exc_info.value)

    rec_sel = _Recorder(
        {
            "error": 'No option matched ["pro"]. Available options: free ("Free"), team ("Team")'
        }
    )
    with pytest.raises(Exception) as sel_exc:
        interact(
            rec_sel,  # type: ignore[arg-type]
            Interaction(
                verb="select",
                selector="#plan",
                value="pro",
                expected_origin="https://a.example",
            ),
            "t0",
        )
    assert "Available options:" in str(sel_exc.value)

    server = _server(PUBLIC)
    try:
        snap = server.handle_tool_call("nbrowser_page_snapshot", {})
        ref = snap["view"]["elements"][0]["ref"]
        assert ref == "@e1"
        delta_snap = server.handle_tool_call("nbrowser_page_snapshot", {"delta": True})
        assert "delta" in delta_snap
        assert delta_snap["delta"]["changed"] is False
        out = server.handle_tool_call(
            "nbrowser_page_interact",
            {"verb": "click", "ref": "@e1", "human": True, "seed": 42},
        )
        assert out["status"] == "applied"
    finally:
        server.close()


@pytest.mark.parametrize("url", ["http://10.0.0.7/app", "http://169.254.169.254/"])
def test_activation_on_a_private_page_is_refused_by_the_seam(url: str) -> None:
    server = _server(url)
    try:
        with pytest.raises(AuthorityRequired):
            server.handle_tool_call(
                "nbrowser_page_interact", {"verb": "click", "selector": "#x"}
            )
    finally:
        server.close()


class _Recorder:
    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.scripts: list[str] = []

    def evaluate(self, tab_id: str, script: str) -> Any:
        self.scripts.append(script)
        return self.answer


class _ArmOnly:
    released: list[str] = []  # noqa: RUF012

    def arm_secret(
        self, session_id: str, origin: str, secret: str, charsets: Any = ()
    ) -> None:
        pass

    def release_submit_lock(self, session_id: str) -> None:
        self.released.append(session_id)


class _GuardedRecorder(_Recorder):
    client = _ArmOnly()

    def _session_for(self, tab_id: str) -> str:
        return f"s-{tab_id}"


@pytest.mark.parametrize("verb", ["click", "scroll", "hover", "focus"])
def test_every_applied_verb_guards_the_expected_origin(verb: str) -> None:
    rec = _Recorder(True)
    interaction = Interaction(
        verb=verb, selector="#x", expected_origin="https://a.example", y=10
    )
    assert interact(rec, interaction, "t0")  # type: ignore[arg-type]
    script = rec.scripts[0]
    assert "window.location.origin !==" in script
    assert '"https://a.example"' in script


def test_hover_on_another_origin_is_not_applied() -> None:
    page = FakePage(PUBLIC, "Fixture", '<div id="menu">')
    session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: CdpDouble([page])
    )
    try:
        moved = Interaction(
            verb="hover", selector="#menu", expected_origin="https://other.example"
        )
        assert not interact(session, moved, "t0")
        assert page.clicks == {}
        same = Interaction(
            verb="hover", selector="#menu", expected_origin="https://93.184.216.34"
        )
        assert interact(session, same, "t0")
        assert page.clicks == {"#menu": 1}
    finally:
        session.close_session()


@pytest.mark.parametrize("verb", ["drag", "dialog"])
def test_a_verb_with_no_dispatch_is_not_applied(verb: str) -> None:
    rec = _Recorder(True)
    assert not interact(rec, Interaction(verb=verb, key="Escape"), "t0")  # type: ignore[arg-type]
    assert rec.scripts == []


def test_an_object_without_a_verb_is_not_a_local_activation() -> None:
    assert not is_local_activation(object())


def test_auth_login_enforces_origin_and_formaction_origin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    from nbrowser import auth

    store_dir = tmp_path / "db"
    store_dir.mkdir(mode=0o700)
    monkeypatch.setenv("NOTT_DATABASE_DIR", str(store_dir))

    auth.save_profile(
        name="corp-sso",
        url="https://93.184.216.34/login",
        username="alice",
        password="top-secret-password-99",
    )

    # 1. Wrong page origin is refused before touching the DOM:
    rec_wrong = _Recorder({"ok": True})
    with pytest.raises(AuthorityRequired):
        interact(
            rec_wrong,  # type: ignore[arg-type]
            Interaction(
                verb="auth_login",
                value="corp-sso",
                expected_origin="https://evil.example",
            ),
            "t0",
        )
    assert rec_wrong.scripts == []

    # 2. Form or submitter formaction pointing to another origin is refused:
    rec_hijack = _GuardedRecorder(
        {"error": "action_origin_mismatch:https://evil.example"}
    )
    with pytest.raises(AuthorityRequired):
        interact(
            rec_hijack,  # type: ignore[arg-type]
            Interaction(
                verb="auth_login",
                value="corp-sso",
                expected_origin="https://93.184.216.34",
            ),
            "t0",
        )

    # A fill refused after arming releases the submit lock it armed.
    class _ProbeThenRefuse(_GuardedRecorder):
        def evaluate(self, tab_id: str, script: str) -> Any:
            self.scripts.append(script)
            if len(self.scripts) == 1:
                return {"ok": True}
            return {"error": "action_origin_mismatch:https://evil.example"}

    _ArmOnly.released.clear()
    with pytest.raises(AuthorityRequired):
        interact(
            _ProbeThenRefuse(None),  # type: ignore[arg-type]
            Interaction(
                verb="auth_login",
                value="corp-sso",
                expected_origin="https://93.184.216.34",
            ),
            "t0",
        )
    assert _ArmOnly.released == ["s-t0"]
    # 3. Matching page and formaction origin succeeds:
    rec_ok = _GuardedRecorder({"ok": True})
    assert interact(
        rec_ok,  # type: ignore[arg-type]
        Interaction(
            verb="auth_login",
            value="corp-sso",
            expected_origin="https://93.184.216.34",
        ),
        "t0",
    )
    # 4. Script re-validates origin after input/change and guards submit:
    assert "resolveOrigin()" in rec_ok.scripts[1]
    assert "addEventListener('submit'" in rec_ok.scripts[1]


def test_click_validates_target_before_clicking_and_submit_calls_request_submit() -> (
    None
):
    class _TwoStepRecorder:
        def __init__(self, answers: list[Any]) -> None:
            self.answers = list(answers)
            self.scripts: list[str] = []

        def evaluate(self, tab_id: str, script: str) -> Any:
            self.scripts.append(script)
            return self.answers.pop(0) if self.answers else None

    # Pre-check returns forbidden loopback target from public origin -> raises AuthorityRequired
    # BEFORE any second evaluate() that would call node.click()
    rec_ssrf = _TwoStepRecorder(
        [{"ok": True, "x": 10.0, "y": 10.0, "targetUrl": "http://127.0.0.1:8080/admin"}]
    )
    with pytest.raises(AuthorityRequired):
        interact(
            rec_ssrf,  # type: ignore[arg-type]
            Interaction(
                verb="click",
                selector="a#internal",
                expected_origin="https://example.com",
            ),
            "t0",
        )
    assert len(rec_ssrf.scripts) == 1
    assert "node.click()" not in rec_ssrf.scripts[0]

    # When pre-check passes, second step executes click or requestSubmit on <form>
    rec_submit = _TwoStepRecorder(
        [
            {"ok": True, "x": 10.0, "y": 10.0, "targetUrl": "https://example.com/post"},
            {"ok": True},
        ]
    )
    assert interact(
        rec_submit,  # type: ignore[arg-type]
        Interaction(
            verb="submit",
            selector="form#f",
            expected_origin="https://example.com",
        ),
        "t0",
    )
    assert len(rec_submit.scripts) == 2
    assert "requestSubmit" in rec_submit.scripts[1]


def test_auth_login_arms_the_network_guard_before_the_password_reaches_the_page(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    from nbrowser import auth
    from nbrowser.errors import BrowserError

    store_dir = tmp_path / "db"
    store_dir.mkdir(mode=0o700)
    monkeypatch.setenv("NOTT_DATABASE_DIR", str(store_dir))
    auth.save_profile(
        name="corp-sso",
        url="https://93.184.216.34/login",
        username="alice",
        password="top-secret-password-99",
    )
    order: list[str] = []

    class _Client:
        def arm_secret(
            self, session_id: str, origin: str, secret: str, charsets: Any = ()
        ) -> None:
            order.append(f"arm {session_id} {origin} {secret} {','.join(charsets)}")

        def release_submit_lock(self, session_id: str) -> None:
            order.append(f"release:{session_id}")

    class _Guarded(_Recorder):
        client = _Client()

        def _session_for(self, tab_id: str) -> str:
            return f"s-{tab_id}"

        def evaluate(self, tab_id: str, script: str) -> Any:
            order.append("evaluate")
            return super().evaluate(tab_id, script)

    login = Interaction(
        verb="auth_login", value="corp-sso", expected_origin="https://93.184.216.34"
    )
    guarded = _Guarded({"ok": True, "charsets": ["Shift_JIS"]})
    assert interact(guarded, login, "t0")  # type: ignore[arg-type]
    # The probe reads the form charset without the password; the guard is
    # armed in that charset; only then does the password reach the page.
    assert order == [
        "evaluate",
        "arm s-t0 https://93.184.216.34 top-secret-password-99 Shift_JIS",
        "evaluate",
    ]
    assert "top-secret-password-99" not in guarded.scripts[0]
    assert "document.characterSet" in guarded.scripts[0]
    assert "top-secret-password-99" in guarded.scripts[1]
    # A session without the network guard never receives the password.
    bare = _Recorder({"ok": True})
    with pytest.raises(BrowserError):
        interact(bare, login, "t0")  # type: ignore[arg-type]
    assert bare.scripts == []


def test_click_activates_once_and_typing_falls_back_only_without_an_input_event() -> (
    None
):
    from nbrowser.interact import _resolve_node_js

    class _Steps:
        def __init__(self, answers: list[Any]) -> None:
            self.answers = answers
            self.scripts: list[str] = []

        def evaluate(self, tab_id: str, script: str) -> Any:
            self.scripts.append(script)
            return self.answers.pop(0)

    click = _Steps([{"ok": True, "x": 0.0, "y": 0.0, "targetUrl": None}, {"ok": True}])
    assert interact(
        click,  # type: ignore[arg-type]
        Interaction(verb="click", selector="input[type=radio]"),
        "t0",
    )
    act = click.scripts[1]
    # One click on the element; the other is the form-only submit fallback.
    assert act.count(".click()") == 2
    assert "checkTarget" not in act

    sent: list[tuple[str, Any]] = []

    class _Client:
        def send(self, method: str, params: Any, session_id: str) -> None:
            sent.append((method, params))

    class _Typing(_Steps):
        client = _Client()

        def _session_for(self, tab_id: str) -> str:
            return f"s-{tab_id}"

    # Text goes in once, by CDP, into an element that holds focus; no DOM rewrite.
    typing = _Typing([{"ok": True}, True])
    assert interact(
        typing,  # type: ignore[arg-type]
        Interaction(verb="type", selector="#q", text="abc"),
        "t0",
    )
    assert sent == [("Input.insertText", {"text": "abc"})]
    assert "document.activeElement" in typing.scripts[0]
    assert all("node.value =" not in s for s in typing.scripts[1:])
    assert all("nbrowser.inputSeen" not in s for s in typing.scripts)
    # Without a CDP client nothing can type: not applied.
    assert not interact(
        _Steps([{"ok": True}]),  # type: ignore[arg-type]
        Interaction(verb="type", selector="#q", text="abc"),
        "t0",
    )

    # A ref never falls back to its CSS selector, with or without the ref store.
    ref_js = _resolve_node_js(
        Interaction(verb="click", selector="#buy", node_uid=7, doc_gen="dg-1")
    )
    after_uid = ref_js.split("if (reqUid !== null)", 1)[1].split("const sel =", 1)[0]
    assert after_uid.rstrip().endswith("return { error: 'stale_ref' };\n        }")


def test_press_key_focuses_its_target_and_judges_the_form_destination() -> None:
    rec = _Recorder({"ok": True, "targetUrl": None})
    interact(
        rec,  # type: ignore[arg-type]
        Interaction(
            verb="press_key",
            selector="#y",
            key="Enter",
            expected_origin="https://a.example",
        ),
        "t0",
    )
    check = rec.scripts[0]
    # Keys go to the focused element, so the named target takes focus first.
    assert "node.focus()" in check
    # Implicit submission sends the form to its default button's formaction or
    # to form.action; a text field's formAction (the page URL) is not it.
    assert "node.formAction" not in check
    assert "defaultButton" in check


def test_an_interact_refusal_carries_its_reason_to_the_agent() -> None:
    from nbrowser.errors import BrowserError, InputFailure

    server = McpServer()

    def refuse(name: str, args: dict[str, Any]) -> dict[str, Any]:
        raise BrowserError(
            InputFailure.SELECTOR,
            'No option matched ["pro"]. Available options: free ("Free")',
        )

    server.handle_tool_call = refuse  # type: ignore[method-assign]
    out = server.call_tool("nbrowser_page_interact", {"verb": "select"})
    envelope = json.loads(out["content"][0]["text"])
    assert envelope["code"] == "invalid_input"
    assert "Available options: free" in envelope["message"]


def test_the_interact_description_names_every_dispatched_verb() -> None:
    import re

    from nbrowser.interact import ALLOWED_INTERACTION_VERBS
    from nbrowser.mcp_server import TOOL_DESCRIPTIONS

    desc = TOOL_DESCRIPTIONS["nbrowser_page_interact"]
    listed = re.search(r"dispatches these eleven verbs: ([a-z_, ]+)\.", desc)
    assert listed is not None, "the description must list the verbs it dispatches"
    named = {part for part in re.split(r",\s+| and ", listed.group(1)) if part}
    assert named == set(ALLOWED_INTERACTION_VERBS)
    assert "back, refresh and dialog refuse with grant_required" in desc
    assert "drag refuses with invalid_input" in desc


@pytest.mark.parametrize(
    ("verb", "code"),
    [
        ("back", "grant_required"),
        ("refresh", "grant_required"),
        ("dialog", "grant_required"),
        ("drag", "invalid_input"),
    ],
)
def test_refused_verbs_answer_with_the_code_the_description_names(
    verb: str, code: str
) -> None:
    server = _server(PUBLIC)
    try:
        out = server.call_tool(
            "nbrowser_page_interact", {"verb": verb, "selector": "#x"}
        )
    finally:
        server.close()
    assert out["isError"] is True
    assert json.loads(out["content"][0]["text"])["code"] == code


def test_press_key_is_applied_at_the_door() -> None:
    server = _server(PUBLIC)
    try:
        out = server.handle_tool_call(
            "nbrowser_page_interact", {"verb": "press_key", "key": "Escape"}
        )
    finally:
        server.close()
    assert out == {
        "status": "applied",
        "verb": "press_key",
        "url": PUBLIC,
        "observed_state": "succeeded",
    }


def test_a_submit_redirected_to_loopback_is_refused_before_the_click() -> None:
    class _OneAnswerRecorder:
        def __init__(self, answer: Any) -> None:
            self.answer = answer
            self.scripts: list[str] = []

        def evaluate(self, tab_id: str, script: str) -> Any:
            self.scripts.append(script)
            return self.answer

    rec = _OneAnswerRecorder(
        {"ok": True, "x": 1.0, "y": 1.0, "targetUrl": "http://127.0.0.1:8080/admin"}
    )
    with pytest.raises(AuthorityRequired):
        interact(
            rec,  # type: ignore[arg-type]
            Interaction(
                verb="submit",
                selector="form#f",
                expected_origin="https://example.com",
            ),
            "t0",
        )
    # The guard reads the resolved action URL before any click step runs.
    assert len(rec.scripts) == 1


def test_egress_guard_keeps_no_activation_key_allowlist() -> None:
    from nbrowser import egress_guard

    assert not hasattr(egress_guard, "is_activation_key")
    assert not hasattr(egress_guard, "ACTIVATION_KEYS")


def test_an_enter_that_navigates_away_is_applied_not_a_timeout() -> None:
    from nbrowser.errors import BrowserError, ClosedFailure

    sent: list[tuple[str, Any, float]] = []

    class _Client:
        def send(
            self, method: str, params: Any, session_id: str, timeout: float = 30.0
        ) -> dict[str, Any]:
            sent.append((params["type"], params["key"], timeout))
            # The engine never answers the key that submitted the form: the
            # document that would answer it is gone.
            raise BrowserError(ClosedFailure.PROTOCOL, f"CDP timeout: {method}")

    class _Page(_Recorder):
        client = _Client()

        def _session_for(self, tab_id: str) -> str:
            return f"s-{tab_id}"

    page = _Page({"ok": True, "targetUrl": "https://a.example/post"})
    assert interact(
        page,  # type: ignore[arg-type]
        Interaction(
            verb="press_key",
            selector="#x",
            key="Enter",
            expected_origin="https://a.example",
        ),
        "t0",
    )
    assert [(t, k) for t, k, _ in sent] == [("keyDown", "Enter")]
    assert all(wait <= 5.0 for *_, wait in sent)
