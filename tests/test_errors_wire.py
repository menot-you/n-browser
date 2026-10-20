"""FailureCode.HOST_DEPENDENCY_MISSING: a host binary a tool shells out to is absent."""

from nbrowser.errors import BrowserError, FailureCode, failure_envelope, wire_code


def test_host_dependency_missing_has_its_own_wire_rung() -> None:
    assert FailureCode.HOST_DEPENDENCY_MISSING.value == "host_dependency_missing"
    assert wire_code("host_dependency_missing") == "host_dependency_missing"
    envelope = failure_envelope(
        BrowserError(FailureCode.HOST_DEPENDENCY_MISSING, "jq is not on PATH")
    )
    assert envelope == {
        "ok": False,
        "code": "host_dependency_missing",
        "taint": "page_derived",
        "rung": "un_witnessed_local",
    }
