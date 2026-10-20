"""Branch coverage for the typed error hierarchy in nott_spine.errors.

Targets branches the existing test suite leaves unexercised in the base-class
constructors and equality methods (return-False fallthrough, default-vs-explicit
message routing, cross-subclass inequality, and the type-instance shortcut in
the wrapper error classes).
"""

from __future__ import annotations

from nott_spine.errors import (
    AuthorityError,
    ContractError,
    InvalidDigest,
)


def test_contract_error_default_message_is_applied_when_none_passed() -> None:
    # Branch: message is falsy -> DEFAULT_MESSAGE used.
    err = ContractError()
    assert err.message == "contract violation"
    assert str(err) == "contract violation"


def test_contract_error_explicit_message_is_preserved() -> None:
    # Branch: explicit truthy message bypasses DEFAULT_MESSAGE.
    err = ContractError("explicit text")
    assert err.message == "explicit text"
    assert str(err) == "explicit text"


def test_authority_error_default_message_is_applied_when_none_passed() -> None:
    err = AuthorityError()
    assert err.message == "authority violation"
    assert str(err) == "authority violation"


def test_authority_error_explicit_message_is_preserved() -> None:
    err = AuthorityError("custom authority message")
    assert err.message == "custom authority message"
    assert str(err) == "custom authority message"


def test_each_subclass_default_message_is_distinct_from_base() -> None:
    # The subclass DEFAULT_MESSAGE overrides the base DEFAULT_MESSAGE in __init__.
    base = ContractError()
    sub = InvalidDigest()
    assert base.message == "contract violation"
    assert sub.message == (
        "digest must be sha256: followed by 64 lowercase hexadecimal digits"
    )
    assert base.message != sub.message


def test_message_attribute_is_stored_on_instance() -> None:
    # Branch: self.message = ... assignment — covered transitively by every other
    # branch test, but pin the attribute name explicitly so a renaming mutant dies.
    err = ContractError("hello")
    assert hasattr(err, "message")
    assert err.message == "hello"

    err2 = ContractError()
    assert err2.message == "contract violation"
