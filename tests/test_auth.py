"""AES-256-GCM credential vault stored in nbrowser.sqlite3 via nott_database.connect,
with key isolated in nott_database.directory() / 'nbrowser.key'."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import nott_database
import pytest

from nbrowser import auth
from nbrowser.errors import BrowserError, InputFailure


def test_save_load_list_and_remove_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store_dir = tmp_path / "db"
    store_dir.mkdir(mode=0o700)
    monkeypatch.setenv("NOTT_DATABASE_DIR", str(store_dir))

    opened_paths: list[str] = []

    def audit_hook(event: str, args: tuple[Any, ...]) -> None:
        if (event == "open" or event.endswith(".connect")) and args:
            opened_paths.append(str(args[0]))

    sys.addaudithook(audit_hook)

    live_dir = str(nott_database.live_directory())
    auth.save_profile(
        name="my-app",
        url="https://app.example.com/login",
        username="alice@example.com",
        password="correct-horse-battery-staple",
        username_selector="#email",
        password_selector="#pass",
        submit_selector="#login-btn",
    )

    assert (store_dir / "nbrowser.sqlite3").exists()
    assert (store_dir / "nbrowser.key").exists()
    assert any(str(store_dir) in p for p in opened_paths)
    assert not any(live_dir in p for p in opened_paths)

    listed = auth.list_profiles()
    assert listed == [
        {
            "name": "my-app",
            "url": "https://app.example.com/login",
            "origin": "https://app.example.com",
            "username": "alice@example.com",
        }
    ]
    assert "password" not in listed[0]

    loaded = auth.load_profile("my-app")
    assert loaded.name == "my-app"
    assert loaded.origin == "https://app.example.com"
    assert loaded.username == "alice@example.com"
    assert loaded.password == "correct-horse-battery-staple"
    assert loaded.username_selector == "#email"
    assert loaded.password_selector == "#pass"
    assert loaded.submit_selector == "#login-btn"

    assert auth.remove_profile("my-app") is True
    assert auth.remove_profile("my-app") is False
    assert auth.list_profiles() == []


def test_aad_binds_name_origin_and_username_without_pipe_collision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store_dir = tmp_path / "db"
    store_dir.mkdir(mode=0o700)
    monkeypatch.setenv("NOTT_DATABASE_DIR", str(store_dir))

    auth.save_profile(
        name="p1",
        url="https://example.com/login",
        username="user|with|pipes",
        password="secret-password",
    )
    assert auth.load_profile("p1").password == "secret-password"

    conn = nott_database.connect(store_dir / "nbrowser.sqlite3")
    try:
        with nott_database.write(conn):
            conn.execute(
                "UPDATE credentials SET origin = ? WHERE name = ?",
                ("https://evil.example", "p1"),
            )
    finally:
        conn.close()

    with pytest.raises(BrowserError) as exc:
        auth.load_profile("p1")
    assert exc.value.code is InputFailure.OPERATION


def test_private_url_or_invalid_profile_name_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store_dir = tmp_path / "db"
    store_dir.mkdir(mode=0o700)
    monkeypatch.setenv("NOTT_DATABASE_DIR", str(store_dir))

    with pytest.raises(BrowserError):
        auth.save_profile(
            name="../bad",
            url="https://example.com/login",
            username="u",
            password="p",
        )

    with pytest.raises(BrowserError):
        auth.save_profile(
            name="private-target",
            url="http://169.254.169.254/login",
            username="u",
            password="p",
        )


def test_live_store_directory_and_symlink_alias_are_refused_under_pytest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    live = nott_database.live_directory()
    monkeypatch.setenv("NOTT_DATABASE_DIR", str(live))
    with pytest.raises(nott_database.RefusedError):
        auth.list_profiles()

    alias = tmp_path / "live-link"
    if live.exists():
        os.symlink(live, alias)
        monkeypatch.setenv("NOTT_DATABASE_DIR", str(alias))
        with pytest.raises(nott_database.RefusedError):
            auth.list_profiles()
