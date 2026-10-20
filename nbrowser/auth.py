"""AES-256-GCM credential vault persisted in nbrowser.sqlite3 via nott_database.connect.

Every credential row stores its secret password encrypted with AES-256-GCM via
OpenSSL's libcrypto (`EVP_aes_256_gcm`), authenticated with unambiguous JSON-array
AAD `[name, origin, username]`. The 256-bit vault key lives beside the store at
`nott_database.directory() / "nbrowser.key"` (mode 0600, validated via `os.lstat`
and `nott_database._admit` / `_check_directory` before any open or creation).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

import nott_database

from .egress_guard import is_public_safe
from .errors import BrowserError, InputFailure

_PROFILE_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
_STORE_FILENAME = "nbrowser.sqlite3"
_KEY_FILENAME = "nbrowser.key"
_EVP_CTRL_GCM_SET_IVLEN = 0x9
_EVP_CTRL_GCM_GET_TAG = 0x10
_EVP_CTRL_GCM_SET_TAG = 0x11

_DDL = """
CREATE TABLE IF NOT EXISTS credentials (
    name TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    origin TEXT NOT NULL,
    username TEXT NOT NULL,
    iv BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    tag BLOB NOT NULL,
    username_selector TEXT NOT NULL DEFAULT '',
    password_selector TEXT NOT NULL DEFAULT '',
    submit_selector TEXT NOT NULL DEFAULT ''
);
"""


@dataclass(frozen=True)
class AuthProfile:
    name: str
    url: str
    origin: str
    username: str
    password: str
    username_selector: str = "input[type='email'], input[name='username'], input[name='email'], input[type='text']"
    password_selector: str = "input[type='password']"
    submit_selector: str = "button[type='submit'], input[type='submit'], button"


def origin_of(parts: SplitResult) -> str:
    port_val = parts.port
    is_default = (parts.scheme == "https" and port_val == 443) or (
        parts.scheme == "http" and port_val == 80
    )
    port = f":{port_val}" if (port_val and not is_default) else ""
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{parts.scheme}://{host}{port}"


def _validate_profile_name(name: str) -> None:
    if not name or not _PROFILE_NAME_RE.match(name):
        raise BrowserError(
            InputFailure.OPERATION,
            f"invalid credential profile name {name!r}: must match ^[a-zA-Z0-9_-]+$",
        )


def _libcrypto() -> ctypes.CDLL:
    lib_name = ctypes.util.find_library("crypto") or "libcrypto.so.3"
    lib = ctypes.CDLL(lib_name)
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
    lib.EVP_EncryptInit_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    lib.EVP_EncryptUpdate.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    lib.EVP_EncryptFinal_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    lib.EVP_DecryptInit_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    lib.EVP_DecryptUpdate.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    lib.EVP_DecryptFinal_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
    ]
    return lib


def _aad_bytes(name: str, origin: str, username: str) -> bytes:
    return json.dumps([name, origin, username], separators=(",", ":")).encode("utf-8")


def _aes_gcm_encrypt(
    key: bytes, plaintext: bytes, aad: bytes
) -> tuple[bytes, bytes, bytes]:
    lib = _libcrypto()
    iv = os.urandom(12)
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise BrowserError(InputFailure.OPERATION, "EVP_CIPHER_CTX_new failed")
    try:
        cipher = lib.EVP_aes_256_gcm()
        if lib.EVP_EncryptInit_ex(ctx, cipher, None, None, None) != 1:
            raise BrowserError(InputFailure.OPERATION, "EVP_EncryptInit_ex failed")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_IVLEN, len(iv), None) != 1:
            raise BrowserError(InputFailure.OPERATION, "GCM set IV length failed")
        if lib.EVP_EncryptInit_ex(ctx, None, None, key, iv) != 1:
            raise BrowserError(InputFailure.OPERATION, "EVP_EncryptInit_ex key failed")
        out_len = ctypes.c_int(0)
        if aad and (
            lib.EVP_EncryptUpdate(ctx, None, ctypes.byref(out_len), aad, len(aad)) != 1
        ):
            raise BrowserError(InputFailure.OPERATION, "EVP_EncryptUpdate AAD failed")
        out_buf = ctypes.create_string_buffer(len(plaintext) + 16)
        if (
            lib.EVP_EncryptUpdate(
                ctx, out_buf, ctypes.byref(out_len), plaintext, len(plaintext)
            )
            != 1
        ):
            raise BrowserError(InputFailure.OPERATION, "EVP_EncryptUpdate failed")
        total = out_len.value
        final_len = ctypes.c_int(0)
        final_buf = ctypes.create_string_buffer(16)
        if lib.EVP_EncryptFinal_ex(ctx, final_buf, ctypes.byref(final_len)) != 1:
            raise BrowserError(InputFailure.OPERATION, "EVP_EncryptFinal_ex failed")
        ciphertext = out_buf.raw[:total] + final_buf.raw[: final_len.value]
        tag_buf = ctypes.create_string_buffer(16)
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_GET_TAG, 16, tag_buf) != 1:
            raise BrowserError(InputFailure.OPERATION, "GCM get tag failed")
        return iv, ciphertext, tag_buf.raw
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def _aes_gcm_decrypt(
    key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes
) -> bytes:
    if len(iv) != 12 or len(tag) != 16:
        raise BrowserError(InputFailure.OPERATION, "invalid GCM IV or tag length")
    lib = _libcrypto()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise BrowserError(InputFailure.OPERATION, "EVP_CIPHER_CTX_new failed")
    try:
        cipher = lib.EVP_aes_256_gcm()
        if lib.EVP_DecryptInit_ex(ctx, cipher, None, None, None) != 1:
            raise BrowserError(InputFailure.OPERATION, "EVP_DecryptInit_ex failed")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_IVLEN, len(iv), None) != 1:
            raise BrowserError(InputFailure.OPERATION, "GCM set IV length failed")
        if lib.EVP_DecryptInit_ex(ctx, None, None, key, iv) != 1:
            raise BrowserError(InputFailure.OPERATION, "EVP_DecryptInit_ex key failed")
        out_len = ctypes.c_int(0)
        if aad and (
            lib.EVP_DecryptUpdate(ctx, None, ctypes.byref(out_len), aad, len(aad)) != 1
        ):
            raise BrowserError(InputFailure.OPERATION, "EVP_DecryptUpdate AAD failed")
        out_buf = ctypes.create_string_buffer(len(ciphertext) + 16)
        if (
            lib.EVP_DecryptUpdate(
                ctx, out_buf, ctypes.byref(out_len), ciphertext, len(ciphertext)
            )
            != 1
        ):
            raise BrowserError(InputFailure.OPERATION, "EVP_DecryptUpdate failed")
        total = out_len.value
        tag_buf = ctypes.create_string_buffer(tag, 16)
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_TAG, 16, tag_buf) != 1:
            raise BrowserError(InputFailure.OPERATION, "GCM set tag failed")
        final_len = ctypes.c_int(0)
        final_buf = ctypes.create_string_buffer(16)
        if lib.EVP_DecryptFinal_ex(ctx, final_buf, ctypes.byref(final_len)) != 1:
            raise BrowserError(
                InputFailure.OPERATION,
                "credential authentication failed (GCM tag or AAD mismatch)",
            )
        return out_buf.raw[:total] + final_buf.raw[: final_len.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def _store_folder(*, allow_live_store: bool) -> Path:
    folder = nott_database.directory().absolute()
    nott_database._admit(folder, allow_live_store)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    nott_database._check_directory(folder)
    return folder


def _ensure_key(*, allow_live_store: bool) -> bytes:
    folder = _store_folder(allow_live_store=allow_live_store)
    key_path = folder / _KEY_FILENAME
    try:
        st = os.lstat(key_path)
    except FileNotFoundError:
        key_bytes = os.urandom(32)
        fd = os.open(
            key_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.write(fd, key_bytes.hex().encode("ascii") + b"\n")
        finally:
            os.close(fd)
        return key_bytes

    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise nott_database.RefusedError(f"{key_path} must be a single regular file")
    nott_database._owned_private(st, key_path)
    raw_hex = key_path.read_text(encoding="ascii").strip()
    if len(raw_hex) != 64:
        raise BrowserError(InputFailure.OPERATION, f"invalid key length in {key_path}")
    return bytes.fromhex(raw_hex)


def _open_store(*, allow_live_store: bool) -> nott_database.Connection:
    folder = _store_folder(allow_live_store=allow_live_store)
    db_path = folder / _STORE_FILENAME
    if not db_path.exists():
        nott_database.create(db_path, _DDL, allow_live_store=allow_live_store)
    conn = nott_database.connect(db_path, allow_live_store=allow_live_store)
    try:
        with nott_database.write(conn):
            conn.executescript(_DDL)
    except BaseException:
        conn.close()
        raise
    return conn


def save_profile(
    name: str,
    url: str,
    username: str,
    password: str,
    username_selector: str = "input[type='email'], input[name='username'], input[name='email'], input[type='text']",
    password_selector: str = "input[type='password']",
    submit_selector: str = "button[type='submit'], input[type='submit'], button",
    *,
    allow_live_store: bool = False,
) -> dict[str, str]:
    _validate_profile_name(name)
    if not is_public_safe(url):
        raise BrowserError(
            InputFailure.OPERATION, f"credential URL refused by egress guard: {url}"
        )
    parts = urlsplit(url)
    origin = origin_of(parts)
    key = _ensure_key(allow_live_store=allow_live_store)
    aad = _aad_bytes(name, origin, username)
    iv, ciphertext, tag = _aes_gcm_encrypt(key, password.encode("utf-8"), aad)

    conn = _open_store(allow_live_store=allow_live_store)
    try:
        with nott_database.write(conn):
            conn.execute(
                """
                INSERT INTO credentials (
                    name, url, origin, username, iv, ciphertext, tag,
                    username_selector, password_selector, submit_selector
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    url = excluded.url,
                    origin = excluded.origin,
                    username = excluded.username,
                    iv = excluded.iv,
                    ciphertext = excluded.ciphertext,
                    tag = excluded.tag,
                    username_selector = excluded.username_selector,
                    password_selector = excluded.password_selector,
                    submit_selector = excluded.submit_selector
                """,
                (
                    name,
                    url,
                    origin,
                    username,
                    iv,
                    ciphertext,
                    tag,
                    username_selector,
                    password_selector,
                    submit_selector,
                ),
            )
    finally:
        conn.close()
    return {"name": name, "url": url, "origin": origin, "username": username}


def load_profile(name: str, *, allow_live_store: bool = False) -> AuthProfile:
    _validate_profile_name(name)
    key = _ensure_key(allow_live_store=allow_live_store)
    conn = _open_store(allow_live_store=allow_live_store)
    try:
        rows = nott_database.query(
            conn,
            """
            SELECT name, url, origin, username, iv, ciphertext, tag,
                   username_selector, password_selector, submit_selector
            FROM credentials
            WHERE name = ?
            """,
            (name,),
        )
        row = rows[0] if rows else None
    finally:
        conn.close()
    if row is None:
        raise BrowserError(
            InputFailure.OPERATION, f"unknown credential profile: {name}"
        )
    r_name = str(row[0])
    r_url = str(row[1])
    r_origin = str(row[2])
    r_username = str(row[3])
    aad = _aad_bytes(r_name, r_origin, r_username)
    plaintext = _aes_gcm_decrypt(key, bytes(row[4]), bytes(row[5]), bytes(row[6]), aad)
    return AuthProfile(
        name=r_name,
        url=r_url,
        origin=r_origin,
        username=r_username,
        password=plaintext.decode("utf-8"),
        username_selector=str(row[7]),
        password_selector=str(row[8]),
        submit_selector=str(row[9]),
    )


def list_profiles(*, allow_live_store: bool = False) -> list[dict[str, Any]]:
    conn = _open_store(allow_live_store=allow_live_store)
    try:
        rows = nott_database.query(
            conn,
            "SELECT name, url, origin, username FROM credentials ORDER BY name ASC",
        )
    finally:
        conn.close()
    return [
        {
            "name": str(r[0]),
            "url": str(r[1]),
            "origin": str(r[2]),
            "username": str(r[3]),
        }
        for r in rows
    ]


def remove_profile(name: str, *, allow_live_store: bool = False) -> bool:
    _validate_profile_name(name)
    conn = _open_store(allow_live_store=allow_live_store)
    try:
        with nott_database.write(conn):
            cur = conn.execute("DELETE FROM credentials WHERE name = ?", (name,))
            return cur.rowcount > 0
    finally:
        conn.close()
