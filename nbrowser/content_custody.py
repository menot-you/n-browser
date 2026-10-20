import threading

from .errors import BrowserError, FailureCode, InputFailure


class FixtureContentResolver:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.store: dict[str, bytes] = {}
        self.kinds: dict[str, str] = {}
        self.texts: dict[str, str] = {}

    def store_bytes(self, digest: str, data: bytes, kind: str = "binary") -> None:
        with self.lock:
            self.store[digest] = data
            self.kinds[digest] = kind

    def holds(self, digest: str) -> bool:
        """Whether the bytes are still in custody: resolve_once pops them."""
        with self.lock:
            return digest in self.store

    def resolve_once(self, digest: str) -> bytes:
        with self.lock:
            if digest not in self.store:
                raise BrowserError(
                    FailureCode.CONTENT_UNAVAILABLE,
                    f"content {digest} unavailable or already resolved",
                )
            self.kinds.pop(digest)
            self.texts.pop(digest, None)
            return self.store.pop(digest)

    def resolve_text_page(
        self, digest: str, offset: int, max_chars: int
    ) -> tuple[str, int | None, int]:
        with self.lock:
            if digest not in self.store:
                raise BrowserError(
                    FailureCode.CONTENT_UNAVAILABLE,
                    "content unavailable or already resolved",
                )
            kind = self.kinds[digest]
            if kind != "text":
                raise BrowserError(
                    FailureCode.CONTENT_UNAVAILABLE,
                    f"artifact kind {kind} cannot be read as text",
                )
            # shortcut: one decoded copy per open text artifact, release it per page if memory matters
            text = self.texts.get(digest)
            if text is None:
                text = self.store[digest].decode("utf-8")
                self.texts[digest] = text
            total = len(text)
            if offset > total:
                raise BrowserError(InputFailure.OPERATION, "offset exceeds total_chars")
            end = min(offset + min(max_chars, 200000), total)
            if end == total:
                del self.store[digest]
                del self.kinds[digest]
                del self.texts[digest]
            return text[offset:end], end if end < total else None, total
