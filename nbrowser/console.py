"""Closed console metadata; raw console payloads are never represented."""

import enum
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from nott_spine import ReceiptRung, TaintClass


class ConsoleLevel(str, enum.Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class ConsoleCategory(str, enum.Enum):
    LOG = "log"
    DIAGNOSTIC = "diagnostic"
    ASSERTION = "assertion"
    GROUP = "group"
    OTHER = "other"


# The console ceiling a single read returns, merged across every session ring.
CONSOLE_RING = 200
# shortcut: one process holds rings for at most this many CDP sessions. The key
# is any CDP session, so an auto-attached iframe or worker counts like a tab.
# When a new session would exceed it, the ring whose newest entry is oldest
# drops first, so eviction follows the last write and not creation order. Raise
# only if a host attaches more sessions than this in one server process.
MAX_SESSION_RINGS = 32


class Sequenced(Protocol):
    """An entry whose append sequence places it in one global order. The
    attribute is read as a property, so a frozen entry dataclass fits."""

    @property
    def seq(self) -> int: ...


# shortcut: a merged read takes one entry from each ring that holds one,
# starting with the newest of each ring, then the second newest, and so on,
# until the ceiling is reached. Every ring that holds an entry is therefore in
# the read: at MAX_SESSION_RINGS that is at least 6 console and 15 network
# entries each.
def merge_rings[T: Sequenced](rings: Iterable[Sequence[T]], ceiling: int) -> list[T]:
    """At most `ceiling` entries, newest last. The console buffer and the
    network read share this; with one ring the answer is that ring's newest
    entries."""
    filled = [ring for ring in rings if ring]
    picked: list[T] = []
    rank = 0
    while len(picked) < ceiling:
        took = False
        for ring in filled:
            if rank >= len(ring):
                continue
            picked.append(ring[-1 - rank])
            took = True
            if len(picked) == ceiling:
                break
        if not took:
            break
        rank += 1
    picked.sort(key=lambda entry: entry.seq)
    return picked


def least_recent_key[T: Sequenced](rings: Mapping[str, Sequence[T]]) -> str:
    """Which ring to drop: the one written least recently, so a session that
    attached first and still works keeps its ring."""
    return min(rings, key=lambda key: rings[key][-1].seq)


@dataclass(frozen=True)
class ConsoleEntry:
    level: ConsoleLevel
    category: ConsoleCategory
    seq: int = 0

    def to_dict(self) -> dict[str, str]:
        return {
            "level": self.level.value,
            "category": self.category.value,
        }


@dataclass
class ConsoleEvidence:
    entries: list[ConsoleEntry] = field(default_factory=list)
    taint: str = "page_derived"
    rung: str = "un_witnessed_local"

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "taint": self.taint,
            "rung": self.rung,
        }


class ConsoleBuffer:
    """One bounded ring per CDP sessionId, written by the CDP reader thread
    and read by the handler. Events with no sessionId share one ring. A read
    takes entries from every ring that holds one and returns at most
    CONSOLE_RING entries, newest last."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.rings: dict[str, list[ConsoleEntry]] = {}
        # A monotonic append sequence across all rings gives one global order.
        self._seq = 0

    def record(
        self, session_id: str, level: ConsoleLevel, category: ConsoleCategory
    ) -> None:
        with self.lock:
            if session_id not in self.rings and len(self.rings) >= MAX_SESSION_RINGS:
                self.rings.pop(least_recent_key(self.rings), None)
            ring = self.rings.setdefault(session_id, [])
            ring.append(ConsoleEntry(level=level, category=category, seq=self._seq))
            self._seq += 1
            if len(ring) > CONSOLE_RING:
                ring.pop(0)

    def drop(self, session_id: str) -> None:
        """Forget one session's ring: the CDP session was detached or disposed."""
        with self.lock:
            self.rings.pop(session_id, None)

    def evidence(self) -> ConsoleEvidence:
        with self.lock:
            rings = [list(ring) for ring in self.rings.values()]
        return ConsoleEvidence(
            entries=merge_rings(rings, CONSOLE_RING),
            taint=TaintClass.PageDerived.value,
            rung=ReceiptRung.UnwitnessedLocal.value,
        )
