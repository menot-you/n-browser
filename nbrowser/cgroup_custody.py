"""Kernel-held custody of the engine subtree.

A userspace reaper decides membership from a pid it walked to and a signal the
target may ignore. `os.setsid` — which the launcher calls, and which is exactly
why abandoned engines became unreachable — rewrites the session and the process
group, so `killpg` loses the tree it was aimed at.

A cgroup needs none of it. Membership is INHERITED, so `setsid` cannot leave
one, and it survives the death of every ancestor. One write to `cgroup.kill`
reaps the whole subtree: no pid named, no signal to trap, no window between
deciding and acting.

Custody is a REFUSAL, never a degrade: without a reapable cgroup there is no
second line of defence left in this port, so every path that cannot hold
custody raises `ClosedFailure.LAUNCH` rather than launching an engine nothing
can reach.
"""

import errno
from pathlib import Path

from .errors import BrowserError, ClosedFailure

CGROUP_ROOT = "/sys/fs/cgroup"
SELF_CGROUP = "/proc/self/cgroup"

# One write reaps the whole subtree. Present since Linux 5.14, never on root.
CGROUP_KILL = "cgroup.kill"

# The kernel's own answer to "is anything still in here?" — `populated 1` while
# any descendant holds a process. Beats counting `cgroup.procs`, which only
# ever describes one level.
CGROUP_EVENTS = "cgroup.events"

# What the kernel answers once an emptied scope is removed: ENOENT to an open
# after the removal, ENODEV to a file opened just before it. Either one means
# the subtree held nothing.
VANISHED = frozenset({errno.ENOENT, errno.ENODEV})


def _components(path: str) -> list[str]:
    return [part for part in path.split("/") if part]


def contains(ancestor: str, descendant: str) -> bool:
    """Whether `ancestor` contains `descendant`, equality counting.

    Component-wise and never textual: `/a/b` must not read as containing
    `/a/bc`. A prefix test on a path is a bug wearing a comparison's clothes,
    and here it would take custody of a sibling subtree.
    """
    parts = _components(ancestor)
    return _components(descendant)[: len(parts)] == parts


def unified_membership(proc_cgroup: str) -> str:
    """The unified-hierarchy path named by a `/proc/<pid>/cgroup` body.

    A pure cgroup v2 host writes one `0::<path>` line. A v1-only or hybrid host
    writes numbered lines whose hierarchies do not hold the engine, so the
    absence of the `0::` line is a refusal, never a fallback.
    """
    for line in proc_cgroup.splitlines():
        if line.startswith("0::"):
            return line[3:].strip()
    raise BrowserError(
        ClosedFailure.LAUNCH,
        f"no cgroup v2 membership (0:: line) in {proc_cgroup!r}: this host has "
        f"no unified hierarchy to hold custody of the engine",
    )


class CgroupCustody:
    """Custody over one cgroup subtree, proven not to contain this process."""

    def __init__(self, relative: str) -> None:
        # The refusal the rest of this class rests on: `cgroup.kill` reaps the
        # subtree, so a subtree containing this server reaps this server. An
        # empty path refuses here too — the root cgroup contains everything,
        # which is how a careless resolve turns "no answer" into "kill the box".
        ours = unified_membership(Path(SELF_CGROUP).read_text())
        if contains(relative, ours):
            raise BrowserError(
                ClosedFailure.LAUNCH,
                f"refusing custody of cgroup {relative!r}: it contains this "
                f"process ({ours!r}), so one write would reap this server",
            )
        self.directory = Path(CGROUP_ROOT) / relative.lstrip("/")
        if not (self.directory / CGROUP_KILL).is_file():
            raise BrowserError(
                ClosedFailure.LAUNCH,
                f"{self.directory} offers no {CGROUP_KILL}: no cgroup v2 "
                f"hierarchy here, so the engine subtree would be unreapable",
            )

    def kill(self) -> None:
        """Reap every process in the subtree, in one write. A subtree already
        removed held nothing: the kernel refuses to remove a populated one."""
        try:
            (self.directory / CGROUP_KILL).write_text("1")
        except OSError as exc:
            if exc.errno not in VANISHED:
                raise

    def is_populated(self) -> bool:
        """Whether the subtree still holds a process, per the kernel's flag.

        Gone is empty: the kernel removes the directory once the last member
        exits and nothing holds it open, and that can land between a check and
        the read after it, so the read is the only test.
        """
        try:
            events = (self.directory / CGROUP_EVENTS).read_text()
        except OSError as exc:
            if exc.errno not in VANISHED:
                raise
            return False
        return "populated 1" in events.split("\n")
