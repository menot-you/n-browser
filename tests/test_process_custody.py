"""The orphan defect, staged: a supervisor SIGKILLed never runs `_teardown`,
and the engine subtree it launched outlives it forever."""

import errno
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from nbrowser import cgroup_custody
from nbrowser.cgroup_custody import (
    CgroupCustody,
    contains,
    unified_membership,
)
from nbrowser.errors import BrowserError, ClosedFailure
from nbrowser.profile import BrowserProfile
from nbrowser.session import BrowserLaunchConfig, BrowserSession

CDP_STARTUP = r"""
IFS= read -r -d '' frame <&3
id=${frame#*'"id": '}
printf '{"id": %s, "result": {}}\0' "${id%%,*}" >&4
"""

# The engine stands in for Chromium and reproduces the exact shape a userspace
# reaper cannot reach: a grandchild that `setsid` into its own session AND
# traps SIGTERM. Chromium's zygote is that shape; a shell script is that shape
# in 3 lines and no download.
ENGINE = (
    """#!/bin/bash
setsid /bin/bash -c 'trap "" TERM; echo $$ > {survivor}; while :; do sleep 3600; done' \
  </dev/null >/dev/null 2>&1 &
"""
    + CDP_STARTUP
    + "while :; do sleep 3600; done\n"
)

SUPERVISOR = """
import sys, time
from nbrowser.session import BrowserLaunchConfig, BrowserSession
session = BrowserSession(BrowserLaunchConfig(headless=True))
cgroup = session.custody.cgroup
open(sys.argv[1], "w").write(f"{cgroup.directory}\\n{cgroup.is_populated()}")
time.sleep(3600)
"""


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
    except ProcessLookupError, FileNotFoundError, IndexError:
        return False


def _await_pid(path: Path, deadline: float) -> int:
    while time.monotonic() < deadline:
        if path.is_file() and path.read_text().strip():
            return int(path.read_text().strip())
        time.sleep(0.02)
    raise AssertionError(f"{path} never named a pid")


def test_sigkilled_supervisor_leaves_no_engine_subtree(tmp_path: Path) -> None:
    survivor_file = tmp_path / "survivor"
    engine = tmp_path / "engine"
    engine.write_text(ENGINE.replace("{survivor}", str(survivor_file)))
    engine.chmod(0o755)
    report = tmp_path / "child"

    env = dict(os.environ, NOTT_NBROWSER_CHROME_BIN=str(engine))
    supervisor = subprocess.Popen(
        [sys.executable, "-c", SUPERVISOR, str(report)], env=env
    )
    survivor = 0
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if report.is_file():
                lines = report.read_text().splitlines()
                if len(lines) >= 2:
                    break
            time.sleep(0.02)
        directory, populated = report.read_text().splitlines()
        survivor = _await_pid(survivor_file, deadline)
        assert _alive(survivor)
        # The kernel's own answer, read by the supervisor that owns custody.
        assert populated == "True"

        # The survivor `setsid` into its own session — the move that puts it
        # out of `killpg`'s reach — and traps SIGTERM. Membership is what it
        # cannot leave.
        assert os.getsid(survivor) == survivor

        os.kill(supervisor.pid, signal.SIGKILL)
        supervisor.wait(timeout=10)

        gone = time.monotonic() + 15
        while time.monotonic() < gone and _alive(survivor):
            time.sleep(0.05)
        assert not _alive(survivor), f"orphan survived the supervisor: pid {survivor}"
        # ... and the kernel agrees, in the strongest form it has: it removes
        # the cgroup itself once the last member is gone. The manager unwinds
        # the scope a beat after the reap, so this is awaited, never snapped.
        while time.monotonic() < gone and Path(directory).exists():
            time.sleep(0.05)
        assert not Path(directory).exists(), (
            f"the scope outlived its members: {directory}"
        )
    finally:
        if supervisor.poll() is None:
            supervisor.kill()
        supervisor.wait()
        if survivor and _alive(survivor):
            os.kill(survivor, signal.SIGKILL)


def test_absent_cgroup_v2_is_a_typed_refusal_never_a_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This host HAS cgroup v2 — `stat -fc %T /sys/fs/cgroup` is `cgroup2fs` —
    so the absence branch is never taken by accident here. It is DRIVEN."""
    monkeypatch.setattr(cgroup_custody, "CGROUP_ROOT", str(tmp_path))

    with pytest.raises(BrowserError) as refusal:
        # Synthetic hierarchy under the disposable cgroup root.
        CgroupCustody("/synthetic/no-such-hierarchy")

    assert refusal.value.code is ClosedFailure.LAUNCH
    assert "cgroup.kill" in refusal.value.message


def test_our_own_cgroup_and_every_ancestor_are_refused() -> None:
    """`cgroup.kill` reaps the subtree; a subtree holding this process reaps
    this process. The refusal is what makes the rest safe to hold."""
    ours = unified_membership(Path(cgroup_custody.SELF_CGROUP).read_text())
    parts = [part for part in ours.split("/") if part]

    while parts:
        with pytest.raises(BrowserError) as refusal:
            CgroupCustody("/" + "/".join(parts))
        assert refusal.value.code is ClosedFailure.LAUNCH
        assert "contains this process" in refusal.value.message
        parts.pop()

    # An empty relative path must not resolve to the root cgroup: the root
    # contains everything, which is how a careless resolve turns "no answer"
    # into custody over the whole machine.
    with pytest.raises(BrowserError):
        CgroupCustody("")


def test_a_host_without_a_unified_line_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A v1-only or hybrid host writes numbered lines whose hierarchies do not
    hold the engine. That is a refusal, never a fallback."""
    hybrid = tmp_path / "cgroup"
    hybrid.write_text("3:cpu,cpuacct:/user.slice\n1:name=systemd:/user.slice\n")
    monkeypatch.setattr(cgroup_custody, "SELF_CGROUP", str(hybrid))

    with pytest.raises(BrowserError) as refusal:
        CgroupCustody("/anywhere")

    assert refusal.value.code is ClosedFailure.LAUNCH
    assert "0::" in refusal.value.message


def test_containment_is_component_wise_and_never_textual() -> None:
    assert contains("/a/b", "/a/b")
    assert contains("/a/b", "/a/b/c")
    assert contains("/", "/a/b")
    # A textual prefix test accepts both of these and takes custody of a
    # sibling subtree it must never touch.
    assert not contains("/a/b", "/a/bc")
    assert not contains("/a/b", "/a/b-2/c")
    assert not contains("/a/b/c", "/a/b")


def test_populated_reads_the_kernel_flag_and_a_gone_cgroup_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The True half is measured on the live launch above. This drives the
    other two answers a subtree can give, without racing a real reap."""
    monkeypatch.setattr(cgroup_custody, "CGROUP_ROOT", str(tmp_path))
    quiet = tmp_path / "quiet"
    quiet.mkdir()
    (quiet / "cgroup.kill").write_text("")
    (quiet / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    custody = CgroupCustody("/quiet")

    assert not custody.is_populated()

    # Gone is empty: the kernel removes the directory once the last member
    # exits and nothing holds it open.
    (quiet / "cgroup.events").unlink()
    assert not custody.is_populated()

    custody.kill()
    assert (quiet / "cgroup.kill").read_text() == "1"


@pytest.mark.parametrize("answer", [errno.ENOENT, errno.ENODEV, errno.EACCES])
def test_a_scope_removed_between_check_and_access_held_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: int
) -> None:
    """systemd removes an emptied scope whenever it gets to it, so the removal can
    land between any check and the access after it: in a regression delta
    `is_file()` saw `cgroup.events` and the read raised FileNotFoundError out of
    teardown. The kernel answers ENOENT to an open after the removal and ENODEV
    to a file opened just before it (both measured on this host); either means
    the subtree is empty. Any other refusal stays the error it is."""
    monkeypatch.setattr(cgroup_custody, "CGROUP_ROOT", str(tmp_path))
    scope = tmp_path / "scope"
    scope.mkdir()
    (scope / "cgroup.kill").write_text("")
    (scope / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    custody = CgroupCustody("/scope")
    real_open = Path.open

    def removed_on_access(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.parent == scope:
            if answer != errno.EACCES:
                shutil.rmtree(scope, ignore_errors=True)
            if answer != errno.ENOENT:
                raise OSError(answer, os.strerror(answer), str(self))
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", removed_on_access)
    if answer == errno.EACCES:
        with pytest.raises(PermissionError):
            custody.is_populated()
        with pytest.raises(PermissionError):
            custody.kill()
    else:
        assert not custody.is_populated()
        custody.kill()


def test_a_launch_that_cannot_start_refuses_typed_and_keeps_no_fd() -> None:
    """The launch opens four pipes before it spawns. A spawn that fails has to
    give all eight ends back, or an idle relaunch leaks a pipe per cycle."""
    monkey = pytest.MonkeyPatch()
    monkey.setenv("NOTT_NBROWSER_CHROME_BIN", "/bin/true")

    def refuse(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        raise OSError("systemd-run is not on this host")

    monkey.setattr(subprocess, "Popen", refuse)
    before = os.listdir("/proc/self/fd")
    try:
        with pytest.raises(BrowserError) as refusal:
            BrowserSession(BrowserLaunchConfig(headless=True))
    finally:
        monkey.undo()

    assert refusal.value.code is ClosedFailure.LAUNCH
    assert len(os.listdir("/proc/self/fd")) == len(before)


def test_launch_refusal_after_spawn_leaks_nothing(monkeypatch, tmp_path):
    """The post-spawn refusal path closes what it opened and reaps the child.

    Every step after Popen can raise — the death-pipe read, the membership
    parse, the custody constructor that refuses an unplaced scope. The engine
    is ALREADY running there, so a bare `raise` would leak three descriptors
    and leave a zombie per attempt. This drives that path and counts both.
    """
    import subprocess as _sp

    from nbrowser import session as _session

    def descriptor_snapshot() -> dict[str, str]:
        snapshot: dict[str, str] = {}
        directory = f"/proc/{os.getpid()}/fd"
        for descriptor in os.listdir(directory):
            try:
                snapshot[descriptor] = os.readlink(f"{directory}/{descriptor}")
            except FileNotFoundError:
                continue
        return snapshot

    engine = tmp_path / "engine"
    engine.write_text("#!/bin/sh\nexec sleep 30\n")
    engine.chmod(0o755)
    monkeypatch.setenv("NOTT_NBROWSER_CHROME_BIN", str(engine))

    # The refusal an unplaced scope produces, forced deterministically.
    monkeypatch.setattr(
        _session,
        "unified_membership",
        lambda _born: (_ for _ in ()).throw(
            BrowserError(ClosedFailure.LAUNCH, "scope placed nothing")
        ),
    )

    spawned: list[_sp.Popen[bytes]] = []
    real_popen = _sp.Popen

    def _record(*a: object, **kw: object) -> _sp.Popen[bytes]:
        proc = real_popen(*a, **kw)  # type: ignore[arg-type]
        spawned.append(proc)
        return proc

    monkeypatch.setattr(_sp, "Popen", _record)

    before = descriptor_snapshot()
    with pytest.raises(BrowserError) as exc:
        BrowserSession(BrowserLaunchConfig(headless=True))
    assert exc.value.code is ClosedFailure.LAUNCH

    after = descriptor_snapshot()
    # Another session can finish descriptor cleanup during this call.
    remaining = after.items() - before.items()
    assert not remaining, f"New descriptors remain open: {sorted(remaining)}"

    assert spawned, "the engine was never spawned, so this drove the wrong path"
    assert spawned[0].poll() is not None, "child left unreaped (zombie)"


@pytest.mark.parametrize(
    "gone",
    [
        "exits-at-startup",
        "removed-after-the-check",
        "exits-after-startup",
        "exits-after-reading",
    ],
)
def test_a_call_on_an_engine_that_is_gone_is_refused_as_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gone: str
) -> None:
    """Startup requires the auto-attach reply. Engine exit must refuse at once,
    during startup or at the next call, and release every descriptor."""
    from nbrowser import session as _session

    engine = tmp_path / "engine"
    script = "#!/bin/bash\n"
    if gone in ("exits-after-startup", "exits-after-reading"):
        script += CDP_STARTUP
    if gone == "exits-after-reading":
        script += "IFS= read -r -d '' frame <&3\n"
    engine.write_text(script + "exit 3\n")
    engine.chmod(0o755)
    monkeypatch.setenv("NOTT_NBROWSER_CHROME_BIN", str(engine))
    if gone == "removed-after-the-check":
        real_profile = _session.BrowserProfile

        def remove_then_profile() -> BrowserProfile:
            engine.unlink()
            return real_profile()

        monkeypatch.setattr(_session, "BrowserProfile", remove_then_profile)
    before = len(os.listdir("/proc/self/fd"))

    if gone in ("exits-at-startup", "removed-after-the-check"):
        started = time.monotonic()
        with pytest.raises(BrowserError) as refusal:
            BrowserSession(BrowserLaunchConfig(headless=True))
        elapsed = time.monotonic() - started
    else:
        session = BrowserSession(BrowserLaunchConfig(headless=True))
        try:
            assert session.client is not None
            if gone == "exits-after-startup":
                # Wait for EOF so the next call writes to a closed pipe.
                session.client.reader_thread.join(timeout=10)
                assert not session.client.reader_thread.is_alive()
            started = time.monotonic()
            with pytest.raises(BrowserError) as refusal:
                session.tabs_list()
            elapsed = time.monotonic() - started
        finally:
            session.close_session()

    assert refusal.value.code is ClosedFailure.BROWSER_CLOSED, refusal.value.message
    # Refused by the pipe's end, never by the 30 s CDP timeout.
    assert elapsed < 15
    assert len(os.listdir("/proc/self/fd")) == before


CHATTY_ENGINE = r"""#!/bin/bash
# 128 KiB on stderr, twice what a pipe holds, before its first answer.
head -c 131072 /dev/zero >&2
while IFS= read -r -d '' frame <&3; do
  id=${frame#*'"id": '}
  printf '{"id": %s, "result": {"product": "chatty"}}\0' "${id%%,*}" >&4
done
"""


def test_an_engine_that_writes_to_stderr_still_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing reads the engine's stderr, and Chromium logs there. As a pipe
    it held 64 KiB: an engine that wrote more blocked on the write, and every
    call waited out its timeout."""
    engine = tmp_path / "engine"
    engine.write_text(CHATTY_ENGINE)
    engine.chmod(0o755)
    monkeypatch.setenv("NOTT_NBROWSER_CHROME_BIN", str(engine))
    before = len(os.listdir("/proc/self/fd"))

    session = BrowserSession(BrowserLaunchConfig(headless=True))
    try:
        assert session.client is not None
        answer = session.client.send("Browser.getVersion", timeout=5)
    finally:
        session.close_session()

    assert answer == {"product": "chatty"}
    assert len(os.listdir("/proc/self/fd")) == before


def _fake_engine(tmp_path: Path) -> Path:
    """Answer startup through CDP, then keep the process in custody."""
    engine = tmp_path / "engine"
    engine.write_text("#!/bin/bash\n" + CDP_STARTUP + "exec sleep 30\n")
    engine.chmod(0o755)
    return engine


def test_a_cleaned_environment_still_reaches_the_session_bus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`systemd-run --user` reads the bus address out of the ENVIRONMENT, and
    a lane proof runs under `env -i` — the ENV LAW of this repo. Measured:
    `env -i PATH=... systemd-run --user --scope --quiet --collect true` fails
    with «$DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined», while
    the same line with the two names restored exits 0. The bus never left the
    disk; only its names did, and both derive from the uid. Fortress's `tilion`
    launcher also needs `HOME` (for its fontconfig cache) and `TILION_NO_GEO=1`
    (so launch never curls ipapi.co/ipinfo.io).
    """
    env_probe = tmp_path / "env.probe"
    engine = tmp_path / "engine"
    engine.write_text(
        f'#!/bin/bash\nprintf "%s|%s" "$HOME" "$TILION_NO_GEO" > "{env_probe}"\n'
        + CDP_STARTUP
        + "exec sleep 30\n"
    )
    engine.chmod(0o755)
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setenv("TILION_NO_GEO", "0")
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.setenv("NOTT_NBROWSER_CHROME_BIN", str(engine))

    session = BrowserSession(BrowserLaunchConfig(headless=True))
    try:
        assert session.custody is not None
        assert session.custody.cgroup.is_populated()
        deadline = time.monotonic() + 2.0
        while not env_probe.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert env_probe.read_text() == f"{os.path.expanduser('~')}|1"
    finally:
        session.close_session()


def test_a_bus_absent_from_the_disk_is_a_typed_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half, and the one that MUST keep refusing: no bus, no scope,
    no delegated cgroup, and an engine nothing can reach is worse than none —
    the crashpad is born in a process group of its own, so there is no signal
    left to degrade to. This box HAS a bus, so the branch is DRIVEN: the
    runtime directory is pointed at an empty one.
    """
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.setenv("NOTT_NBROWSER_CHROME_BIN", str(_fake_engine(tmp_path)))

    with pytest.raises(BrowserError) as refusal:
        BrowserSession(BrowserLaunchConfig(headless=True))

    assert refusal.value.code is ClosedFailure.LAUNCH
    # The two cases read differently because their cures differ: an unnamed
    # bus is derived, an absent one is refused.
    assert str(tmp_path / "bus") in refusal.value.message
    assert "no longer refuses" in refusal.value.message


def test_terminate_returns_only_once_the_subtree_is_empty() -> None:
    """`cgroup.kill` is asynchronous: members die a beat after the write. The
    profile is removed right after `terminate`, so returning while a renderer
    still writes into it leaked 651 profiles (1.7 GB of RAM-backed /tmp)."""
    from nbrowser.process_custody import BrowserCustody

    answers = [True, True, False]

    class Draining:
        def kill(self) -> None:
            pass

        def is_populated(self) -> bool:
            return answers.pop(0) if answers else False

    process = subprocess.Popen(["true"])
    _, death_write = os.pipe()
    BrowserCustody(process, Draining(), death_write).terminate()  # type: ignore[arg-type]

    assert answers == [], "terminate returned while the cgroup still held members"
