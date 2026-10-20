import glob
import os
import shutil
import stat
import tempfile
import time
import weakref

from .errors import BrowserError, ClosedFailure
from .renamed import env

FORTRESS_SLOTS = "~/.cache/nbrowser/fortress/*/tilion"


def get_chromium_executable() -> str:
    """The engine nBROWSER launches: Fortress, or an explicit override.

    System Chromium is NOT a fallback. Fortress is a pre-patched Chromium
    whose fingerprint surface and bundled fonts are the ones this port's
    evidence was measured against; silently launching whatever `/usr/bin/chromium`
    happens to be is launching a different browser without saying so.

    The slot is admitted BY FORM — a regular file with the execute bit (`lstat`,
    never following a symlink to system Chromium) — never by owner: it is
    installed into the user's own cache, so the root-owner check system
    Chromium must pass would refuse it by design.

    NOTT_NBROWSER_CHROME_BIN is the whole interface for connecting another engine.
    """
    env_bin = env("NOTT_NBROWSER_CHROME_BIN")
    if env_bin and os.path.exists(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin

    # One look per slot: its form and its age come from the same lstat. A check
    # and then a second read left a window in which a release replaced during
    # a launch raised an untyped FileNotFoundError out of the resolver, and
    # stat() followed symlinks to system Chromium. The newest wins; a tie goes
    # to the path, never to the listing's order.
    usable: list[tuple[float, str]] = []
    for slot in glob.glob(os.path.expanduser(FORTRESS_SLOTS)):
        try:
            status = os.lstat(slot)
        except OSError:  # gone since the listing: what `isfile` answered False to
            continue
        if stat.S_ISREG(status.st_mode) and os.access(slot, os.X_OK):
            usable.append((status.st_mtime, slot))
    if usable:
        return max(usable)[1]

    # ClosedFailure.LAUNCH, not a code of its own: session.py already raises
    # exactly this for "no engine to launch", and its wire rung is
    # engine_failure — which is what an absent engine is.
    raise BrowserError(
        ClosedFailure.LAUNCH,
        f"no Fortress slot under {FORTRESS_SLOTS}: install a release there, "
        f"or point NOTT_NBROWSER_CHROME_BIN at an executable engine",
    )


def chromium_present() -> bool:
    """Whether an engine is resolvable, as a question — never as an exception to read.

    `get_chromium_executable` returns `str` or RAISES; it never returns `None`. Four callers
    asked it `is not None` / `is None` anyway, so on a host WITHOUT a slot the probe itself
    raised and the absence branch each of them exists to drive was reported as a failure —
    measured 2026-09-03 as the gate's executor, whose home has no engine release. A
    caller that wants to BRANCH asks this; a caller that wants the engine calls the other and
    lets the typed refusal travel.
    """
    try:
        get_chromium_executable()
    except BrowserError:
        return False
    return True


class PrivateRootContext:
    def __init__(self) -> None:
        self.profile_dir = tempfile.mkdtemp(prefix="nbrowser-profile-")
        # A context dropped without close() (a launch that failed after creating
        # it, interpreter exit) still removes its tree, as TemporaryDirectory did.
        self._finalizer = weakref.finalize(
            self, shutil.rmtree, self.profile_dir, ignore_errors=True
        )

    def get_profile_path(self) -> str:
        return self.profile_dir

    def close(self) -> None:
        self._finalizer.detach()
        # A write that lands between rmtree's listing and its rmdir fails one pass
        # with ENOTEMPTY; the old `ignore_cleanup_errors` turned that into a silent
        # leak (651 profiles, 1.7 GB of RAM-backed /tmp). Retry, then say so.
        for _ in range(9):
            try:
                shutil.rmtree(self.profile_dir)
                return
            except FileNotFoundError:
                return
            except OSError:
                time.sleep(0.05)
        shutil.rmtree(self.profile_dir)
