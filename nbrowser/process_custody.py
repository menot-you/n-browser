import os
import subprocess
import time

from .cgroup_custody import CgroupCustody


class BrowserCustody:
    """The engine launch, paired with the cgroup that holds it.

    `killpg` is gone: it was the only line of defence and it could not reach a
    member that `setsid` moved out of the group, which is the shape a real
    engine's zygote has. What replaces it is not a better signal — it is the
    kernel, through `cgroup_custody`.
    """

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        cgroup: CgroupCustody,
        death_write_fd: int,
    ) -> None:
        self.process = process
        self.pid = process.pid
        self.cgroup = cgroup
        # The supervisor's end of the death pipe. It is never written to: its
        # CLOSING is the message, and the kernel closes it on any death this
        # process cannot run code for — SIGKILL included.
        self.death_write_fd = death_write_fd

    def terminate(self) -> None:
        self.cgroup.kill()
        os.close(self.death_write_fd)
        self.process.wait(timeout=5)
        # `cgroup.kill` is asynchronous: a renderer can still be writing into the
        # profile after the wrapper is reaped, and the profile is removed next.
        deadline = time.monotonic() + 5
        while self.cgroup.is_populated() and time.monotonic() < deadline:
            time.sleep(0.02)
