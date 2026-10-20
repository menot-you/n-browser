"""Public MCP interleavings over a real pipe session, without replacing method results."""

import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import FrameType
from typing import Any

from test_ssrf_runtime import _Engine


def test_wait_event_blocks_until_matching_native_frame_arrives() -> None:
    engine = _Engine()
    entered_wait = threading.Event()

    def schedule(frame: FrameType, event: str, arg: Any) -> None:
        if (
            event == "call"
            and frame.f_code is threading.Condition.wait.__code__
            and frame.f_locals.get("self") is engine.client.cond
        ):
            entered_wait.set()

    def wait() -> dict[str, Any]:
        sys.setprofile(schedule)
        try:
            return engine.client.wait_event("Fixture.ready", "s1", timeout=3)
        finally:
            sys.setprofile(None)

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(wait)
            assert entered_wait.wait(timeout=2), "consumer did not wait for the frame"
            engine.emit(
                {
                    "method": "Fixture.ready",
                    "sessionId": "s1",
                    "params": {"ready": True},
                }
            )
            assert result.result(timeout=3) == {"ready": True}
        assert engine.client.events == []
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)
        assert not engine.client.reader_thread.is_alive()
