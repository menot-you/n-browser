"""Real CDP pipes: correlation under concurrency and bounded protocol failure."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from test_ssrf_runtime import _Engine

from nbrowser.errors import BrowserError, ClosedFailure


@settings(max_examples=100, derandomize=True, deadline=None)
@given(
    first=st.integers(),
    second=st.integers(),
    cut=st.integers(min_value=1, max_value=40),
)
def test_concurrent_pipe_replies_are_correlated_across_fragmented_frames(
    first: int, second: int, cut: int
) -> None:
    engine = _Engine()
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(engine.client.send, "Test.echo", {"value": value}, None, 2)
                for value in (first, second)
            ]
            requests = [engine.frame(), engine.frame()]
            assert requests[0]["id"] != requests[1]["id"]
            for request in reversed(requests):
                frame = (
                    json.dumps(
                        {"id": request["id"], "result": request["params"]}
                    ).encode()
                    + b"\0"
                )
                os.write(engine.to_client, frame[:cut])
                os.write(engine.to_client, frame[cut:])
            assert [future.result(timeout=3) for future in futures] == [
                {"value": first},
                {"value": second},
            ]
            assert engine.client.responses == {}
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)
        assert not engine.client.reader_thread.is_alive()


def test_protocol_fault_then_deadline_leave_the_pipe_usable() -> None:
    engine = _Engine()
    try:
        engine.emit({"id": 1, "error": {"code": -1, "message": "fixture fault"}})
        with pytest.raises(BrowserError) as fault:
            engine.client.send("Test.fault", timeout=0.1)
        assert fault.value.code is ClosedFailure.PROTOCOL
        assert "fixture fault" in fault.value.message
        assert engine.frame()["method"] == "Test.fault"
        with pytest.raises(BrowserError) as deadline:
            engine.client.send("Test.unanswered", timeout=0.01)
        assert deadline.value.code is ClosedFailure.PROTOCOL
        assert deadline.value.message == "CDP timeout: Test.unanswered"
        assert engine.frame()["method"] == "Test.unanswered"
        engine.emit({"id": 3, "result": {"alive": True}})
        assert engine.client.send("Test.next", timeout=0.1) == {"alive": True}
        assert engine.frame()["method"] == "Test.next"
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)
        assert not engine.client.reader_thread.is_alive()


def test_empty_and_invalid_pipe_frames_do_not_poison_next_reply() -> None:
    engine = _Engine()
    try:
        os.write(engine.to_client, b"\0not-json\0")
        engine.emit({"id": 1, "result": {"alive": True}})
        assert engine.client.send("Test.alive", timeout=1) == {"alive": True}
        assert engine.frame()["method"] == "Test.alive"
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)
        assert not engine.client.reader_thread.is_alive()
