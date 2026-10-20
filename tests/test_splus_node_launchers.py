"""Real Node launchers and disposable child executables exercise process contracts."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("launcher", ["nbrowser"])
@pytest.mark.parametrize(
    "scenario",
    ["uv_success", "uv_failure", "fallback", "missing", "permission", "signal"],
)
def test_node_launcher_native_process_outcomes(
    tmp_path: Path, launcher: str, scenario: str
) -> None:
    node = shutil.which("node")
    assert node is not None, "native Node prerequisite is required"
    package = Path(__file__).resolve().parents[1]
    script = package / "npm" / "bin" / (launcher + ".js")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    child = bin_dir / launcher
    if scenario != "missing":
        child.write_text('#!/bin/sh\nprintf "fallback:%s\\n" "$@"\n', encoding="utf-8")
        child.chmod(0o700)
    if scenario in {"uv_success", "uv_failure", "permission", "signal"}:
        uv = bin_dir / "uv"
        if scenario == "signal":
            uv.write_text('#!/bin/sh\nkill -TERM "$$"\n', encoding="utf-8")
        else:
            uv.write_text(
                '#!/bin/sh\nprintf "uv:%s\\n" "$@"\nexit '
                + ("7" if scenario == "uv_failure" else "0")
                + "\n",
                encoding="utf-8",
            )
        uv.chmod(0o600 if scenario == "permission" else 0o700)
    env = {**os.environ, "PATH": str(bin_dir), "UV_NO_SYNC": "1"}
    result = subprocess.run(
        [node, str(script), "--fixture", "two words"],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    expected = {
        "uv_success": 0,
        "uv_failure": 7,
        "fallback": 0,
        "missing": 1,
        "permission": 1,
        "signal": 1,
    }[scenario]
    assert result.returncode == expected
    if scenario in {"uv_success", "uv_failure"}:
        assert result.stdout.splitlines() == [
            "uv:run",
            "uv:" + launcher,
            "uv:--fixture",
            "uv:two words",
        ]
    elif scenario == "fallback":
        assert result.stdout.splitlines() == [
            "fallback:--fixture",
            "fallback:two words",
        ]
    else:
        assert result.stdout == ""
    if scenario in {"missing", "permission"}:
        assert "Failed to execute " + launcher in result.stderr
    else:
        assert result.stderr == ""
    # Preserve each observed process outcome when a proof collector is requested.
    proof_dir = os.environ.get("NOTT_BROWSER_LAUNCHER_PROOF")
    if proof_dir:
        path = Path(proof_dir)
        path.mkdir(parents=True, exist_ok=True)
        (path / (launcher + "-" + scenario + ".json")).write_text(
            json.dumps(
                {
                    "launcher": launcher,
                    "scenario": scenario,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
                indent=2,
            )
            + "\n"
        )
