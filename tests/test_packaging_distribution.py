"""Packaging and distribution tests for nbrowser npm and python distributions."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tomllib
from pathlib import Path

from workspace_root import workspace_path

# The launchers run `uv run nbrowser`, which finds its project from the working
# directory. It is the member in the workspace, always: under mutmut the member
# directory this file sits in is `mutants/`, whose copied pyproject.toml names
# workspace sources without being a workspace member, and `uv run` refuses it
# ("references a workspace in `tool.uv.sources` ... but is not a workspace member").
MEMBER_IN_WORKSPACE = workspace_path("mcps/nbrowser")


def _get_project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def test_npm_package_json_exists_and_valid() -> None:
    pkg_root = _get_project_root()
    package_json_path = pkg_root / "npm" / "package.json"
    assert package_json_path.is_file(), f"Expected {package_json_path} to exist"

    with package_json_path.open("rb") as f:
        data = json.load(f)

    assert isinstance(data, dict)
    assert data.get("name") == "@nott/nbrowser"

    # Verify version matches pyproject.toml
    pyproject_path = pkg_root / "pyproject.toml"
    assert pyproject_path.is_file()
    with pyproject_path.open("rb") as f:
        pyproject_data = tomllib.load(f)

    expected_version = pyproject_data["project"]["version"]
    assert data.get("version") == expected_version

    # Node engine >= 18
    engines = data.get("engines", {})
    assert "node" in engines
    assert "18" in engines["node"]

    # Bin declarations
    bins = data.get("bin", {})
    assert bins == {"nbrowser": "./bin/nbrowser.js"}


def test_npm_bin_scripts_exist_and_executable() -> None:
    pkg_root = _get_project_root()
    package_json_path = pkg_root / "npm" / "package.json"
    with package_json_path.open("rb") as f:
        data = json.load(f)

    bins = data.get("bin", {})
    for name, rel_path in bins.items():
        script_path = pkg_root / "npm" / rel_path
        assert script_path.is_file(), f"Binary script {script_path} does not exist"
        assert os.access(script_path, os.X_OK), (
            f"Binary script {script_path} is not executable"
        )

        content = script_path.read_text(encoding="utf-8")
        assert content.startswith("#!/usr/bin/env node"), (
            f"Script {name} missing '#!/usr/bin/env node' shebang"
        )


def test_npm_and_python_readmes_exist() -> None:
    pkg_root = _get_project_root()
    npm_readme = pkg_root / "npm" / "README.md"
    python_readme = pkg_root / "python" / "README.md"

    assert npm_readme.is_file()
    assert python_readme.is_file()

    assert len(npm_readme.read_text(encoding="utf-8").strip()) > 0
    assert len(python_readme.read_text(encoding="utf-8").strip()) > 0


def test_npm_nbrowser_wrapper_execution() -> None:
    pkg_root = _get_project_root()
    script_path = pkg_root / "npm" / "bin" / "nbrowser.js"

    node_bin = shutil.which("node")
    if node_bin is None:
        return

    result = subprocess.run(
        [node_bin, str(script_path), "--help"],
        capture_output=True,
        text=True,
        check=False,
        cwd=MEMBER_IN_WORKSPACE,
    )
    assert result.returncode == 0
    assert "nbrowser" in result.stdout
