#!/usr/bin/env python3
import json
import pathlib
import tempfile
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from verify_runtime_tools import build_runtime_tool_check, write_runtime_tool_check  # noqa: E402


def test_missing_clang_blocks_binutils_runtime():
    results = {
        "rg": (0, "rg 1"),
        "semgrep": (0, "1.0"),
        "cppcheck": (0, "2.0"),
        "osv-scanner": (0, "2.4"),
        "gcc": (0, "gcc"),
        "g++": (0, "g++"),
        "clang": (127, "not found"),
        "clang++": (0, "clang++"),
        "llvm-symbolizer": (0, "LLVM"),
        "make": (0, "make"),
        "timeout": (0, "timeout"),
    }
    check = build_runtime_tool_check("binutils", "pvas-container", lambda name, _cmd: results[name])
    assert check["status"] == "blocked-recovery-required"
    assert check["reason"] == "container-tool-missing: clang"
    assert check["recovery_action"] == "rebuild-runtime-image"


def test_host_clang_does_not_satisfy_container_missing():
    results = {name: (0, name) for name in ("rg", "semgrep", "cppcheck", "osv-scanner", "gcc", "g++", "clang++", "llvm-symbolizer", "make", "timeout")}
    results["clang"] = (127, "container missing")
    check = build_runtime_tool_check(
        "binutils",
        "pvas-container",
        lambda name, _cmd: results[name],
        host_observations={"clang": {"status": "present"}},
    )
    assert check["tools"]["clang"]["status"] == "missing"
    assert check["host_observations"]["clang"]["status"] == "present"
    assert check["status"] == "blocked-recovery-required"


def test_all_strict_tools_present_passes_and_writes_artifacts():
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / "00-environment"
        check = build_runtime_tool_check("binutils", "pvas-container", lambda name, _cmd: (0, f"{name} version"))
        write_runtime_tool_check(check, out)
        payload = json.loads((out / "runtime-tool-check.json").read_text())
        text = (out / "runtime-tool-check.md").read_text()
        assert payload["status"] == "passed"
        assert "Runtime Tool Check" in text


if __name__ == "__main__":
    test_missing_clang_blocks_binutils_runtime()
    test_host_clang_does_not_satisfy_container_missing()
    test_all_strict_tools_present_passes_and_writes_artifacts()
    print("runtime tool check tests passed")
