from __future__ import annotations

import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import run_tool_matrix as rtm
import tool_matrix_hardening


def test_run_tools_uses_canonical_runner_not_safe_wrapper():
    script = (ROOT / "tools" / "run_tools.sh").read_text()

    assert "run_tool_matrix.py" in script
    assert "run_tool_matrix_safe.py" not in script


def test_tool_matrix_hardening_patches_runtime_once():
    original = rtm.run_with_watchdog
    try:
        tool_matrix_hardening.apply_to_runtime(rtm)
        first = rtm.run_with_watchdog
        tool_matrix_hardening.apply_to_runtime(rtm)
        second = rtm.run_with_watchdog

        assert first is second
        assert getattr(rtm, "_PVAS_TOOL_MATRIX_HARDENED") is True
    finally:
        # Keep module state deterministic for following tests in this process.
        rtm.run_with_watchdog = original
        if hasattr(rtm, "_PVAS_TOOL_MATRIX_HARDENED"):
            delattr(rtm, "_PVAS_TOOL_MATRIX_HARDENED")


def test_canonical_hardening_watchdog_kills_blocking_tool(tmp_path):
    output = tmp_path / "tool.out"
    tool = {
        "name": "fake-required-tool",
        "applicability": "recommended",
        "timeout": "0.2s",
        "watchdog": {"hard_timeout": "0.6s"},
    }
    started = time.monotonic()
    rc, elapsed_ms, events, reason = tool_matrix_hardening.hardened_run_with_watchdog(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        {},
        output,
        tool,
        runtime=rtm,
    )
    elapsed = time.monotonic() - started

    assert rc is None
    assert reason == "hard-limit"
    assert elapsed < 3
    assert elapsed_ms >= 0
    assert any(event.get("event") == "hard-limit" for event in events)
