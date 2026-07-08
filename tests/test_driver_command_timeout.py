from __future__ import annotations

import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import driver_command_timeout


def original_run(_cmd, allow_fail=False):
    raise AssertionError("original run should be replaced")


def test_default_driver_timeout_is_outer_safety_fuse(monkeypatch):
    monkeypatch.delenv("PVAS_DRIVER_COMMAND_TIMEOUT_SECONDS", raising=False)

    assert driver_command_timeout.resolve_timeout_seconds() == 7200.0


def test_timed_run_returns_124_when_allow_fail(monkeypatch):
    monkeypatch.setenv("PVAS_DRIVER_COMMAND_TIMEOUT_SECONDS", "0.2")
    timed_run = driver_command_timeout.make_timed_run(original_run)
    started = time.monotonic()

    rc, output = timed_run([sys.executable, "-c", "import time; time.sleep(10)"], allow_fail=True)
    elapsed = time.monotonic() - started

    assert rc == driver_command_timeout.TIMEOUT_EXIT_CODE
    assert "[PVAS-TIMEOUT]" in output
    assert elapsed < 3


def test_timed_run_raises_when_timeout_not_allow_fail(monkeypatch):
    monkeypatch.setenv("PVAS_DRIVER_COMMAND_TIMEOUT_SECONDS", "0.2")
    timed_run = driver_command_timeout.make_timed_run(original_run)
    started = time.monotonic()

    try:
        timed_run([sys.executable, "-c", "import time; time.sleep(10)"], allow_fail=False)
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected RuntimeError")
    elapsed = time.monotonic() - started

    assert "command timeout" in message
    assert "[PVAS-TIMEOUT]" in message
    assert elapsed < 3


def test_timed_run_preserves_success(monkeypatch):
    monkeypatch.setenv("PVAS_DRIVER_COMMAND_TIMEOUT_SECONDS", "2")
    timed_run = driver_command_timeout.make_timed_run(original_run)

    rc, output = timed_run([sys.executable, "-c", "print('ok')"], allow_fail=False)

    assert rc == 0
    assert output.strip() == "ok"


def test_patch_globals_replaces_run_once(monkeypatch):
    monkeypatch.setenv("PVAS_DRIVER_COMMAND_TIMEOUT_SECONDS", "2")
    glob = {"run": original_run}

    assert driver_command_timeout.patch_globals(glob) is True
    first = glob["run"]
    assert getattr(first, "_pvas_driver_timeout_enabled") is True
    assert driver_command_timeout.patch_globals(glob) is False
    assert glob["run"] is first
