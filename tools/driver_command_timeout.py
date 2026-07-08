#!/usr/bin/env python3
"""Timeout wrapper for enforced_audit_driver.run().

The driver executes many subprocess-based workflow stages. A stuck child command
must not hang the whole audit indefinitely. This module patches the driver's
`run(cmd, allow_fail=False)` helper while preserving its existing return/raise
semantics.

The default timeout is intentionally a coarse outer safety fuse for whole driver
subcommands, not the per-tool budget for cppcheck, Semgrep, or other scanners.
Tool-specific timeouts, cppcheck sharding, partial-timeout handling, and degraded
report status remain responsible for large-codebase scan control.

The same wrapper also routes the driver's final-report command to the explicit
`generate_final_report_with_status.py` entry point. That removes the need for a
separate implicit final-report postprocess hook in `sitecustomize.py` while
avoiding a high-risk full-file rewrite of the large driver.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
from typing import Any, Callable

DEFAULT_TIMEOUT_SECONDS = 7200.0
TIMEOUT_ENV = 'PVAS_DRIVER_COMMAND_TIMEOUT_SECONDS'
TIMEOUT_EXIT_CODE = 124
FINAL_REPORT_SCRIPT = 'tools/generate_final_report.py'
FINAL_REPORT_WITH_STATUS_SCRIPT = 'tools/generate_final_report_with_status.py'


def _coerce_text(value: str | bytes | None) -> str:
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value.decode(errors='replace')
    return str(value)


def _cmd_display(cmd: list[str]) -> str:
    return ' '.join(str(part) for part in cmd)


def resolve_timeout_seconds() -> float | None:
    raw = os.environ.get(TIMEOUT_ENV, str(DEFAULT_TIMEOUT_SECONDS)).strip()
    if raw.lower() in {'', '0', 'none', 'off', 'false', 'no', 'disabled'}:
        return None
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return value if value > 0 else None


def route_driver_command(cmd: list[str]) -> tuple[list[str], bool]:
    """Route legacy final-report command to the explicit status-aware wrapper."""
    routed = [str(part) for part in cmd]
    changed = False
    for idx, part in enumerate(routed):
        if part == FINAL_REPORT_SCRIPT or pathlib.Path(part).as_posix() == FINAL_REPORT_SCRIPT:
            routed[idx] = FINAL_REPORT_WITH_STATUS_SCRIPT
            changed = True
    return routed, changed


def timeout_message(cmd: list[str], timeout_seconds: float | None) -> str:
    return f'[PVAS-TIMEOUT] command exceeded {timeout_seconds:g}s: {_cmd_display(cmd)}'


def make_timed_run(original_run: Callable[..., tuple[int, str]]):
    glob = getattr(original_run, '__globals__', {})
    root = pathlib.Path(glob.get('ROOT') or pathlib.Path.cwd())
    subprocess_module = glob.get('subprocess') or subprocess

    def timed_run(cmd: list[str], allow_fail: bool = False) -> tuple[int, str]:
        cmd_list, routed = route_driver_command(cmd)
        timeout_seconds = resolve_timeout_seconds()
        route_note = '[PVAS-REPORT-STATUS] routed generate_final_report.py to generate_final_report_with_status.py\n' if routed else ''
        try:
            p = subprocess_module.run(
                cmd_list,
                cwd=root,
                text=True,
                stdout=subprocess_module.PIPE,
                stderr=subprocess_module.STDOUT,
                timeout=timeout_seconds,
            )
        except subprocess_module.TimeoutExpired as exc:
            output = route_note + _coerce_text(getattr(exc, 'stdout', ''))
            stderr = _coerce_text(getattr(exc, 'stderr', ''))
            if stderr:
                output = output + stderr
            msg = timeout_message(cmd_list, timeout_seconds)
            if allow_fail:
                return TIMEOUT_EXIT_CODE, (output + '\n' + msg).strip() + '\n'
            raise RuntimeError(f'command timeout: {msg}\n{output}') from exc
        stdout = route_note + p.stdout
        if p.returncode and not allow_fail:
            raise RuntimeError(f'command failed ({p.returncode}): {_cmd_display(cmd_list)}\n{stdout}')
        return p.returncode, stdout

    timed_run.__name__ = getattr(original_run, '__name__', 'run')
    timed_run.__doc__ = 'Timeout-enforced replacement for enforced_audit_driver.run().'
    timed_run._pvas_driver_timeout_enabled = True  # type: ignore[attr-defined]
    return timed_run


def patch_globals(glob: dict[str, Any]) -> bool:
    run_func = glob.get('run')
    if not callable(run_func):
        return False
    if getattr(run_func, '_pvas_driver_timeout_enabled', False):
        glob['_PVAS_DRIVER_COMMAND_TIMEOUT_ENABLED'] = True
        return False
    glob['run'] = make_timed_run(run_func)
    glob['_PVAS_DRIVER_COMMAND_TIMEOUT_ENABLED'] = True
    return True
