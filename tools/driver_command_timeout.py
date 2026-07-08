#!/usr/bin/env python3
"""Timeout wrapper for enforced_audit_driver.run().

The driver executes many subprocess-based workflow stages. A stuck child command
must not hang the whole audit indefinitely. This module patches the driver's
`run(cmd, allow_fail=False)` helper while preserving its existing return/raise
semantics.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
from typing import Any, Callable

DEFAULT_TIMEOUT_SECONDS = 1800.0
TIMEOUT_ENV = 'PVAS_DRIVER_COMMAND_TIMEOUT_SECONDS'
TIMEOUT_EXIT_CODE = 124


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


def timeout_message(cmd: list[str], timeout_seconds: float | None) -> str:
    return f'[PVAS-TIMEOUT] command exceeded {timeout_seconds:g}s: {_cmd_display(cmd)}'


def make_timed_run(original_run: Callable[..., tuple[int, str]]):
    glob = getattr(original_run, '__globals__', {})
    root = pathlib.Path(glob.get('ROOT') or pathlib.Path.cwd())
    subprocess_module = glob.get('subprocess') or subprocess

    def timed_run(cmd: list[str], allow_fail: bool = False) -> tuple[int, str]:
        cmd_list = [str(part) for part in cmd]
        timeout_seconds = resolve_timeout_seconds()
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
            output = _coerce_text(getattr(exc, 'stdout', ''))
            stderr = _coerce_text(getattr(exc, 'stderr', ''))
            if stderr:
                output = output + stderr
            msg = timeout_message(cmd_list, timeout_seconds)
            if allow_fail:
                return TIMEOUT_EXIT_CODE, (output + '\n' + msg).strip() + '\n'
            raise RuntimeError(f'command timeout: {msg}\n{output}') from exc
        if p.returncode and not allow_fail:
            raise RuntimeError(f'command failed ({p.returncode}): {_cmd_display(cmd_list)}\n{p.stdout}')
        return p.returncode, p.stdout

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
