#!/usr/bin/env python3
"""Compatibility shim for the hardened tool-matrix runner.

The canonical workflow now runs `run_tool_matrix.py` directly. This file remains
for callers that still invoke `run_tool_matrix_safe.py`, but all hardening logic
lives in `tool_matrix_hardening.py`.
"""
from __future__ import annotations

import pathlib
import sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import run_tool_matrix as rtm  # noqa: E402
import tool_matrix_hardening as hardening  # noqa: E402

semgrep_config_requires_network = hardening.semgrep_config_requires_network


def hardened_run_with_watchdog(command, env, output, tool):
    return hardening.hardened_run_with_watchdog(command, env, output, tool, runtime=rtm)


def apply_patches() -> None:
    hardening.apply_to_runtime(rtm)


def main() -> int:
    apply_patches()
    return rtm.main()


if __name__ == '__main__':
    raise SystemExit(main())
