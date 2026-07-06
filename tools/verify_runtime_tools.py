#!/usr/bin/env python3
"""Verify required tools inside the authoritative PVAS runtime container."""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys
from typing import Callable

from pvas_io import write_json
from tool_catalog import CATALOG, STRICT_REQUIRED_TOOLS


Runner = Callable[[str, list[str]], tuple[int, str]]


def _required_tools(profile: str) -> list[str]:
    return list(STRICT_REQUIRED_TOOLS.get(profile) or STRICT_REQUIRED_TOOLS.get("standard") or [])


def _status_for(rc: int, output: str) -> str:
    if rc == 0:
        return "present"
    if rc == 124:
        return "abnormal-timeout"
    if rc == 127:
        return "missing"
    return "installed-but-unusable"


def build_runtime_tool_check(
    profile: str,
    target_runtime: str,
    runner: Runner,
    *,
    host_observations: dict | None = None,
) -> dict:
    tools: dict[str, dict] = {}
    missing_required: list[str] = []
    unusable_required: list[str] = []
    for name in _required_tools(profile):
        meta = CATALOG.get(name, {"binary": name, "version_args": ["--version"]})
        command = [str(meta.get("binary") or name), *list(meta.get("version_args") or ["--version"])]
        rc, output = runner(name, command)
        status = _status_for(rc, output)
        tools[name] = {
            "binary": command[0],
            "command": command,
            "status": status,
            "exit_code": rc,
            "version_output": (output or "").splitlines()[:3],
            "runtime_scope": meta.get("runtime_scope", "container-required"),
        }
        if status == "missing":
            missing_required.append(name)
        elif status != "present":
            unusable_required.append(name)

    if missing_required:
        status = "blocked-recovery-required"
        reason = f"container-tool-missing: {missing_required[0]}"
        recovery_action = "rebuild-runtime-image"
    elif unusable_required:
        status = "blocked-recovery-required"
        reason = f"installed-but-unusable: {unusable_required[0]}"
        recovery_action = "rebuild-runtime-image"
    else:
        status = "passed"
        reason = ""
        recovery_action = "none"
    return {
        "schema_version": "1.0",
        "status": status,
        "profile": profile,
        "target_runtime": target_runtime,
        "actual_runtime": "container",
        "reason": reason,
        "recovery_action": recovery_action,
        "tools": tools,
        "host_observations": host_observations or {},
    }


def render_markdown(check: dict) -> str:
    lines = [
        "# Runtime Tool Check",
        "",
        f"- Status: {check['status']}",
        f"- Profile: {check['profile']}",
        f"- Actual runtime: {check.get('actual_runtime', 'container')}",
        f"- Reason: {check.get('reason') or 'none'}",
        "",
        "## Tools",
        "",
    ]
    for name, row in check.get("tools", {}).items():
        lines.append(f"- {name}: {row.get('status')} ({row.get('binary')})")
    lines.append("")
    return "\n".join(lines)


def write_runtime_tool_check(check: dict, out_dir: pathlib.Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "runtime-tool-check.json", check)
    (out_dir / "runtime-tool-check.md").write_text(render_markdown(check))


def local_runner(_name: str, command: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
    except FileNotFoundError:
        return 127, "not found"
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or "") if isinstance(exc.stdout, str) else "timeout"
    return proc.returncode, proc.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="standard")
    ap.add_argument("--target-runtime", default="pvas-container")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    check = build_runtime_tool_check(args.profile, args.target_runtime, local_runner)
    write_runtime_tool_check(check, pathlib.Path(args.out))
    return 0 if check["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
