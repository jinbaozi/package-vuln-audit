#!/usr/bin/env python3
"""Execute traditional tools from required-tools-matrix.json."""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import time


BLOCKING_APPLICABILITY = {"mandatory", "profile-required", "recommended"}


def load_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def expand_command(command: list[str], source: pathlib.Path, raw: pathlib.Path) -> list[str]:
    return [part.replace("<source>", str(source)).replace("<raw>", str(raw)) for part in command]


def run_one(tool: dict, source: pathlib.Path, raw: pathlib.Path) -> tuple[dict, list[dict]]:
    name = tool["name"]
    binary = tool["binary"]
    attempts = []
    if tool["applicability"] == "not-applicable":
        return {
            "name": name,
            "status": "not-applicable",
            "output": "",
            "reason": tool.get("evidence", "not applicable to this project"),
            "notes": tool.get("evidence", ""),
        }, attempts

    if shutil.which(binary) is None:
        reason = "not-installed"
        return {
            "name": name,
            "status": "blocked" if tool["applicability"] in BLOCKING_APPLICABILITY else "not-installed",
            "output": "",
            "reason": reason,
            "notes": tool.get("evidence", ""),
        }, [{
            "tool": name,
            "attempt": 1,
            "status": reason,
            "command": tool.get("command", []),
            "elapsed_ms": 0,
            "exit_code": None,
            "recovery_action": "tool-install-assistant" if tool["applicability"] in BLOCKING_APPLICABILITY else "record-missing",
        }]

    max_attempts = int(tool.get("retry_policy", {}).get("max_attempts", 1))
    final_rc = 1
    final_output = raw / f"{name}.out"
    command = expand_command(tool["command"], source, raw)
    for attempt in range(1, max_attempts + 1):
        start = time.time()
        with final_output.open("w") as fh:
            p = subprocess.run(command, stdout=fh, stderr=subprocess.STDOUT, text=True)
        elapsed_ms = int((time.time() - start) * 1000)
        final_rc = p.returncode
        attempts.append({
            "tool": name,
            "attempt": attempt,
            "status": "completed" if p.returncode == 0 else "failed",
            "command": command,
            "elapsed_ms": elapsed_ms,
            "exit_code": p.returncode,
            "recovery_action": "none" if p.returncode == 0 else "retry" if attempt < max_attempts else "block",
        })
        if p.returncode == 0:
            break

    if final_rc == 0:
        return {"name": name, "status": "completed", "output": str(final_output), "reason": "", "notes": ""}, attempts
    status = "blocked" if tool["applicability"] in BLOCKING_APPLICABILITY else "failed"
    return {"name": name, "status": status, "output": str(final_output), "reason": "nonzero-exit", "notes": tool.get("evidence", "")}, attempts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    matrix_path = pathlib.Path(args.matrix)
    source = pathlib.Path(args.source)
    out = pathlib.Path(args.out)
    raw = out / "raw"
    raw.mkdir(parents=True, exist_ok=True)

    matrix = load_json(matrix_path)
    rows = []
    attempts = []
    blocked = []
    for tool in matrix.get("tools", []):
        row, tool_attempts = run_one(tool, source, raw)
        rows.append(row)
        attempts.extend(tool_attempts)
        if row["status"] == "blocked":
            blocked.append(row["name"])

    summary = {
        "tools": rows,
        "raw_outputs": [r["output"] for r in rows if r.get("output")],
        "summary": "Tool execution completed." if not blocked else "Tool execution blocked: " + ", ".join(blocked),
        "normalized_candidate_count": 0,
        "errors": [f"{name}: blocked" for name in blocked],
    }
    (out / "tool-summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    (out / "tool-execution-attempts.json").write_text(json.dumps({"attempts": attempts}, indent=2, ensure_ascii=False))
    return 2 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
