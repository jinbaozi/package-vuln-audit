#!/usr/bin/env python3
"""Execute traditional tools from required-tools-matrix.json."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Any

from pvas_io import load_json, write_json

BLOCKING_APPLICABILITY = {"mandatory", "profile-required", "recommended"}
ABNORMAL_STATUSES = {"abnormal"}
TIMEOUT_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)(ms|s|m|h)?\s*$", re.I)
LOCAL_DB_TOOLS = {"codeql", "grype", "trivy", "syft"}


def expand_command(command: list[str], source: pathlib.Path, raw: pathlib.Path) -> list[str]:
    return [part.replace("<source>", str(source)).replace("<raw>", str(raw)) for part in command]


def expand_env(env: dict[str, str], source: pathlib.Path, raw: pathlib.Path) -> dict[str, str]:
    expanded: dict[str, str] = {}
    for key, value in env.items():
        expanded[key] = value.replace("<source>", str(source)).replace("<raw>", str(raw))
    return expanded


def parse_duration(value: Any, default: float) -> float:
    if isinstance(value, (int, float)):
        return max(float(value), 0.1)
    if not isinstance(value, str):
        return default
    m = TIMEOUT_RE.match(value)
    if not m:
        return default
    amount = float(m.group(1))
    unit = (m.group(2) or "s").lower()
    if unit == "ms":
        return max(amount / 1000.0, 0.1)
    if unit == "m":
        return amount * 60
    if unit == "h":
        return amount * 3600
    return amount


def proc_cpu_ticks(pid: int) -> int:
    try:
        parts = pathlib.Path(f"/proc/{pid}/stat").read_text().split()
        return int(parts[13]) + int(parts[14])
    except Exception:
        return 0


def output_size(path: pathlib.Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def terminate_process(proc: subprocess.Popen[str], grace_seconds: float = 2.0) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        proc.terminate()
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.05)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        proc.kill()


def command_mentions_remote_semgrep(command: list[str]) -> bool:
    return "--config" in command and "auto" in command


def no_semgrep_config(command: list[str]) -> bool:
    return "semgrep" in pathlib.Path(command[0]).name and "--config" not in command


def classify_osv_output(output: pathlib.Path) -> tuple[str | None, str | None]:
    text = output.read_text(errors="ignore") if output.exists() else ""
    lowered = text.lower()
    if "no package sources found" in lowered or "no lockfiles found" in lowered:
        return "not-applicable", "no-package-sources"
    return None, None


def semgrep_json_status(raw: pathlib.Path, stdout_path: pathlib.Path) -> tuple[str | None, str | None, str]:
    semgrep_json = raw / "semgrep.json"
    if not semgrep_json.exists():
        return "incomplete", "malformed-output", str(stdout_path)
    try:
        parsed = json.loads(semgrep_json.read_text())
    except json.JSONDecodeError:
        return "incomplete", "malformed-output", str(stdout_path)
    results = parsed.get("results") if isinstance(parsed, dict) else None
    if isinstance(results, list) and results:
        return "completed-with-findings", "", str(semgrep_json)
    return "completed", "", str(semgrep_json)


def preflight_tool(tool: dict, raw: pathlib.Path) -> tuple[dict | None, list[dict]]:
    name = tool["name"]
    attempts: list[dict] = []
    if tool.get("applicability") == "not-applicable":
        return {
            "name": name,
            "status": "not-applicable",
            "output": "",
            "reason": tool.get("evidence", "not applicable to this project"),
            "notes": tool.get("evidence", ""),
            "strict_decision": "continue",
            "coverage_impact": "none",
            "watchdog_events": [],
            "network_used": False,
        }, attempts
    raw.mkdir(parents=True, exist_ok=True)
    return None, attempts


def run_with_watchdog(command: list[str], env: dict[str, str], output: pathlib.Path, tool: dict) -> tuple[int | None, int, list[dict], str]:
    soft_timeout = parse_duration(tool.get("timeout"), 60.0)
    idle_timeout = parse_duration((tool.get("watchdog") or {}).get("idle_timeout"), max(min(soft_timeout / 2, 30.0), 1.0))
    hard_timeout = parse_duration(tool.get("hard_timeout"), max(soft_timeout * 10, soft_timeout + idle_timeout + 1.0))
    watchdog_events: list[dict] = []
    start = time.monotonic()
    last_progress = start
    last_size = output_size(output)
    last_cpu = 0

    merged_env = os.environ.copy()
    merged_env.update(env)
    for key in ("SEMGREP_SETTINGS_FILE", "SEMGREP_LOG_FILE"):
        if key in merged_env:
            pathlib.Path(merged_env[key]).parent.mkdir(parents=True, exist_ok=True)

    try:
        with output.open("w") as fh:
            proc = subprocess.Popen(
                command,
                stdout=fh,
                stderr=subprocess.STDOUT,
                text=True,
                env=merged_env,
                start_new_session=True,
            )
            last_cpu = proc_cpu_ticks(proc.pid)
            while True:
                rc = proc.poll()
                now = time.monotonic()
                current_size = output_size(output)
                current_cpu = proc_cpu_ticks(proc.pid)
                if current_size > last_size or current_cpu > last_cpu:
                    last_progress = now
                    last_size = current_size
                    last_cpu = current_cpu
                    watchdog_events.append({
                        "event": "progress",
                        "elapsed_ms": int((now - start) * 1000),
                        "output_bytes": current_size,
                    })
                if rc is not None:
                    return rc, int((now - start) * 1000), watchdog_events, "exited"
                if now - start > hard_timeout:
                    terminate_process(proc)
                    status = "hard-timeout-with-progress" if last_progress > start else "hard-timeout"
                    watchdog_events.append({"event": status, "elapsed_ms": int((now - start) * 1000)})
                    return None, int((time.monotonic() - start) * 1000), watchdog_events, status
                if now - start > soft_timeout and now - last_progress > idle_timeout:
                    terminate_process(proc)
                    watchdog_events.append({"event": "abnormal-timeout", "elapsed_ms": int((now - start) * 1000)})
                    return None, int((time.monotonic() - start) * 1000), watchdog_events, "abnormal-timeout"
                time.sleep(0.1)
    except OSError as e:
        watchdog_events.append({"event": "spawn-failed", "error": str(e)})
        return None, int((time.monotonic() - start) * 1000), watchdog_events, "spawn-failed"


def run_one(tool: dict, source: pathlib.Path, raw: pathlib.Path) -> tuple[dict, list[dict]]:
    name = tool["name"]
    binary = tool["binary"]
    row, attempts = preflight_tool(tool, raw)
    if row:
        return row, attempts

    command = expand_command(tool["command"], source, raw)
    env = expand_env(tool.get("env") or {}, source, raw)
    network_used = bool(tool.get("network_required") and command_mentions_remote_semgrep(command))
    if shutil.which(binary) is None:
        reason = "not-installed"
        attempt = {
            "tool": name,
            "attempt": 1,
            "status": reason,
            "command": command,
            "elapsed_ms": 0,
            "exit_code": None,
            "recovery_action": "tool-install-assistant" if tool.get("applicability") in BLOCKING_APPLICABILITY else "record-missing",
            "watchdog_events": [],
            "network_used": False,
        }
        return {
            "name": name,
            "status": "not-installed",
            "output": "",
            "reason": reason,
            "notes": tool.get("evidence", ""),
            "strict_decision": "needs-install",
            "coverage_impact": tool.get("evidence", ""),
            "watchdog_events": [],
            "network_used": False,
        }, [attempt]
    if name == "semgrep" and no_semgrep_config(tool.get("command", [])):
        return {
            "name": name,
            "status": "incomplete",
            "output": "",
            "reason": "no-local-rules",
            "notes": "No local Semgrep rules were available and network-backed --config auto is not approved.",
            "strict_decision": "continue-needs-manual-review",
            "coverage_impact": "semgrep rule-based SAST coverage missing",
            "watchdog_events": [],
            "network_used": False,
        }, attempts
    if name in LOCAL_DB_TOOLS and tool.get("network_policy") in {"offline", "restricted"} and tool.get("offline_fallback"):
        return {
            "name": name,
            "status": "incomplete",
            "output": "",
            "reason": "missing-local-db",
            "notes": f"{name} requires a local database/bundle in {tool.get('network_policy')} mode.",
            "strict_decision": "continue-needs-manual-review",
            "coverage_impact": f"{name} offline database coverage missing",
            "watchdog_events": [],
            "network_used": False,
        }, attempts

    max_attempts = int(tool.get("retry_policy", {}).get("max_attempts", 1))
    final_output = raw / f"{name}.out"
    final_rc: int | None = None
    final_reason = ""
    final_events: list[dict] = []
    elapsed_ms = 0
    for attempt_no in range(1, max_attempts + 1):
        final_rc, elapsed_ms, final_events, final_reason = run_with_watchdog(command, env, final_output, tool)
        abnormal = final_reason in {"spawn-failed", "abnormal-timeout"}
        attempts.append({
            "tool": name,
            "attempt": attempt_no,
            "status": "abnormal" if abnormal else "completed" if final_rc == 0 else "incomplete",
            "command": command,
            "elapsed_ms": elapsed_ms,
            "exit_code": final_rc,
            "recovery_action": "none" if final_rc == 0 else "retry" if attempt_no < max_attempts and abnormal else "manual-review",
            "watchdog_events": final_events,
            "network_used": network_used,
        })
        if final_rc == 0 or not abnormal:
            break

    if final_reason == "spawn-failed":
        status, reason = "abnormal", "spawn-failed"
    elif final_reason == "abnormal-timeout":
        status, reason = "abnormal", "abnormal-timeout"
    elif final_reason == "hard-timeout-with-progress":
        status, reason = "incomplete", "hard-timeout-with-progress"
    elif final_rc == 0:
        status, reason = "completed", ""
    else:
        status, reason = "incomplete", "nonzero-exit"

    output_path = str(final_output)
    if name == "osv-scanner" and status == "incomplete":
        special_status, special_reason = classify_osv_output(final_output)
        if special_status:
            status, reason = special_status, special_reason or reason
    if name == "semgrep" and status == "completed":
        semgrep_status, semgrep_reason, output_path = semgrep_json_status(raw, final_output)
        if semgrep_status:
            status = semgrep_status
            reason = semgrep_reason or reason

    strict_decision = "block" if status == "abnormal" else "continue"
    if status in {"incomplete", "not-installed"}:
        strict_decision = "continue-needs-manual-review"
    coverage = "" if status in {"completed", "completed-with-findings", "not-applicable"} else tool.get("evidence", "")
    return {
        "name": name,
        "status": status,
        "output": output_path,
        "reason": reason,
        "notes": tool.get("evidence", ""),
        "strict_decision": strict_decision,
        "coverage_impact": coverage,
        "watchdog_events": final_events,
        "network_used": network_used,
    }, attempts


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
    try:
        raw.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        write_json(out / "tool-summary.json", {
            "tools": [],
            "raw_outputs": [],
            "summary": f"Tool execution abnormal: output directory unavailable: {e}",
            "normalized_candidate_count": 0,
            "errors": [f"output-directory: {e}"],
            "strict_decision": "block",
        })
        return 2

    matrix = load_json(matrix_path)
    rows = []
    attempts = []
    abnormal = []
    incomplete = []
    for tool in matrix.get("tools", []):
        row, tool_attempts = run_one(tool, source, raw)
        rows.append(row)
        attempts.extend(tool_attempts)
        if row["status"] in ABNORMAL_STATUSES:
            abnormal.append(row["name"])
        elif row["status"] in {"incomplete", "not-installed"}:
            incomplete.append(row["name"])

    strict_decision = "block" if abnormal else "continue"
    summary = {
        "tools": rows,
        "raw_outputs": [r["output"] for r in rows if r.get("output")],
        "summary": "Tool execution completed." if not abnormal else "Tool execution abnormal: " + ", ".join(abnormal),
        "normalized_candidate_count": 0,
        "errors": [f"{name}: abnormal" for name in abnormal],
        "strict_decision": strict_decision,
        "coverage_impact": [r for r in rows if r.get("coverage_impact")],
        "incomplete_tools": incomplete,
    }
    write_json(out / "tool-summary.json", summary)
    write_json(out / "tool-execution-attempts.json", {"attempts": attempts})
    return 2 if abnormal else 0


if __name__ == "__main__":
    raise SystemExit(main())
