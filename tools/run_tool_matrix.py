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
BLOCKING_STATUSES = {"blocked-pending-confirmation", "blocked-recovery-required"}
TIMEOUT_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)(ms|s|m|h)?\s*$", re.I)
LOCAL_DB_TOOLS = {"codeql", "grype", "trivy", "syft"}
CPPCHECK_IMPL_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".c++"}
CPPCHECK_EXCLUDE_PARTS = {".git", "build", "dist", "out", "target", "node_modules", "vendor", "third_party", "audit-output", "__pycache__"}
CPPCHECK_GCC_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?:(?P<column>\d+):)?\s*"
    r"(?P<severity>error|warning|style|performance|portability|information):\s*"
    r"(?P<message>.*?)(?:\s*\[(?P<id>[^\]]+)\])?\s*$",
    re.I,
)
DEFAULT_CPPCHECK_SHARD_SIZE = 100


def terminal_summary_chars() -> int:
    try:
        return max(int(os.environ.get("PVAS_TERMINAL_SUMMARY_CHARS", "1000")), 80)
    except ValueError:
        return 1000


def truncate_text(text: str, limit: int | None = None) -> tuple[str, bool]:
    limit = terminal_summary_chars() if limit is None else limit
    if len(text) <= limit:
        return text, False
    return text[: max(limit - 15, 0)] + "...[truncated]", True


def semgrep_result_count(path: pathlib.Path) -> int:
    if not path.exists():
        return 0
    try:
        parsed = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return 0
    results = parsed.get("results") if isinstance(parsed, dict) else None
    return len(results) if isinstance(results, list) else 0


def annotate_summary_row(row: dict) -> dict:
    output = str(row.get("output") or "")
    output_path = pathlib.Path(output) if output else None
    if "raw_output_ref" not in row:
        row["raw_output_ref"] = output
    if "output_bytes" not in row:
        row["output_bytes"] = output_size(output_path) if output_path else 0
    if "result_count" not in row:
        row["result_count"] = 0
    row.setdefault("terminal_summary_truncated", False)
    return apply_admission_policy(row)


def apply_admission_policy(row: dict) -> dict:
    status = str(row.get("status") or "")
    reason = str(row.get("reason") or "")
    result_count = int(row.get("result_count") or 0)
    shards_total = int(row.get("shards_total") or 0)
    shards_completed = int(row.get("shards_completed") or 0)
    has_partial_coverage = (
        reason == "partial-timeout"
        or (shards_total > 0 and 0 < shards_completed < shards_total)
        or bool(row.get("partial_outputs") and status in {"incomplete", "blocked-recovery-required"})
    )

    if status == "not-applicable":
        coverage_profile = "not_applicable"
    elif status in {"completed", "completed-with-findings"}:
        coverage_profile = "complete"
    elif has_partial_coverage:
        coverage_profile = "partial"
    else:
        coverage_profile = "unavailable"

    if status in {"completed", "completed-with-findings", "not-applicable"}:
        accuracy_risk = "none"
    elif reason in {"not-installed"}:
        accuracy_risk = "missing_tool"
    elif reason in {"malformed-output"}:
        accuracy_risk = "malformed_output"
    elif reason in {"missing-local-db"}:
        accuracy_risk = "stale_database"
    elif has_partial_coverage:
        accuracy_risk = "limited_coverage"
    else:
        accuracy_risk = "manual_confirmation_required"

    if coverage_profile == "complete":
        admission_policy = "candidate_evidence_allowed"
    elif has_partial_coverage and result_count > 0:
        admission_policy = "positive_only"
    elif row.get("strict_decision") == "continue-needs-manual-review":
        admission_policy = "manual_review_only"
    else:
        admission_policy = "not_admissible"

    row["coverage_profile"] = coverage_profile
    row["accuracy_risk"] = accuracy_risk
    row["admission_policy"] = admission_policy
    row["negative_conclusion_allowed"] = coverage_profile == "complete" and status in {"completed", "completed-with-findings"}
    return row


def print_tool_status(row: dict) -> None:
    payload = {
        "tool": row.get("name"),
        "status": row.get("status"),
        "reason": row.get("reason", ""),
        "output": row.get("raw_output_ref") or row.get("output", ""),
        "result_count": row.get("result_count", 0),
        "bytes": row.get("output_bytes", 0),
    }
    text, truncated = truncate_text(json.dumps(payload, sort_keys=True))
    row["terminal_summary_truncated"] = truncated
    print(f"[PVAS-TOOL] {text}")


def expand_command(command: list[str], source: pathlib.Path, raw: pathlib.Path, file_list: list[pathlib.Path] | None = None) -> list[str]:
    source_str = " ".join(str(f) for f in file_list) if file_list else str(source)
    return [part.replace("<source>", source_str).replace("<raw>", str(raw)) for part in command]


def expand_env(env: dict[str, str], source: pathlib.Path, raw: pathlib.Path, file_list: list[pathlib.Path] | None = None) -> dict[str, str]:
    source_str = " ".join(str(f) for f in file_list) if file_list else str(source)
    expanded: dict[str, str] = {}
    for key, value in env.items():
        expanded[key] = value.replace("<source>", source_str).replace("<raw>", str(raw))
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


def is_blocking_tool(tool: dict) -> bool:
    return tool.get("applicability") in BLOCKING_APPLICABILITY


def block_required_status(tool: dict, status: str, reason: str) -> tuple[str, str, str]:
    if not is_blocking_tool(tool):
        if status == "abnormal":
            return status, reason, "block"
        if status in {"incomplete", "not-installed"}:
            return status, reason, "needs-install" if status == "not-installed" else "continue-needs-manual-review"
        return status, reason, "continue"
    if status in {"completed", "completed-with-findings", "not-applicable"}:
        return status, reason, "continue"
    if reason == "stalled":
        return "blocked-pending-confirmation", reason, "block"
    return "blocked-recovery-required", reason or status, "block"


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


MANIFEST_PATTERNS = [
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.toml", "Cargo.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock",
    "Gemfile", "Gemfile.lock",
    "go.mod", "go.sum",
    "pom.xml", "build.gradle", "gradle.lockfile",
    "composer.json", "composer.lock",
    "nuget.config", "packages.lock.json",
]


def _check_osv_applicable(source: pathlib.Path) -> tuple[str | None, str | None]:
    """Check if source tree has package manifests that osv-scanner can scan.
    Returns (status, reason) or (None, None) if applicable."""
    for pattern in MANIFEST_PATTERNS:
        matches = list(source.rglob(pattern))
        if matches:
            return None, None
    return "not-applicable", f"no package manifests found in {source}; osv-scanner requires lockfiles"


def preflight_tool(tool: dict, raw: pathlib.Path, source: pathlib.Path | None = None) -> tuple[dict | None, list[dict]]:
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
            "result_count": 0,
            "output_bytes": 0,
            "raw_output_ref": "",
            "terminal_summary_truncated": False,
        }, attempts
    if name == "osv-scanner" and source is not None:
        osv_status, osv_reason = _check_osv_applicable(source)
        if osv_status:
            return {
                "name": name,
                "status": osv_status,
                "output": "",
                "reason": osv_reason or "no package manifests detected",
                "notes": tool.get("evidence", ""),
                "strict_decision": "continue",
            "coverage_impact": "none",
            "watchdog_events": [],
            "network_used": False,
            "result_count": 0,
            "output_bytes": 0,
            "raw_output_ref": "",
            "terminal_summary_truncated": False,
        }, attempts
    raw.mkdir(parents=True, exist_ok=True)
    return None, attempts


def run_with_watchdog(command: list[str], env: dict[str, str], output: pathlib.Path, tool: dict) -> tuple[int | None, int, list[dict], str]:
    soft_timeout = parse_duration(tool.get("timeout"), 600.0)
    watchdog_events: list[dict] = []
    start = time.monotonic()
    last_progress = start
    last_size = output_size(output)
    last_cpu = 0
    blocking = is_blocking_tool(tool)
    stalled = False

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
                    return rc, int((now - start) * 1000), watchdog_events, "stalled" if stalled else "exited"
                if now - last_progress > soft_timeout:
                    if blocking:
                        stalled = True
                        watchdog_events.append({
                            "event": "stalled-diagnostic",
                            "elapsed_ms": int((now - start) * 1000),
                            "output_bytes": current_size,
                            "diagnostic": "required tool made no observed CPU/output progress; waiting for process exit",
                        })
                        last_progress = now
                        time.sleep(0.1)
                        continue
                    terminate_process(proc)
                    watchdog_events.append({"event": "abnormal-timeout", "elapsed_ms": int((now - start) * 1000)})
                    return None, int((time.monotonic() - start) * 1000), watchdog_events, "abnormal-timeout"
                time.sleep(0.1)
    except OSError as e:
        watchdog_events.append({"event": "spawn-failed", "error": str(e)})
        return None, int((time.monotonic() - start) * 1000), watchdog_events, "spawn-failed"


def run_one(tool: dict, source: pathlib.Path, raw: pathlib.Path, file_list: list[pathlib.Path] | None = None) -> tuple[dict, list[dict]]:
    name = tool["name"]
    binary = tool["binary"]
    row, attempts = preflight_tool(tool, raw, source=source if name == "osv-scanner" else None)
    if row:
        return row, attempts
    if name == "cppcheck":
        if tool.get("execution_mode") == "project":
            return run_cppcheck_project(tool, source, raw)
        return run_cppcheck_sharded(tool, source, raw, file_list=file_list)

    command = expand_command(tool["command"], source, raw, file_list=file_list)
    env = expand_env(tool.get("env") or {}, source, raw, file_list=file_list)
    network_used = bool(tool.get("network_required") and command_mentions_remote_semgrep(command))
    if shutil.which(binary) is None:
        reason = "not-installed"
        blocking = is_blocking_tool(tool)
        if blocking:
            print(f"[PVAS-TOOL-MISSING] {name} not installed. Impact: {tool.get('evidence', '')}", file=sys.stderr)
            print(f"[PVAS-TOOL-MISSING] {name} is required ({tool.get('applicability', 'unknown')}). Blocking execution.", file=sys.stderr)
        attempt = {
            "tool": name,
            "attempt": 1,
            "status": reason,
            "command": command,
            "elapsed_ms": 0,
            "exit_code": None,
            "recovery_action": "tool-install-assistant" if blocking else "record-missing",
            "watchdog_events": [],
            "network_used": False,
        }
        return {
            "name": name,
            "status": "blocked-recovery-required" if blocking else "not-installed",
            "output": "",
            "reason": reason,
            "notes": tool.get("evidence", ""),
            "strict_decision": "block" if blocking else "needs-install",
            "coverage_impact": tool.get("evidence", ""),
            "watchdog_events": [],
            "network_used": False,
            "result_count": 0,
            "output_bytes": 0,
            "raw_output_ref": "",
            "terminal_summary_truncated": False,
        }, [attempt]
    if name == "semgrep" and no_semgrep_config(tool.get("command", [])):
        status, reason, strict_decision = block_required_status(tool, "incomplete", "no-local-rules")
        return {
            "name": name,
            "status": status,
            "output": "",
            "reason": reason,
            "notes": "No local Semgrep rules were available and network-backed --config auto is not approved.",
            "strict_decision": strict_decision,
            "coverage_impact": "semgrep rule-based SAST coverage missing",
            "watchdog_events": [],
            "network_used": False,
            "result_count": 0,
            "output_bytes": 0,
            "raw_output_ref": "",
            "terminal_summary_truncated": False,
        }, attempts
    if name in LOCAL_DB_TOOLS and tool.get("network_policy") in {"offline", "restricted"} and tool.get("offline_fallback"):
        status, reason, strict_decision = block_required_status(tool, "incomplete", "missing-local-db")
        return {
            "name": name,
            "status": status,
            "output": "",
            "reason": reason,
            "notes": f"{name} requires a local database/bundle in {tool.get('network_policy')} mode.",
            "strict_decision": strict_decision,
            "coverage_impact": f"{name} offline database coverage missing",
            "watchdog_events": [],
            "network_used": False,
            "result_count": 0,
            "output_bytes": 0,
            "raw_output_ref": "",
            "terminal_summary_truncated": False,
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
            "status": "blocked-pending-confirmation" if final_reason == "stalled" and is_blocking_tool(tool) else "abnormal" if abnormal else "completed" if final_rc == 0 else "incomplete",
            "command": command,
            "elapsed_ms": elapsed_ms,
            "exit_code": final_rc,
            "recovery_action": "none" if final_rc == 0 else "retry" if attempt_no < max_attempts and abnormal else "manual-review",
            "watchdog_events": final_events,
            "network_used": network_used,
            "output": str(final_output),
            "output_bytes": output_size(final_output),
        })
        if final_rc == 0 or not abnormal:
            break

    if final_reason == "stalled" and is_blocking_tool(tool):
        status, reason = "blocked-pending-confirmation", "stalled"
    elif final_reason == "spawn-failed":
        status, reason = "abnormal", "spawn-failed"
    elif final_reason == "abnormal-timeout":
        status, reason = "abnormal", "abnormal-timeout"
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
    output_ref = output_path
    output_ref_path = pathlib.Path(output_ref) if output_ref else final_output
    result_count = semgrep_result_count(output_ref_path) if name == "semgrep" else 0

    status, reason, strict_decision = block_required_status(tool, status, reason)
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
        "result_count": result_count,
        "output_bytes": output_size(output_ref_path),
        "raw_output_ref": output_ref,
        "terminal_summary_truncated": False,
    }, attempts


def cppcheck_summary_metadata(tool: dict) -> dict:
    if tool.get("name") != "cppcheck":
        return {}
    metadata = {}
    for key in (
        "cppcheck_mode",
        "cppcheck_mode_source",
        "mode_limitations",
        "cppcheck_scope_mode",
        "cppcheck_scope_file",
        "cppcheck_compile_database",
        "cppcheck_profile_ids",
        "scope_limitations",
        "cppcheck_include_paths",
        "cppcheck_build_dir",
        "cppcheck_jobs",
    ):
        if key in tool:
            metadata[key] = tool[key]
    return metadata


def expand_command_for_files(command: list[str], source: pathlib.Path, raw: pathlib.Path, files: list[pathlib.Path]) -> list[str]:
    expanded: list[str] = []
    for part in command:
        if part == "<source>":
            expanded.extend(str(f) for f in files)
        else:
            expanded.append(part.replace("<source>", str(source)).replace("<raw>", str(raw)))
    return expanded


def expand_cppcheck_command_for_file_list(command: list[str], source: pathlib.Path, raw: pathlib.Path, file_list_path: pathlib.Path) -> list[str]:
    expanded: list[str] = []
    used_file_list = False
    for part in command:
        if part == "<source>":
            expanded.append(f"--file-list={file_list_path}")
            used_file_list = True
        elif str(part).startswith("--file-list="):
            expanded.append(f"--file-list={file_list_path}")
            used_file_list = True
        else:
            replaced = part.replace("<source>", str(source)).replace("<raw>", str(raw))
            expanded.append(replaced)
    if not used_file_list:
        expanded.append(f"--file-list={file_list_path}")
    return expanded


def ensure_cppcheck_build_dirs(command: list[str]) -> None:
    for idx, part in enumerate(command):
        build_dir = ""
        if part == "--cppcheck-build-dir" and idx + 1 < len(command):
            build_dir = command[idx + 1]
        elif part.startswith("--cppcheck-build-dir="):
            build_dir = part.split("=", 1)[1]
        if build_dir:
            pathlib.Path(build_dir).mkdir(parents=True, exist_ok=True)


def cppcheck_diagnostic_count(path: pathlib.Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(errors="ignore").splitlines() if CPPCHECK_GCC_RE.match(line))


def cppcheck_output_bytes(paths: list[pathlib.Path]) -> int:
    return sum(output_size(path) for path in paths)


def is_cppcheck_source(path: pathlib.Path) -> bool:
    return path.suffix.lower() in CPPCHECK_IMPL_EXTENSIONS


def is_cppcheck_translation_unit(path: pathlib.Path) -> bool:
    return path.suffix.lower() in CPPCHECK_IMPL_EXTENSIONS


def discover_cppcheck_files(source: pathlib.Path) -> list[pathlib.Path]:
    if source.is_file():
        return [source] if is_cppcheck_source(source) else []
    if not source.is_dir():
        return []
    files: list[pathlib.Path] = []
    for path in source.rglob("*"):
        if not path.is_file() or not is_cppcheck_source(path):
            continue
        try:
            rel_parts = path.relative_to(source).parts
        except ValueError:
            rel_parts = path.parts
        if any(part in CPPCHECK_EXCLUDE_PARTS for part in rel_parts):
            continue
        files.append(path)
    return sorted(files)


def cppcheck_file_scope(source: pathlib.Path, file_list: list[pathlib.Path] | None) -> list[pathlib.Path]:
    selected = file_list if file_list is not None else discover_cppcheck_files(source)
    files: list[pathlib.Path] = []
    seen: set[str] = set()
    for path in selected:
        if not is_cppcheck_source(path) or not path.exists():
            continue
        key = str(path.resolve())
        if key not in seen:
            files.append(path)
            seen.add(key)
    return files


def _scope_path(tool: dict) -> pathlib.Path | None:
    value = str(tool.get("cppcheck_scope_file") or "")
    return pathlib.Path(value) if value else None


def _load_cppcheck_scope(tool: dict) -> tuple[dict | None, list[str]]:
    path = _scope_path(tool)
    if not path:
        return None, ["cppcheck scope artifact not configured; used conservative fallback file discovery"]
    if not path.exists():
        return None, ["cppcheck scope artifact missing; used conservative fallback file discovery"]
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return None, ["cppcheck scope artifact malformed; used conservative fallback file discovery"]
    if not isinstance(data, dict):
        return None, ["cppcheck scope artifact malformed; used conservative fallback file discovery"]
    return data, []


def cppcheck_scope_files_from_artifact(scope: dict) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for value in scope.get("included_files") or []:
        path = pathlib.Path(str(value))
        if path.exists() and is_cppcheck_translation_unit(path):
            files.append(path)
    return files


def apply_cppcheck_scope_metadata(row: dict, tool: dict, scope: dict | None, limitations: list[str]) -> dict:
    if scope:
        row["cppcheck_scope_mode"] = str(scope.get("scope_mode") or tool.get("cppcheck_scope_mode") or "unspecified")
        row["cppcheck_compile_database"] = str(scope.get("compile_database") or tool.get("cppcheck_compile_database") or "")
        row["cppcheck_profile_ids"] = list(scope.get("profile_ids") or tool.get("cppcheck_profile_ids") or [])
        row["cppcheck_include_paths"] = list(scope.get("include_paths") or tool.get("cppcheck_include_paths") or [])
        combined_limitations = list(scope.get("limitations") or [])
        combined_limitations.extend(limitations)
        row["scope_limitations"] = combined_limitations
    else:
        row["cppcheck_scope_mode"] = "fallback-file-list"
        row["cppcheck_compile_database"] = str(tool.get("cppcheck_compile_database") or "")
        row["cppcheck_profile_ids"] = list(tool.get("cppcheck_profile_ids") or [])
        row["cppcheck_include_paths"] = list(tool.get("cppcheck_include_paths") or [])
        row["scope_limitations"] = limitations
    for key in ("cppcheck_mode", "cppcheck_mode_source", "mode_limitations", "cppcheck_scope_file", "cppcheck_build_dir", "cppcheck_jobs"):
        if key in tool:
            row[key] = tool[key]
    return row


def cppcheck_effective_files(tool: dict, source: pathlib.Path, file_list: list[pathlib.Path] | None) -> tuple[list[pathlib.Path], dict | None, list[str], pathlib.Path | None]:
    if file_list is not None:
        return cppcheck_file_scope(source, file_list), None, [], None
    scope, limitations = _load_cppcheck_scope(tool)
    if scope:
        compile_database = scope.get("compile_database")
        if scope.get("scope_mode") == "compile-database" and compile_database:
            return cppcheck_scope_files_from_artifact(scope), scope, limitations, pathlib.Path(str(compile_database))
        files = cppcheck_scope_files_from_artifact(scope)
        return cppcheck_file_scope(source, files), scope, limitations, None
    return cppcheck_file_scope(source, None), None, limitations, None


def chunks(items: list[pathlib.Path], size: int) -> list[list[pathlib.Path]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def write_cppcheck_file_list(raw: pathlib.Path, files: list[pathlib.Path]) -> pathlib.Path:
    path = raw / "cppcheck.files.txt"
    path.write_text("\n".join(str(f) for f in files) + ("\n" if files else ""))
    return path


def write_cppcheck_shard_file_list(raw: pathlib.Path, output_no: int, files: list[pathlib.Path]) -> pathlib.Path:
    path = raw / f"cppcheck.part{output_no:04d}.files.txt"
    path.write_text("\n".join(str(f) for f in files) + ("\n" if files else ""))
    return path


def run_cppcheck_project(tool: dict, source: pathlib.Path, raw: pathlib.Path) -> tuple[dict, list[dict]]:
    name = tool["name"]
    binary = tool["binary"]
    scope, limitations = _load_cppcheck_scope(tool)
    final_output = raw / "cppcheck.out"
    command = expand_command(tool["command"], source, raw)
    if shutil.which(binary) is None:
        reason = "not-installed"
        blocking = is_blocking_tool(tool)
        if blocking:
            print(f"[PVAS-TOOL-MISSING] {name} not installed. Impact: {tool.get('evidence', '')}", file=sys.stderr)
            print(f"[PVAS-TOOL-MISSING] {name} is required ({tool.get('applicability', 'unknown')}). Blocking execution.", file=sys.stderr)
        row = {
            "name": name,
            "status": "blocked-recovery-required" if blocking else "not-installed",
            "output": "",
            "reason": reason,
            "notes": tool.get("evidence", ""),
            "strict_decision": "block" if blocking else "needs-install",
            "coverage_impact": tool.get("evidence", ""),
            "watchdog_events": [],
            "network_used": False,
            "result_count": 0,
            "shards_total": 0,
            "shards_completed": 0,
            "output_bytes": 0,
            "raw_output_ref": "",
            "terminal_summary_truncated": False,
            "partial_outputs": [],
            "file_list": "",
        }
        return apply_cppcheck_scope_metadata(row, tool, scope, limitations), [{
            "tool": name,
            "attempt": 1,
            "status": reason,
            "command": command,
            "elapsed_ms": 0,
            "exit_code": None,
            "recovery_action": "tool-install-assistant" if blocking else "record-missing",
            "watchdog_events": [],
            "network_used": False,
            "output_bytes": 0,
        }]

    env = expand_env(tool.get("env") or {}, source, raw)
    ensure_cppcheck_build_dirs(command)
    rc, elapsed_ms, events, reason = run_with_watchdog(command, env, final_output, tool)
    abnormal = reason in {"spawn-failed", "abnormal-timeout"}
    if reason == "stalled" and is_blocking_tool(tool):
        status, status_reason = "blocked-pending-confirmation", "stalled"
    elif abnormal:
        status, status_reason = "abnormal", reason
    elif rc == 0:
        result_count = cppcheck_diagnostic_count(final_output)
        status, status_reason = ("completed-with-findings", "") if result_count else ("completed", "")
    else:
        status, status_reason = "incomplete", "nonzero-exit"
    result_count = cppcheck_diagnostic_count(final_output) if final_output.exists() else 0
    status, status_reason, strict_decision = block_required_status(tool, status, status_reason)
    output_path = str(final_output) if final_output.exists() and status not in BLOCKING_STATUSES else ""
    coverage = "" if status in {"completed", "completed-with-findings", "not-applicable"} else tool.get("evidence", "")
    row = {
        "name": name,
        "status": status,
        "output": output_path,
        "reason": status_reason,
        "notes": tool.get("evidence", ""),
        "strict_decision": strict_decision,
        "coverage_impact": coverage,
        "watchdog_events": events,
        "network_used": False,
        "result_count": result_count,
        "shards_total": 1,
        "shards_completed": 1 if rc == 0 else 0,
        "output_bytes": output_size(final_output),
        "raw_output_ref": output_path,
        "terminal_summary_truncated": False,
        "partial_outputs": [str(final_output)] if final_output.exists() else [],
        "file_list": "",
    }
    attempt = {
        "tool": name,
        "attempt": 1,
        "status": status if status in BLOCKING_STATUSES else "completed" if rc == 0 else "abnormal" if abnormal else "incomplete",
        "command": command,
        "elapsed_ms": elapsed_ms,
        "exit_code": rc,
        "recovery_action": "none" if rc == 0 else "manual-review",
        "watchdog_events": events,
        "network_used": False,
        "output": str(final_output),
        "output_bytes": output_size(final_output),
    }
    return apply_cppcheck_scope_metadata(row, tool, scope, limitations), [attempt]


def run_cppcheck_shard(command: list[str], env: dict[str, str], output: pathlib.Path, tool: dict) -> tuple[int | None, int, list[dict], str]:
    watchdog = tool.get("watchdog") or {}
    idle_timeout = parse_duration(watchdog.get("idle_timeout") or tool.get("timeout"), 600.0)
    hard_limit_value = watchdog.get("hard_timeout") or tool.get("hard_timeout") or tool.get("hard_limit")
    hard_limit = parse_duration(hard_limit_value, 0.0) if hard_limit_value else 0.0
    watchdog_events: list[dict] = []
    start = time.monotonic()
    last_progress = start
    last_size = output_size(output)
    last_cpu = 0

    merged_env = os.environ.copy()
    merged_env.update(env)
    try:
        ensure_cppcheck_build_dirs(command)
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
                if hard_limit and now - start > hard_limit:
                    terminate_process(proc)
                    watchdog_events.append({
                        "event": "hard-limit",
                        "elapsed_ms": int((time.monotonic() - start) * 1000),
                        "output_bytes": current_size,
                    })
                    return None, int((time.monotonic() - start) * 1000), watchdog_events, "hard-limit"
                if now - last_progress > idle_timeout:
                    terminate_process(proc)
                    watchdog_events.append({
                        "event": "stalled",
                        "elapsed_ms": int((time.monotonic() - start) * 1000),
                        "output_bytes": current_size,
                        "diagnostic": "cppcheck shard made no observed CPU/output progress",
                    })
                    return None, int((time.monotonic() - start) * 1000), watchdog_events, "stalled"
                time.sleep(0.05)
    except OSError as e:
        watchdog_events.append({"event": "spawn-failed", "error": str(e)})
        return None, int((time.monotonic() - start) * 1000), watchdog_events, "spawn-failed"


def cppcheck_attempt_status(reason: str, rc: int | None) -> str:
    if reason == "stalled":
        return "blocked-pending-confirmation"
    if reason in {"spawn-failed", "hard-limit"}:
        return "abnormal"
    if rc == 0:
        return "completed"
    return "incomplete"


def run_cppcheck_sharded(tool: dict, source: pathlib.Path, raw: pathlib.Path, file_list: list[pathlib.Path] | None = None) -> tuple[dict, list[dict]]:
    name = tool["name"]
    binary = tool["binary"]
    files, scope, scope_limitations, compile_database = cppcheck_effective_files(tool, source, file_list)
    if compile_database and compile_database.exists():
        project_tool = dict(tool)
        project_tool["execution_mode"] = "project"
        project_tool["command"] = [
            part for part in tool["command"]
            if part != "<source>" and not str(part).startswith("--project=")
        ]
        project_tool["command"].append(f"--project={compile_database}")
        return run_cppcheck_project(project_tool, source, raw)
    file_list_path = write_cppcheck_file_list(raw, files)
    final_output = raw / "cppcheck.out"
    if final_output.exists():
        final_output.unlink()

    command_for_missing = expand_cppcheck_command_for_file_list(tool["command"], source, raw, file_list_path)
    if shutil.which(binary) is None:
        reason = "not-installed"
        blocking = is_blocking_tool(tool)
        if blocking:
            print(f"[PVAS-TOOL-MISSING] {name} not installed. Impact: {tool.get('evidence', '')}", file=sys.stderr)
            print(f"[PVAS-TOOL-MISSING] {name} is required ({tool.get('applicability', 'unknown')}). Blocking execution.", file=sys.stderr)
        row = {
            "name": name,
            "status": "blocked-recovery-required" if blocking else "not-installed",
            "output": "",
            "reason": reason,
            "notes": tool.get("evidence", ""),
            "strict_decision": "block" if blocking else "needs-install",
            "coverage_impact": tool.get("evidence", ""),
            "watchdog_events": [],
            "network_used": False,
            "result_count": 0,
            "shards_total": 0,
            "shards_completed": 0,
            "output_bytes": 0,
            "raw_output_ref": "",
            "terminal_summary_truncated": False,
            "partial_outputs": [],
            "file_list": str(file_list_path),
        }
        return apply_cppcheck_scope_metadata(row, tool, scope, scope_limitations), [{
            "tool": name,
            "attempt": 1,
            "status": reason,
            "command": command_for_missing,
            "elapsed_ms": 0,
            "exit_code": None,
            "recovery_action": "tool-install-assistant" if blocking else "record-missing",
            "watchdog_events": [],
            "network_used": False,
            "output_bytes": 0,
        }]

    if not files:
        row = {
            "name": name,
            "status": "not-applicable",
            "output": "",
            "reason": "no-cppcheck-source-files",
            "notes": tool.get("evidence", ""),
            "strict_decision": "continue",
            "coverage_impact": "none",
            "watchdog_events": [],
            "network_used": False,
            "result_count": 0,
            "shards_total": 0,
            "shards_completed": 0,
            "output_bytes": 0,
            "raw_output_ref": "",
            "terminal_summary_truncated": False,
            "partial_outputs": [],
            "file_list": str(file_list_path),
        }
        return apply_cppcheck_scope_metadata(row, tool, scope, scope_limitations), []

    try:
        shard_size = max(int(tool.get("shard_size") or DEFAULT_CPPCHECK_SHARD_SIZE), 1)
    except (TypeError, ValueError):
        shard_size = DEFAULT_CPPCHECK_SHARD_SIZE
    initial_shards = chunks(files, shard_size)
    env = expand_env(tool.get("env") or {}, source, raw)
    attempts: list[dict] = []
    partial_outputs: list[pathlib.Path] = []
    completed_outputs: list[pathlib.Path] = []
    watchdog_events: list[dict] = []
    attempt_no = 0
    output_no = 0
    try:
        stalled_retries = max(int(tool.get("stalled_retry_attempts", 1)), 0)
    except (TypeError, ValueError):
        stalled_retries = 1
    effective_shards = len(initial_shards)

    def execute_scope(scope_files: list[pathlib.Path], shard_index: int | str, shard_total: int) -> tuple[bool, str]:
        nonlocal attempt_no, output_no, effective_shards
        for stalled_try in range(stalled_retries + 1):
            attempt_no += 1
            output_no += 1
            part_output = raw / f"cppcheck.part{output_no:04d}.out"
            shard_file_list = write_cppcheck_shard_file_list(raw, output_no, scope_files)
            partial_outputs.append(part_output)
            command = expand_cppcheck_command_for_file_list(tool["command"], source, raw, shard_file_list)
            rc, elapsed_ms, events, reason = run_cppcheck_shard(command, env, part_output, tool)
            watchdog_events.extend(events)
            if rc == 0:
                attempts.append({
                    "tool": name,
                    "attempt": attempt_no,
                    "status": "completed",
                    "command": command,
                    "elapsed_ms": elapsed_ms,
                    "exit_code": rc,
                    "recovery_action": "none",
                    "watchdog_events": events,
                    "network_used": False,
                    "shard_index": shard_index,
                    "shard_total": shard_total,
                    "shard_file_count": len(scope_files),
                    "file_list": str(shard_file_list),
                    "output": str(part_output),
                    "output_bytes": output_size(part_output),
                })
                completed_outputs.append(part_output)
                return True, ""

            if reason == "stalled":
                if stalled_try < stalled_retries:
                    recovery_action = "retry"
                elif len(scope_files) > 1:
                    recovery_action = "split-scope"
                else:
                    recovery_action = "manual-confirmation"
                attempts.append({
                    "tool": name,
                    "attempt": attempt_no,
                    "status": "blocked-pending-confirmation",
                    "command": command,
                    "elapsed_ms": elapsed_ms,
                    "exit_code": rc,
                    "recovery_action": recovery_action,
                    "watchdog_events": events,
                    "network_used": False,
                    "shard_index": shard_index,
                    "shard_total": shard_total,
                    "shard_file_count": len(scope_files),
                    "file_list": str(shard_file_list),
                    "output": str(part_output),
                    "output_bytes": output_size(part_output),
                })
                if recovery_action == "retry":
                    continue
                if recovery_action == "split-scope":
                    midpoint = max(len(scope_files) // 2, 1)
                    left = scope_files[:midpoint]
                    right = scope_files[midpoint:]
                    child_total = 2 if right else 1
                    if right:
                        effective_shards += 1
                    ok, child_reason = execute_scope(left, f"{shard_index}.1", child_total)
                    if not ok:
                        return False, child_reason
                    if right:
                        ok, child_reason = execute_scope(right, f"{shard_index}.2", child_total)
                        if not ok:
                            return False, child_reason
                    return True, ""
                return False, "stalled"

            attempts.append({
                "tool": name,
                "attempt": attempt_no,
                "status": cppcheck_attempt_status(reason, rc),
                "command": command,
                "elapsed_ms": elapsed_ms,
                "exit_code": rc,
                "recovery_action": "manual-review",
                "watchdog_events": events,
                "network_used": False,
                "shard_index": shard_index,
                "shard_total": shard_total,
                "shard_file_count": len(scope_files),
                "file_list": str(shard_file_list),
                "output": str(part_output),
                "output_bytes": output_size(part_output),
            })
            if reason == "hard-limit":
                return False, "hard-limit"
            if reason == "spawn-failed":
                return False, "spawn-failed"
            return False, "nonzero-exit"
        return False, "stalled"

    blocked_reason = ""
    for idx, shard_files in enumerate(initial_shards, start=1):
        ok, blocked_reason = execute_scope(shard_files, idx, len(initial_shards))
        if not ok:
            break

    if not blocked_reason or completed_outputs:
        with final_output.open("w") as dest:
            for part in completed_outputs:
                if part.exists():
                    text = part.read_text(errors="ignore")
                    if text:
                        dest.write(text)
                        if not text.endswith("\n"):
                            dest.write("\n")
        result_count = cppcheck_diagnostic_count(final_output)
        if blocked_reason:
            status = "incomplete"
            reason = "partial-timeout" if blocked_reason == "stalled" else blocked_reason
        else:
            status = "completed-with-findings" if result_count else "completed"
            reason = ""
    else:
        result_count = 0
        status = "blocked-pending-confirmation" if blocked_reason == "stalled" else "blocked-recovery-required"
        reason = blocked_reason

    if reason == "partial-timeout" and tool.get("degraded_continuation_allowed"):
        status, reason, strict_decision = "incomplete", reason, "continue-needs-manual-review"
    else:
        status, reason, strict_decision = block_required_status(tool, status, reason)
    output_path = str(final_output) if not blocked_reason else ""
    if reason == "partial-timeout" and final_output.exists():
        output_path = str(final_output)
    total_shards = effective_shards
    output_paths = [str(path) for path in partial_outputs]
    if reason == "partial-timeout":
        coverage = {
            "impact": tool.get("evidence", ""),
            "limitation": "partial cppcheck coverage",
            "completed_shards": len(completed_outputs),
            "total_shards": total_shards,
        }
    else:
        coverage = "" if status in {"completed", "completed-with-findings", "not-applicable"} else tool.get("evidence", "")
    row = {
        "name": name,
        "status": status,
        "output": output_path,
        "reason": reason,
        "notes": tool.get("evidence", ""),
        "strict_decision": strict_decision,
        "coverage_impact": coverage,
        "watchdog_events": watchdog_events,
        "network_used": False,
        "result_count": result_count,
        "shards_total": total_shards,
        "shards_completed": len(completed_outputs),
        "output_bytes": output_size(final_output) if final_output.exists() else cppcheck_output_bytes(partial_outputs),
        "raw_output_ref": output_path,
        "terminal_summary_truncated": False,
        "partial_outputs": output_paths,
        "file_list": str(file_list_path),
    }
    return apply_cppcheck_scope_metadata(row, tool, scope, scope_limitations), attempts


def _load_file_list(path: str) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    p = pathlib.Path(path)
    if not p.exists():
        return files
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            fp = pathlib.Path(line)
            if fp.exists():
                files.append(fp)
    return files


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--file-list", default=None,
                    help="Path to text file listing source files to scan (one per line). "
                         "When provided, replaces <source> with these files instead of the full source root.")
    args = ap.parse_args()

    matrix_path = pathlib.Path(args.matrix)
    source = pathlib.Path(args.source)
    out = pathlib.Path(args.out)
    file_list: list[pathlib.Path] | None = None
    if args.file_list:
        file_list = _load_file_list(args.file_list)
        if file_list:
            print(f"[PVAS-TOOL-MATRIX] scope-limited scan: {len(file_list)} file(s) from {args.file_list}")
        else:
            print(f"[PVAS-TOOL-MATRIX] --file-list {args.file_list} provided but no readable files found; using full source root")
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
    blocked = []
    incomplete = []
    for tool in matrix.get("tools", []):
        row, tool_attempts = run_one(tool, source, raw, file_list=file_list)
        row.update(cppcheck_summary_metadata(tool))
        row = annotate_summary_row(row)
        print_tool_status(row)
        rows.append(row)
        attempts.extend(tool_attempts)
        if row["status"] in BLOCKING_STATUSES or row.get("strict_decision") == "block":
            blocked.append(row["name"])
        if row["status"] in ABNORMAL_STATUSES:
            abnormal.append(row["name"])
        elif row["status"] in {"incomplete", "not-installed"}:
            incomplete.append(row["name"])

    strict_decision = "block" if (abnormal or blocked) else "continue"
    errors = [f"{name}: abnormal" for name in abnormal] + [f"{name}: blocked" for name in blocked if name not in abnormal]
    summary = {
        "tools": rows,
        "raw_outputs": [r["output"] for r in rows if r.get("output")],
        "summary": "Tool execution completed." if not errors else "Tool execution blocked: " + ", ".join(errors),
        "normalized_candidate_count": 0,
        "errors": errors,
        "strict_decision": strict_decision,
        "blocked_tools": blocked,
        "coverage_impact": [r for r in rows if r.get("coverage_impact")],
        "incomplete_tools": incomplete,
    }
    write_json(out / "tool-summary.json", summary)
    write_json(out / "tool-execution-attempts.json", {"attempts": attempts})
    missing_blocking = [r["name"] for r in rows if r.get("reason") == "not-installed" and r.get("strict_decision") == "block"]
    if missing_blocking:
        print(f"[PVAS-TOOL-MISSING] blocking due to missing required tools: {', '.join(missing_blocking)}", file=sys.stderr)
        print("[PVAS-TOOL-MISSING] run controlled install-assistant or ensure tools are installed before retry", file=sys.stderr)
    return 2 if (abnormal or blocked) else 0


if __name__ == "__main__":
    raise SystemExit(main())
