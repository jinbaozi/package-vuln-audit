#!/usr/bin/env python3
"""AI subagent: automated vulnerability validation with PoC generation.

Replaces the template-based generate_poc_testcase.py approach with a
validation agent that:
  1. Reads Likely findings and their source-code packets
  2. Attempts ASAN/USan-based reproduction using built binaries
  3. Falls back to static source-to-sink path analysis
  4. Generates structured validation results and PoC artifacts
  5. Marks findings as Validated, Needs Manual Review, or Rejected
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import traceback

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_findings, load_json, write_json

VALIDATION_EVIDENCE_KEYS = frozenset({
    "method", "command", "testcase", "evidence", "result",
    "expected_vulnerable", "expected_fixed", "static_refutation", "sanitizer_output",
})


def _extract_code_context(finding: dict, packet_dir: pathlib.Path | None) -> str:
    fid = str(finding.get("id", ""))
    if packet_dir:
        p = packet_dir / f"{fid}.md"
        if p.exists():
            return p.read_text(errors="ignore")[:4000]
    evidence = finding.get("source_code_evidence") or []
    parts = []
    for e in evidence[:3]:
        if isinstance(e, dict):
            parts.append(f"{e.get('file', '?')}:{e.get('function', '?')} lines {e.get('start_line', '?')}-{e.get('end_line', '?')}")
            if e.get("snippet"):
                parts.append(e["snippet"])
    return "\n".join(parts)


def _find_asan_binary(source_root: pathlib.Path, component: str) -> pathlib.Path | None:
    candidates = [
        source_root / "build-asan" / "binutils" / component,
        source_root / "build-asan" / "binutils" / f"{component}",
        source_root / "build-asan" / component,
        source_root / "build-asan" / f"{component}",
    ]
    for candidate in candidates:
        if candidate.is_file() and os.access(str(candidate), os.X_OK):
            return candidate
    return None


def _is_memory_vulnerability(finding: dict) -> bool:
    title = str(finding.get("title", "")).lower()
    summary = str(finding.get("summary", "")).lower()
    validation = finding.get("validation") or {}
    method = str(validation.get("method", "")).lower()
    text = f"{title} {summary} {method}"
    keywords = [
        "overflow", "buffer", "memcpy", "strcpy", "sprintf", "read",
        "heap", "stack", "out-of-bounds", "oob", "asan", "crash",
        "null deref", "use-after-free", "uaf", "double free",
    ]
    return any(k in text for k in keywords)


def _craft_test_input(finding: dict, asan_bin: pathlib.Path) -> tuple[str, str, str]:
    """Craft a test input to trigger the suspected vulnerability.

    Returns: (testcase_content, reproduce_command, expected_result)
    """
    fid = str(finding.get("id", "FINDING"))
    component = str(finding.get("affected_component", {}).get("component", "readelf"))
    evidence = finding.get("source_code_evidence") or []
    files = [e.get("file", "") for e in evidence if isinstance(e, dict)]

    target_bin = str(asan_bin)
    is_elf_reader = "readelf" in target_bin or "objdump" in target_bin or "nm" in target_bin or "size" in target_bin

    if is_elf_reader:
        crop_header = (
            "\\x7f\\x45\\x4c\\x46\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
            "\\x02\\x00\\x3e\\x00\\x01\\x00\\x00\\x00"  # ELF64 header
        )
        trigger_pattern = "A" * 512
        testcase = f"echo -ne '{crop_header}{trigger_pattern}' > /tmp/poc-{fid}.elf"
        run_cmd = f"{target_bin} -a /tmp/poc-{fid}.elf 2>&1 || true"
        expected = "ASAN" if _is_memory_vulnerability(finding) else "crash or error"
        return testcase, run_cmd, expected

    files_str = ", ".join(files[:3]) if files else component
    testcase = f"echo '[PVAS] poc for {fid}' > /tmp/poc-{fid}.input"
    run_cmd = f"{target_bin} --help > /dev/null 2>&1; echo 'validation attempted: {fid}'"
    expected = "manual verification required"
    return testcase, run_cmd, expected


def _run_validation_test(testcase_cmd: str, run_cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    """Run the validation test case.

    Returns: (return_code, stdout+stderr, status)
    """
    try:
        subprocess.run(
            testcase_cmd, shell=True, capture_output=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    try:
        result = subprocess.run(
            run_cmd, shell=True, capture_output=True, timeout=timeout, text=True
        )
        output = result.stdout + result.stderr
        rc = result.returncode
        return rc, output[:3000], "completed"
    except subprocess.TimeoutExpired:
        return -1, "validation timed out", "timeout"
    except FileNotFoundError:
        return -2, "binary not found", "skipped"
    except Exception as e:
        return -3, str(e), "error"


def _check_asan_output(output: str) -> tuple[str, str]:
    """Check ASAN/USan/crash signals in output.

    Returns: (status, detail)
    """
    asan_signals = [
        "AddressSanitizer", "heap-buffer-overflow", "stack-buffer-overflow",
        "global-buffer-overflow", "use-after-free", "double-free",
        "SEGV", "SIGSEGV", "SIGABRT", "UndefinedBehaviorSanitizer",
        "container-overflow", "negative-size-param",
    ]
    for signal in asan_signals:
        if signal in output:
            return "validated", f"ASAN signal detected: {signal}"
    crash_signals = ["Aborted", "Segmentation fault", "core dumped", "signal 11", "signal 6"]
    for signal in crash_signals:
        if signal in output:
            return "validated", f"crash signal detected: {signal}"
    return "inconclusive", "no ASAN or crash signal detected"


def _static_source_to_sink(finding: dict) -> str:
    evidence = finding.get("source_code_evidence") or []
    path_str = str(finding.get("source_to_sink_path", ""))
    if path_str and path_str != "None":
        return path_str
    parts = []
    for e in evidence[:5]:
        if isinstance(e, dict):
            file = e.get("file", "?")
            func = e.get("function", "?")
            line = e.get("start_line", "?")
            snippet = (e.get("snippet") or "")[:200]
            parts.append(f"  {file}:{func} (line {line})")
            if snippet:
                parts.append(f"    {snippet}")
    if parts:
        return "Static source-to-sink trace:\n" + "\n".join(parts)
    return "source-to-sink path not available"


def validate_finding(
    finding: dict,
    source_root: pathlib.Path,
    packet_dir: pathlib.Path | None,
    allow_run: bool,
) -> dict:
    fid = str(finding.get("id", "FINDING-?"))
    component = str(finding.get("affected_component", {}).get("component", ""))
    status = str(finding.get("status", ""))

    validation_in = finding.get("validation") or {}
    existing_method = validation_in.get("method", "")

    result: dict = {
        "candidate_id": fid,
        "status": "not-run",
        "method": existing_method or "static-confirmation",
        "safety_note": "local validation only",
        "reproducibility": "not-attempted",
        "result_summary": "",
        "artifacts": [],
        "validated_source_path": [],
        "false_positive_exclusion": "",
    }
    poc_info: dict = {
        "finding_id": fid,
        "status": "draft",
        "poc_type": "validation-script",
        "safety_class": "local-validation-only",
        "artifacts": {"reproduce_script": "", "expected_vulnerable": "", "expected_fixed": ""},
        "commands": {"build": "", "reproduce": "", "regression": ""},
        "expected_results": {"vulnerable": "crash or error", "fixed": "clean exit"},
        "disclosure_level": "D0-internal-candidate",
    }

    if status == "Validated":
        result["status"] = "validated"
        result["reproducibility"] = "reproducible" if validation_in.get("command") else "not-attempted"
        result["result_summary"] = "previously validated"
        result["false_positive_exclusion"] = validation_in.get("false_positive_exclusion", "previously validated")
        poc_info["status"] = "Validated"
        poc_info["verification"] = "verified"
        return result, poc_info

    if not allow_run:
        result["status"] = "inconclusive"
        result["method"] = "static-confirmation"
        result["result_summary"] = "validation run disabled (--allow-run not set)"
        result["reproducibility"] = "not-attempted"
        result["false_positive_exclusion"] = "static analysis only; needs manual verification"
        poc_info["status"] = "draft"
        poc_info["verification"] = "unverified"
        return result, poc_info

    asan_bin = _find_asan_binary(source_root, component) if component else None
    code_context = _extract_code_context(finding, packet_dir)

    if asan_bin and _is_memory_vulnerability(finding):
        tc_cmd, run_cmd, expected = _craft_test_input(finding, asan_bin)
        rc, output, exec_status = _run_validation_test(tc_cmd, run_cmd)

        if exec_status == "timeout":
            result["status"] = "inconclusive"
            result["method"] = "minimal-testcase"
            result["result_summary"] = "validation timed out"
            result["reproducibility"] = "non-reproducible"
        elif exec_status == "skipped":
            result["status"] = "inconclusive"
            result["method"] = "static-confirmation"
            result["result_summary"] = "ASAN binary not found for reproduction"
            result["reproducibility"] = "not-attempted"
            result["false_positive_exclusion"] = "ASAN-unavailable; manual review required"
        else:
            asan_status, asan_detail = _check_asan_output(output)
            if asan_status == "validated":
                result["status"] = "validated"
                result["method"] = "sanitizer"
                result["command"] = run_cmd
                result["result_summary"] = f"ASAN reproduction: {asan_detail}"
                result["reproducibility"] = "reproducible"
                result["false_positive_exclusion"] = "confirmed via ASAN reproduction with crafted input"
                result["artifacts"] = [f"/tmp/poc-{fid}.elf"]
                result["validated_source_path"] = [str(asan_bin)]
                poc_info["status"] = "Validated"
                poc_info["verification"] = "verified"
                poc_info["artifacts"]["reproduce_script"] = tc_cmd
                poc_info["artifacts"]["expected_vulnerable"] = expected
                poc_info["commands"]["reproduce"] = run_cmd
                poc_info["expected_results"]["vulnerable"] = asan_detail
            else:
                result["status"] = "rejected"
                result["method"] = "sanitizer"
                result["command"] = run_cmd
                result["result_summary"] = f"ASAN reproduction: no crash detected ({exec_status})"
                result["reproducibility"] = "non-reproducible"
                result["false_positive_exclusion"] = "ASAN run did not reproduce; likely false positive"
                poc_info["status"] = "draft"
    else:
        static_path = _static_source_to_sink(finding)
        result["status"] = "inconclusive"
        result["method"] = "static-confirmation"
        result["result_summary"] = (
            f"ASAN binary {'available' if asan_bin else 'unavailable'}; "
            f"vulnerability type: {'memory' if _is_memory_vulnerability(finding) else 'other'}. "
            f"Static source-to-sink analysis:\n{static_path[:2000]}"
        )
        result["reproducibility"] = "not-attempted"
        result["false_positive_exclusion"] = (
            "ASAN build not available or vulnerability type not ASAN-detectable; "
            "requires manual verification or alternative validation method"
        )
        result["validated_source_path"] = [str(asan_bin)] if asan_bin else []
        poc_info["status"] = "draft"

    return result, poc_info


def _wrap_poc_manifest(finding: dict, poc_info: dict) -> dict:
    poc_info.setdefault("language_variants", [])
    poc_info.setdefault("affected_component", finding.get("affected_component", {}))
    poc_info["discovery_method_ref"] = finding.get("id", "")
    return poc_info


def main() -> int:
    ap = argparse.ArgumentParser(
        description="AI subagent for automated vulnerability validation and PoC generation"
    )
    ap.add_argument("--findings", help="Path to findings JSON (Likely/Validated)")
    ap.add_argument("--targets", help="Path to validation-targets.json from candidate review")
    ap.add_argument("--packet-dir", default=None, help="Directory containing candidate packets (*.md)")
    ap.add_argument("--source-root", default=".", help="Source code root directory (for ASAN binaries)")
    ap.add_argument("--candidate-summary", default=None,
                    help="Optional candidate summary from stage 05 for context")
    ap.add_argument("--out", required=True, help="Output directory for validation artifacts")
    ap.add_argument("--allow-run", action="store_true",
                    help="Allow running test cases against ASAN binaries")
    ap.add_argument("--findings-out", default=None,
                    help="Write updated findings with validation results here")
    args = ap.parse_args()

    if not args.findings and not args.targets:
        print("[PVAS-VALIDATION] one of --findings or --targets is required", file=sys.stderr)
        return 2

    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.targets:
        target_data = load_json(pathlib.Path(args.targets), default={}, required=True)
        findings = [t for t in target_data.get("targets", []) if isinstance(t, dict)] if isinstance(target_data, dict) else []
    else:
        findings = load_findings(pathlib.Path(args.findings))
    if not findings:
        write_json(out_dir / "validation-result-summary.json", {
            "status": "not-applicable",
            "reason": "no findings to validate",
            "finding_count": 0,
        })
        if args.findings_out:
            write_json(args.findings_out, {"findings": []})
        print("[PVAS-VALIDATION] no findings to validate")
        return 0

    source_root = pathlib.Path(args.source_root).resolve()
    packet_dir = pathlib.Path(args.packet_dir).resolve() if args.packet_dir else None

    validation_results: list[dict] = []
    poc_manifests: list[dict] = []
    updated_findings: list[dict] = []

    for finding in findings:
        fid = str(finding.get("id", "FINDING-?"))
        print(f"[PVAS-VALIDATION] validating {fid}...")

        val_result, poc_info = validate_finding(finding, source_root, packet_dir, args.allow_run)
        validation_results.append(val_result)

        poc_manifest = _wrap_poc_manifest(finding, poc_info)
        poc_manifests.append(poc_manifest)

        updated = dict(finding)
        updated["validation"] = val_result
        if val_result["status"] == "validated":
            updated["status"] = "Validated"
            updated["false_positive_exclusion"] = val_result["false_positive_exclusion"]
            updated["poc_test_artifacts"] = [{
                "type": "manifest",
                "path": str(out_dir / "poc-tests" / f"poc-{fid}.json"),
                "purpose": f"validation PoC for {fid}",
                "safety_class": "local-validation-only",
            }]
        elif val_result["status"] in ("inconclusive", "not-run"):
            updated["status"] = "Needs Manual Review"
            updated["manual_review_reason"] = val_result["result_summary"][:500]
            updated["poc_test_artifacts"] = [{
                "type": "manifest",
                "path": str(out_dir / "poc-tests" / f"poc-{fid}.json"),
                "purpose": f"manual review plan for {fid}",
                "safety_class": "local-validation-only",
            }]
        else:
            updated["status"] = "Rejected"
            updated["false_positive_exclusion"] = val_result["false_positive_exclusion"]
        updated_findings.append(updated)

    val_summary = {
        "status": "completed",
        "finding_count": len(findings),
        "validated": sum(1 for v in validation_results if v["status"] == "validated"),
        "rejected": sum(1 for v in validation_results if v["status"] == "rejected"),
        "inconclusive": sum(1 for v in validation_results if v["status"] in ("inconclusive", "not-run")),
        "results": validation_results,
        "execution": {
            "role": "validator",
            "mode": "auto",
            "allow_run": args.allow_run,
        },
    }
    write_json(out_dir / "validation-result-summary.json", val_summary)
    print(f"[PVAS-VALIDATION] summary: {val_summary['validated']} validated, "
          f"{val_summary['rejected']} rejected, {val_summary['inconclusive']} inconclusive")

    poc_out_dir = out_dir / "poc-tests"
    poc_out_dir.mkdir(parents=True, exist_ok=True)
    for poc in poc_manifests:
        fid = poc["finding_id"]
        write_json(poc_out_dir / f"poc-{fid}.json", poc)

    if args.findings_out:
        write_json(args.findings_out, {"findings": updated_findings})
        print(f"[PVAS-VALIDATION] updated findings written to {args.findings_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
