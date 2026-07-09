#!/usr/bin/env python3
"""Normalize raw tool outputs to SKILL's candidate.json schema.

Reads raw outputs from:
  - audit-output/02-tools/raw/cppcheck-shards/cppcheck-shard-*.out
  - audit-output/02-tools/raw/semgrep.json
  - audit-output/02-tools/raw/osv/osv-scanner.json

Writes:
  - audit-output/03-candidates/raw-candidates.json (unified candidate format)

Each candidate has the fields required by schemas/candidate.schema.json:
  - id, type (T-CAND/A-CAND/F-CAND), status, title, component
  - profile, source_locations, evidence, confidence
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import defaultdict
from typing import Iterable

TOOLS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import pvas_container  # noqa: E402  (for AuditContext, available if used)

# Module-level state for log_path resolution
_args_root = pathlib.Path.cwd()

# Map cppcheck severity to candidate severity
CPPCHECK_SEV_MAP = {
    "error": "high",
    "warning": "medium",
    "style": "low",
    "performance": "low",
    "portability": "low",
    "information": "low",
}

# Map cppcheck category to "high signal" filter
HIGH_SIGNAL_CPPCHECK = {
    "arrayIndexOutOfBounds", "arrayIndexOutOfBoundsCond",
    "nullPointer", "nullPointerOutOfMemory", "nullPointerRedundantCheck",
    "nullPointerArithmeticRedundantCheck",
    "memleak", "invalidLifetime", "returnDanglingLifetime",
    "uninitvar", "autoVariables", "ignoredReturnValue",
    "accessMoved", "missingReturn", "uninitStructMember",
    "leakReturnValNotUsed", "autovarInvalidDeallocation",
}


def parse_cppcheck_shards(raw_dir: pathlib.Path) -> Iterable[dict]:
    """Parse cppcheck GCC-template output into candidate dicts."""
    for shard in sorted(raw_dir.glob("cppcheck-shard-*.out")):
        with shard.open() as f:
            for line in f:
                line = line.rstrip()
                # GCC template: file:line:col: severity: message [id]
                m = re.match(
                    r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+):\s*"
                    r"(?P<sev>error|warning|style|performance|portability|information):\s*"
                    r"(?P<msg>.*?)(?:\s*\[(?P<id>[^\]]+)\])?\s*$",
                    line,
                )
                if not m:
                    continue
                cid = m.group("id")
                if not cid or cid not in HIGH_SIGNAL_CPPCHECK:
                    continue
                yield {
                    "type": "T-CAND",
                    "status": "Raw Tool Hit",
                    "title": f"cppcheck: {cid} at {m.group('file')}:{m.group('line')}",
                    "component": m.group("file").split("/")[0],
                    "source_locations": [{
                        "file": m.group("file"),
                        "function": "",
                        "start_line": int(m.group("line")),
                        "end_line": int(m.group("line")),
                    }],
                    "evidence": {
                        "tool": "cppcheck",
                        "severity": CPPCHECK_SEV_MAP.get(m.group("sev"), "medium"),
                        "category": cid,
                        "message": m.group("msg"),
                        "log_path": str(shard.resolve().relative_to(_args_root.resolve())),
                    },
                    "confidence": "medium",
                    "provisional_severity": "low",
                }


def parse_semgrep(raw_path: pathlib.Path) -> Iterable[dict]:
    """Parse semgrep JSON output into candidate dicts."""
    if not raw_path.is_file():
        return
    data = json.loads(raw_path.read_text())
    for i, r in enumerate(data.get("results", []), 1):
        check_id = r.get("check_id", "")
        # Skip generic dangerous-sprintf rules (too noisy)
        if "dangerous-sprintf" in check_id:
            continue
        path = r.get("path", "")
        line = r.get("start", {}).get("line", 0)
        yield {
            "type": "T-CAND",
            "status": "Raw Tool Hit",
            "title": f"semgrep: {check_id.split('.')[-1]} at {path}:{line}",
            "component": path.split("/")[0] if path else "unknown",
            "source_locations": [{
                "file": path,
                "function": "",
                "start_line": line,
                "end_line": r.get("end", {}).get("line", line),
            }],
            "evidence": {
                "tool": "semgrep",
                "severity": r.get("extra", {}).get("severity", "WARNING"),
                "category": check_id.split(".")[-1],
                "message": r.get("extra", {}).get("message", ""),
                "log_path": str(raw_path),
            },
            "confidence": "medium",
            "provisional_severity": "low",
        }


def parse_osv(raw_path: pathlib.Path) -> Iterable[dict]:
    """Parse osv-scanner JSON output. These are NOT vulnerabilities in the package
    itself; they are known-CVE matches in vendored dependencies. We don't emit
    them as T-CAND; they are recorded separately as F-CAND-style advisories."""
    if not raw_path.is_file():
        return
    data = json.loads(raw_path.read_text())
    for r in data.get("results", []):
        for p in r.get("packages", []):
            cves = []
            for g in p.get("groups", []):
                cves.extend([a for a in g.get("aliases", []) if a.startswith("CVE")])
            if not cves:
                continue
            yield {
                "type": "F-CAND",
                "status": "Raw Tool Hit",
                "title": f"osv-scanner: {len(cves)} CVEs in {p['package']['name']}@{p['package']['version']}",
                "component": "vendored-deps",
                "source_locations": [{
                    "file": r.get("source", {}).get("path", ""),
                    "function": "",
                    "start_line": 0,
                    "end_line": 0,
                }],
                "evidence": {
                    "tool": "osv-scanner",
                    "severity": "info",
                    "category": "known-vulnerability",
                    "message": f"Known CVEs: {','.join(cves[:10])}",
                    "log_path": str(raw_path),
                },
                "confidence": "high",
                "provisional_severity": "info",
            }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-output", default="audit-output")
    args = parser.parse_args()

    audit_out = pathlib.Path(args.audit_output)
    raw_dir = audit_out / "02-tools" / "raw"
    out_path = audit_out / "03-candidates" / "raw-candidates.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Save args_root for nested use

    candidates = []
    cppcheck_count = 0
    for c in parse_cppcheck_shards(raw_dir / "cppcheck-shards"):
        c["id"] = f"T-CAND-{len(candidates)+1:03d}"
        candidates.append(c)
        cppcheck_count += 1

    semgrep_count = 0
    for c in parse_semgrep(raw_dir / "semgrep.json"):
        c["id"] = f"T-CAND-S{len(candidates)+1:03d}"
        candidates.append(c)
        semgrep_count += 1

    osv_count = 0
    for c in parse_osv(raw_dir / "osv" / "osv-scanner.json"):
        c["id"] = f"F-CAND-{len(candidates)+1:03d}"
        candidates.append(c)
        osv_count += 1

    out = {
        "schema_version": "1.0",
        "step_id": "04-ai-hypothesis",
        "audit_id": "gcc-12.3.0-strict-20260708",
        "candidates": candidates,
        "summary": {
            "total_candidates": len(candidates),
            "from_cppcheck": cppcheck_count,
            "from_semgrep": semgrep_count,
            "from_osv_scanner": osv_count,
        },
    }
    with out_path.open("w") as f:
        json.dump(out, f, indent=2)
    print(f"[normalize-results] wrote {len(candidates)} candidates to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())