#!/usr/bin/env python3
"""Validate that reportable findings carry real validation evidence."""
from __future__ import annotations

import argparse
import pathlib
import sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_findings, write_json

EVIDENCE_KEYS = {
    "method",
    "command",
    "testcase",
    "evidence",
    "result",
    "expected_vulnerable",
    "expected_fixed",
    "static_refutation",
    "sanitizer_output",
}


def finding_errors(finding: dict) -> list[str]:
    fid = finding.get("id", "?")
    status = finding.get("status")
    errors: list[str] = []
    validation = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
    if status == "Validated":
        populated = [k for k in EVIDENCE_KEYS if validation.get(k)]
        if len(populated) < 2:
            errors.append(f"{fid}: Validated finding requires validation evidence with at least two populated evidence fields")
        if not finding.get("false_positive_exclusion"):
            errors.append(f"{fid}: Validated finding requires false_positive_exclusion")
    if status == "Needs Manual Review":
        manual = finding.get("manual_review") if isinstance(finding.get("manual_review"), dict) else {}
        if not manual.get("blocked_reason") and not finding.get("manual_review_reason"):
            errors.append(f"{fid}: Needs Manual Review requires blocked_reason or manual_review_reason")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()

    findings = load_findings(pathlib.Path(args.findings))
    errors: list[str] = []
    for finding in findings:
        errors.extend(finding_errors(finding))
    result = {"passed": not errors, "errors": errors, "finding_count": len(findings)}
    if args.out:
        write_json(args.out, result)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"[PVAS-VALIDATION] validated evidence for {len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
