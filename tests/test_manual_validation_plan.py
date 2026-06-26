#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_manual_validation_plan_generated_for_needs_manual_review():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        findings = td / "findings.json"
        findings.write_text(json.dumps({"findings": [{
            "id": "MANUAL-001",
            "status": "Needs Manual Review",
            "title": "possible parser issue",
            "summary": "manual validation required for parser issue",
            "affected_component": {"package": "demo", "component": "parser"},
            "source_code_evidence": [{"file": "src/parser.c", "function": "parse", "start_line": 10, "end_line": 40}],
            "source_to_sink_path": "input -> parse -> memcpy",
            "manual_review": {
                "blocked_reason": "target requires unavailable corpus",
                "suggested_test_method": "build parser and run malformed length-field input",
                "expected_observable_signal": "ASan heap-buffer-overflow or graceful rejection after fix",
            },
            "disclosure_level": "D1-internal-likely",
            "discovery_method": [{"type": "ai", "hypothesis_id": "A-CAND-1", "description": "slice review"}],
            "disclosure_status": "unknown",
        }]}))
        out = td / "manual-review"
        subprocess.check_call([
            sys.executable,
            str(ROOT / "tools" / "generate_manual_validation_plan.py"),
            "--findings",
            str(findings),
            "--out",
            str(out),
        ])
        plan_json = out / "MANUAL-001" / "manual-validation-plan.json"
        plan_md = out / "MANUAL-001" / "manual-validation-plan.md"
        data = json.loads(plan_json.read_text())
        text = plan_md.read_text()
        assert data["id"] == "MANUAL-001"
        assert data["status"] == "Needs Manual Review"
        assert "target requires unavailable corpus" in data["blocked_reason"]
        assert "人工验证计划" in text
        assert "ASan heap-buffer-overflow" in text


if __name__ == "__main__":
    test_manual_validation_plan_generated_for_needs_manual_review()
    print("manual validation plan tests passed")
