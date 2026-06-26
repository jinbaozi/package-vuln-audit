#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def finding(status="Validated"):
    base = {
        "id": "FINDING-001" if status == "Validated" else "MANUAL-001",
        "status": status,
        "title": "parser issue",
        "summary": "parser issue summary",
        "affected_component": {"package": "demo", "component": "parser"},
        "source_code_evidence": [{"file": "src/parser.c", "function": "parse", "start_line": 1, "end_line": 20}],
        "source_to_sink_path": "input -> parse -> memcpy",
        "validation": {"evidence": "local"},
        "cvss": {"vector": "CVSS:4.0/AV:L", "base_score": 6.0, "severity": "Medium"},
        "fix_recommendation": "add bounds check",
        "disclosure_level": "D2-internal-validated",
        "discovery_method": [{"type": "tool", "tool_name": "semgrep", "description": "fixture"}],
        "disclosure_status": "not_found_in_configured_sources",
    }
    if status == "Needs Manual Review":
        base["validation"] = {}
        base["cvss"] = {}
        base["manual_review"] = {"blocked_reason": "needs corpus"}
    return base


def test_report_completeness_requires_manual_plan():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        findings = td / "findings.json"
        corr = td / "corr.json"
        out = td / "audit-output"
        findings.write_text(json.dumps({"findings": [finding("Needs Manual Review")]}))
        corr.write_text(json.dumps({"correlations": []}))
        (out / "zh-CN/05-内部安全报告").mkdir(parents=True)
        (out / "en-US/05-internal-security-report").mkdir(parents=True)
        (out / "zh-CN/05-内部安全报告/internal-security-report.md").write_text("公开披露状态与标准来源汇总表\n| A | B |\n|---|---|\n")
        (out / "en-US/05-internal-security-report/internal-security-report.md").write_text("Public Disclosure Status and Standard Source Summary\n| A | B |\n|---|---|\n")
        p = subprocess.run([
            sys.executable,
            str(ROOT / "tools" / "validate_report_completeness.py"),
            "--findings",
            str(findings),
            "--correlation",
            str(corr),
            "--report-root",
            str(out),
            "--manual-root",
            str(out / "04-validation/manual-review"),
            "--out",
            str(out / "machine/report-completeness.json"),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 1
        result = json.loads((out / "machine/report-completeness.json").read_text())
        assert any("manual validation plan" in e for e in result["errors"])


def test_final_summary_is_chinese_and_lists_manual_review():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        audit = td / "audit-output"
        (audit / "00-environment").mkdir(parents=True)
        (audit / "01-profile").mkdir(parents=True)
        (audit / "02-tools").mkdir(parents=True)
        (audit / "04-validation/manual-review/MANUAL-001").mkdir(parents=True)
        (audit / "00-environment/environment-check.json").write_text(json.dumps({"tools": [], "decision": "continue"}))
        (audit / "01-profile/package-profile.json").write_text(json.dumps({"package_name": "demo", "primary_language": ["C/C++"]}))
        (audit / "01-profile/required-tools-matrix.json").write_text(json.dumps({"tools": [{"name": "semgrep", "final_status": "completed"}]}))
        (audit / "02-tools/tool-summary.json").write_text(json.dumps({"tools": [{"name": "semgrep", "status": "completed"}]}))
        (audit / "04-validation/manual-review/MANUAL-001/manual-validation-plan.md").write_text("# 人工验证计划：MANUAL-001\n")
        findings = td / "findings.json"
        findings.write_text(json.dumps({"findings": [finding("Needs Manual Review")]}))
        out = audit / "06-report"
        subprocess.check_call([
            sys.executable,
            str(ROOT / "tools" / "generate_final_report.py"),
            "--audit-root",
            str(audit),
            "--findings",
            str(findings),
            "--out",
            str(out),
        ])
        text = (out / "zh-CN/final-summary-report.md").read_text()
        assert "执行摘要" in text
        assert "Needs Manual Review" in text
        assert "MANUAL-001" in text
        assert "人工验证计划" in text


if __name__ == "__main__":
    test_report_completeness_requires_manual_plan()
    test_final_summary_is_chinese_and_lists_manual_review()
    print("final summary gate tests passed")
