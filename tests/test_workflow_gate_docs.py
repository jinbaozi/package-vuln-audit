#!/usr/bin/env python3
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def text(path):
    return (ROOT / path).read_text()


def test_tool_scan_documents_matrix_and_semgrep_gate():
    t = text("workflows/03-tool-scan.md")
    assert "required-tools-matrix.json" in t
    assert "tool-execution-attempts.json" in t
    assert "semgrep" in t
    assert "不能静默降级" in t


def test_validation_documents_poc_run_result_and_manual_plan():
    t = text("workflows/06-validation.md")
    assert "poc-run-result.json" in t
    assert "manual-validation-plan.md" in t
    assert "Needs Manual Review" in t
    assert "draft" in t
    assert "unverified" in t
    assert 'status = `passed`' in t
    assert "does not change the finding status" in t


def test_report_documents_chinese_summary_and_dual_lane():
    t = text("workflows/08-report.md")
    assert "中文" in t
    assert "Validated" in t
    assert "Needs Manual Review" in t
    assert "最终汇总报告" in t
    assert "Manual validation plan" in t
    assert "Draft PoC artifact index" in t
    assert 'status = `passed`' in t


if __name__ == "__main__":
    test_tool_scan_documents_matrix_and_semgrep_gate()
    test_validation_documents_poc_run_result_and_manual_plan()
    test_report_documents_chinese_summary_and_dual_lane()
    print("workflow gate docs tests passed")
