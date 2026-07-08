from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import report_status


def write_json(path: pathlib.Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def test_complete_report_allows_negative_conclusion(tmp_path):
    audit = tmp_path / "audit"
    write_json(audit / "02-tools/tool-summary.json", {
        "strict_decision": "continue",
        "tools": [
            {"name": "rg", "status": "completed", "negative_conclusion_allowed": True},
            {"name": "semgrep", "status": "not-applicable", "negative_conclusion_allowed": True},
        ],
    })
    write_json(audit / "machine/workflow-steps/08-report.json", {
        "step_id": "08-report",
        "status": "completed",
        "decision": "continue",
    })

    status = report_status.compute_report_status(audit_root=audit, findings=[])

    assert status["report_type"] == "complete-audit-report"
    assert status["negative_conclusion_allowed"] is True
    assert status["blocking_reasons"] == []


def test_degraded_report_when_manual_review_exists(tmp_path):
    audit = tmp_path / "audit"
    write_json(audit / "02-tools/tool-summary.json", {
        "strict_decision": "continue",
        "tools": [{"name": "rg", "status": "completed", "negative_conclusion_allowed": True}],
    })
    write_json(audit / "machine/workflow-steps/08-report.json", {
        "step_id": "08-report",
        "status": "completed",
        "decision": "continue",
    })
    findings = [{"id": "F-1", "status": "Needs Manual Review"}]

    status = report_status.compute_report_status(audit_root=audit, findings=findings)

    assert status["report_type"] == "degraded-audit-report"
    assert status["negative_conclusion_allowed"] is False
    assert any("manual review" in reason for reason in status["degraded_reasons"])


def test_failure_summary_when_tool_blocks(tmp_path):
    audit = tmp_path / "audit"
    write_json(audit / "02-tools/tool-summary.json", {
        "strict_decision": "block",
        "tools": [{"name": "semgrep", "status": "blocked-recovery-required", "reason": "no-local-rules"}],
    })
    write_json(audit / "machine/workflow-steps/03-tool-scan.json", {
        "step_id": "03-tool-scan",
        "status": "failed-after-retries",
        "decision": "blocked-recovery-required",
        "blocking_issues": ["semgrep missing local rules"],
    })

    status = report_status.compute_report_status(audit_root=audit, findings=[])

    assert status["report_type"] == "failure-summary-report"
    assert status["negative_conclusion_allowed"] is False
    assert status["blocking_reasons"]


def test_validated_without_correlation_is_degraded(tmp_path):
    audit = tmp_path / "audit"
    write_json(audit / "02-tools/tool-summary.json", {
        "strict_decision": "continue",
        "tools": [{"name": "rg", "status": "completed", "negative_conclusion_allowed": True}],
    })
    write_json(audit / "machine/workflow-steps/08-report.json", {
        "step_id": "08-report",
        "status": "completed",
        "decision": "continue",
    })
    findings = [{"id": "F-1", "status": "Validated"}]

    status = report_status.compute_report_status(audit_root=audit, findings=findings, correlation={})

    assert status["report_type"] == "degraded-audit-report"
    assert status["public_correlation_status"] == "correlation_not_configured"
    assert status["public_disclosure_negative_conclusion_allowed"] is False
    assert status["negative_conclusion_allowed"] is False
    assert status["coverage_limitations"]


def test_postprocess_final_report_writes_machine_and_prepends_human_reports(tmp_path):
    audit = tmp_path / "audit"
    out = audit / "06-report"
    write_json(audit / "02-tools/tool-summary.json", {
        "strict_decision": "continue",
        "tools": [{"name": "rg", "status": "completed", "negative_conclusion_allowed": True}],
    })
    write_json(audit / "machine/workflow-steps/08-report.json", {
        "step_id": "08-report",
        "status": "completed",
        "decision": "continue",
    })
    write_json(audit / "05-findings/finding-index.json", {"findings": []})
    write_json(out / "machine/final-report.json", {"findings": []})
    (out / "en-US").mkdir(parents=True)
    (out / "zh-CN").mkdir(parents=True)
    (out / "en-US/final-summary-report.md").write_text("# Final Report\n\nBody\n")
    (out / "zh-CN/final-summary-report.md").write_text("# 最终报告\n\n正文\n")

    status = report_status.postprocess_final_report(audit_root=audit, out_root=out)
    machine = json.loads((out / "machine/final-report.json").read_text())
    en_text = (out / "en-US/final-summary-report.md").read_text()
    zh_text = (out / "zh-CN/final-summary-report.md").read_text()

    assert status["report_type"] == "complete-audit-report"
    assert machine["report_type"] == "complete-audit-report"
    assert machine["negative_conclusion_allowed"] is True
    assert "Audit Conclusion Status" in en_text
    assert "审计结论状态" in zh_text
    assert (out / "machine/report-status.json").is_file()
