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


def minimal_success_audit(audit: pathlib.Path):
    write_json(audit / "02-tools/tool-summary.json", {
        "strict_decision": "continue",
        "tools": [{"name": "rg", "status": "completed", "negative_conclusion_allowed": True}],
    })
    write_json(audit / "machine/workflow-steps/08-report.json", {
        "step_id": "08-report",
        "status": "completed",
        "decision": "continue",
    })


def test_scope_coverage_evidence_only_degrades_report_status(tmp_path):
    audit = tmp_path / "audit"
    minimal_success_audit(audit)
    write_json(audit / "01-profile/scope-coverage.json", {
        "schema_version": "1.0",
        "counts": {
            "all_files_considered": 5,
            "direct_scan_files": 1,
            "evidence_only_files": 4,
            "hard_excluded_files_sampled": 0,
        },
        "evidence_only_categories": {
            "tests": 1,
            "examples": 1,
            "docs": 1,
            "fuzz-corpus": 1,
        },
    })

    status = report_status.compute_report_status(audit_root=audit, findings=[])

    assert status["report_type"] == "degraded-audit-report"
    assert status["negative_conclusion_allowed"] is False
    assert status["scope_coverage"]["counts"]["evidence_only_files"] == 4
    assert any("scope coverage" in item for item in status["coverage_limitations"])


def test_missing_scope_coverage_is_legacy_compatible(tmp_path):
    audit = tmp_path / "audit"
    minimal_success_audit(audit)

    status = report_status.compute_report_status(audit_root=audit, findings=[])

    assert status["report_type"] == "complete-audit-report"
    assert status["scope_coverage"] == {}
    assert status["coverage_limitations"] == []


def test_postprocess_copies_scope_coverage_to_machine_report_and_human_status(tmp_path):
    audit = tmp_path / "audit"
    out = audit / "06-report"
    minimal_success_audit(audit)
    write_json(audit / "01-profile/scope-coverage.json", {
        "schema_version": "1.0",
        "counts": {
            "all_files_considered": 3,
            "direct_scan_files": 1,
            "evidence_only_files": 2,
            "hard_excluded_files_sampled": 0,
        },
        "evidence_only_categories": {"tests": 2},
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

    assert status["report_type"] == "degraded-audit-report"
    assert machine["scope_coverage"]["counts"]["evidence_only_files"] == 2
    assert "Evidence-only files: 2" in en_text
    assert "证据-only 文件数量：2" in zh_text
