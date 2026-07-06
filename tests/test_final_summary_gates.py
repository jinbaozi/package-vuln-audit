#!/usr/bin/env python3
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / 'tools'))
import manifest_io
from tool_runner import minimal_finding, temp_audit_dir
from tool_runner import run_subprocess


def write_workflow_step(audit: pathlib.Path, step_id: str):
    payload = {
        'step_id': step_id,
        'status': 'completed',
        'decision': 'continue',
        'attempt_count': 1,
        'blocking_issues': [],
        'limitations': [],
    }
    for rel, text in [
        (pathlib.Path('machine/workflow-steps') / f'{step_id}.json', json.dumps(payload)),
        (pathlib.Path('zh-CN/workflow-steps') / f'{step_id}.md', f'# {step_id}\n\n- 状态：completed\n'),
        (pathlib.Path('en-US/workflow-steps') / f'{step_id}.md', f'# {step_id}\n\n- Status: completed\n'),
    ]:
        path = audit / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def write_minimal_report_inputs(out: pathlib.Path):
    (out / "zh-CN/05-内部安全报告").mkdir(parents=True, exist_ok=True)
    (out / "en-US/05-internal-security-report").mkdir(parents=True, exist_ok=True)
    (out / "zh-CN/05-内部安全报告/internal-security-report.md").write_text("公开披露状态与标准来源汇总表\n| A | B |\n|---|---|\n")
    (out / "en-US/05-internal-security-report/internal-security-report.md").write_text("Public Disclosure Status and Standard Source Summary\n| A | B |\n|---|---|\n")
    (out / "02-tools").mkdir(parents=True, exist_ok=True)
    (out / "02-tools/tool-summary.json").write_text(json.dumps({
        "strict_decision": "continue",
        "tools": [{"name": "semgrep", "status": "completed", "strict_decision": "continue"}],
    }))


def test_report_completeness_requires_manual_plan():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        findings = td / "findings.json"
        corr = td / "corr.json"
        out = td / "audit-output"
        findings.write_text(json.dumps({"findings": [minimal_finding(
            id="MANUAL-001", status="Needs Manual Review", validation={}, cvss={},
            manual_review={"blocked_reason": "needs corpus"},
        )]}))
        corr.write_text(json.dumps({"correlations": []}))
        write_minimal_report_inputs(out)
        p = run_subprocess('tools/validate_report_completeness.py', [
            '--findings', str(findings),
            '--correlation', str(corr),
            '--report-root', str(out),
            '--manual-root', str(out / '04-validation/manual-review'),
            '--out', str(out / 'machine/report-completeness.json'),
        ], check=False)
        assert p.returncode == 1
        result = json.loads((out / "machine/report-completeness.json").read_text())
        assert any("manual validation plan" in e for e in result["errors"])


def test_report_completeness_requires_all_workflow_steps_when_enabled():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        findings = td / "findings.json"
        corr = td / "corr.json"
        out = td / "audit-output"
        findings.write_text(json.dumps({"findings": []}))
        corr.write_text(json.dumps({"correlations": []}))
        write_minimal_report_inputs(out)
        p = run_subprocess('tools/validate_report_completeness.py', [
            '--findings', str(findings),
            '--correlation', str(corr),
            '--report-root', str(out),
            '--require-workflow-steps',
            '--out', str(out / 'machine/report-completeness.json'),
        ], check=False)
        assert p.returncode == 1
        result = json.loads((out / "machine/report-completeness.json").read_text())
        assert any("missing workflow step conclusion" in e for e in result["errors"])


def test_final_summary_is_chinese_and_lists_manual_review():
    with temp_audit_dir() as td:
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
        findings.write_text(json.dumps({"findings": [minimal_finding(
            id="MANUAL-001", status="Needs Manual Review", validation={}, cvss={},
            manual_review={"blocked_reason": "needs corpus"},
        )]}))
        out = audit / "06-report"
        run_subprocess('tools/generate_final_report.py', [
            '--audit-root', str(audit),
            '--findings', str(findings),
            '--out', str(out),
        ])
        text = (out / "zh-CN/final-summary-report.md").read_text()
        assert "执行摘要" in text
        assert "Needs Manual Review" in text
        assert "MANUAL-001" in text
        assert "人工验证计划" in text


def test_final_summary_records_offline_db_freshness_and_complete_workflow_steps():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        audit = td / "audit-output"
        (audit / "00-environment").mkdir(parents=True)
        (audit / "01-profile").mkdir(parents=True)
        (audit / "02-tools").mkdir(parents=True)
        (audit / "machine/correlation").mkdir(parents=True)
        (audit / "00-environment/environment-check.json").write_text(json.dumps({"tools": [], "decision": "continue"}))
        (audit / "01-profile/package-profile.json").write_text(json.dumps({"package_name": "demo", "primary_language": ["C/C++"]}))
        (audit / "01-profile/required-tools-matrix.json").write_text(json.dumps({"tools": []}))
        (audit / "02-tools/tool-summary.json").write_text(json.dumps({"tools": []}))
        (audit / "machine/correlation/offline-db-freshness.json").write_text(json.dumps({
            "status": "ok",
            "sources": [{"source": "NVD", "freshness": "stale", "limitations": ["offline DB is stale"]}],
        }))
        for step_id in manifest_io.business_workflow_ids(ROOT):
            write_workflow_step(audit, step_id)
        findings = td / "findings.json"
        findings.write_text(json.dumps({"findings": []}))
        corr = td / "corr.json"
        corr.write_text(json.dumps({"correlations": []}))
        out = audit / "06-report"
        run_subprocess('tools/generate_final_report.py', [
            '--audit-root', str(audit),
            '--findings', str(findings),
            '--correlation', str(corr),
            '--out', str(out),
        ])
        machine = json.loads((out / "machine/final-report.json").read_text())
        assert machine["public_disclosure"]["offline_db_freshness"]["sources"][0]["freshness"] == "stale"
        en_text = (out / "en-US/final-summary-report.md").read_text()
        zh_text = (out / "zh-CN/final-summary-report.md").read_text()
        assert "NVD:stale" in en_text
        assert "NVD:stale" in zh_text
        assert "`08-report` | completed" in en_text
        assert "`09-progressive-disclosure` | completed" in en_text
        assert "workflow step artifact missing" not in en_text


def test_report_completeness_blocks_final_report_on_blocked_tool_scan():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        findings = td / "findings.json"
        corr = td / "corr.json"
        out = td / "audit-output"
        findings.write_text(json.dumps({"findings": []}))
        corr.write_text(json.dumps({"correlations": []}))
        write_minimal_report_inputs(out)
        (out / "02-tools/tool-summary.json").write_text(json.dumps({
            "strict_decision": "block",
            "tools": [{
                "name": "semgrep",
                "status": "blocked-recovery-required",
                "reason": "not-installed",
                "strict_decision": "block",
            }],
        }))
        p = run_subprocess('tools/validate_report_completeness.py', [
            '--findings', str(findings),
            '--correlation', str(corr),
            '--report-root', str(out),
            '--out', str(out / 'machine/report-completeness.json'),
        ], check=False)
        assert p.returncode == 1
        result = json.loads((out / "machine/report-completeness.json").read_text())
        assert any("tool execution gate blocked" in e for e in result["errors"])


def test_final_summary_reports_blocked_tool_execution_status():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        audit = td / "audit-output"
        (audit / "00-environment").mkdir(parents=True)
        (audit / "01-profile").mkdir(parents=True)
        (audit / "02-tools").mkdir(parents=True)
        (audit / "00-environment/environment-check.json").write_text(json.dumps({"tools": [], "decision": "continue"}))
        (audit / "01-profile/package-profile.json").write_text(json.dumps({"package_name": "demo", "primary_language": ["C/C++"]}))
        (audit / "01-profile/required-tools-matrix.json").write_text(json.dumps({"tools": [{"name": "semgrep", "final_status": "planned"}]}))
        (audit / "02-tools/tool-summary.json").write_text(json.dumps({
            "strict_decision": "block",
            "tools": [{
                "name": "semgrep",
                "status": "blocked-recovery-required",
                "reason": "not-installed",
                "strict_decision": "block",
            }],
        }))
        findings = td / "findings.json"
        findings.write_text(json.dumps({"findings": []}))
        out = audit / "06-report"
        run_subprocess('tools/generate_final_report.py', [
            '--audit-root', str(audit),
            '--findings', str(findings),
            '--out', str(out),
        ])
        machine = json.loads((out / "machine/final-report.json").read_text())
        assert machine["tool_execution_status"]["decision"] == "block"
        assert machine["tool_execution_status"]["blocked"][0]["name"] == "semgrep"
        en_text = (out / "en-US/final-summary-report.md").read_text()
        assert "Tool Execution Status" in en_text
        assert "cannot support a no-vulnerability conclusion" in en_text


if __name__ == "__main__":
    test_report_completeness_requires_manual_plan()
    test_report_completeness_requires_all_workflow_steps_when_enabled()
    test_final_summary_is_chinese_and_lists_manual_review()
    test_final_summary_records_offline_db_freshness_and_complete_workflow_steps()
    test_report_completeness_blocks_final_report_on_blocked_tool_scan()
    test_final_summary_reports_blocked_tool_execution_status()
    print("final summary gate tests passed")
