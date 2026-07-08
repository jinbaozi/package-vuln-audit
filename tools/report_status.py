#!/usr/bin/env python3
"""Report status classification and post-processing helpers.

The final report must distinguish a complete audit from a degraded audit and a
failure summary. This module is intentionally independent from the large report
renderer so it can be reused by tests, report post-processing, and future driver
integration.
"""
from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from typing import Any

BLOCKING_TOOL_STATUSES = {
    'blocked-pending-confirmation',
    'blocked-recovery-required',
    'abnormal',
    'incomplete',
    'not-installed',
    'malformed-output',
    'nonzero-exit',
}
SUCCESS_TOOL_STATUSES = {'completed', 'completed-with-findings', 'not-applicable'}
FAILURE_WORKFLOW_STATUSES = {'failed-after-retries'}
DEGRADED_WORKFLOW_STATUSES = {'completed-with-recovery'}
STATUS_MARKER = '<!-- PVAS-REPORT-STATUS -->'


def _load_json(path: pathlib.Path, default: Any = None) -> Any:
    try:
        if path.is_file():
            return json.loads(path.read_text())
    except Exception:
        return default
    return default


def _write_json(path: pathlib.Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def _findings_from_path(path: pathlib.Path) -> list[dict]:
    raw = _load_json(path, [])
    if isinstance(raw, dict):
        raw = raw.get('findings', [])
    return [f for f in raw if isinstance(f, dict)] if isinstance(raw, list) else []


def _reportable_findings(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    validated = [f for f in findings if f.get('status') == 'Validated']
    manual = [f for f in findings if f.get('status') == 'Needs Manual Review']
    return validated, manual


def _tool_reasons(tool_summary: dict) -> tuple[list[str], list[str], bool]:
    blocking: list[str] = []
    degraded: list[str] = []
    negative_allowed = False
    if not isinstance(tool_summary, dict) or not tool_summary:
        return ['tool summary missing'], degraded, False
    tools = [t for t in tool_summary.get('tools') or [] if isinstance(t, dict)]
    if not tools:
        return ['tool summary has no tool rows'], degraded, False
    for tool in tools:
        name = str(tool.get('name') or '?')
        status = str(tool.get('status') or '')
        strict_decision = str(tool.get('strict_decision') or '')
        reason = str(tool.get('reason') or status or 'unknown')
        if strict_decision == 'block' or status in BLOCKING_TOOL_STATUSES:
            blocking.append(f'{name}: {reason}')
        elif status not in SUCCESS_TOOL_STATUSES:
            degraded.append(f'{name}: {reason}')
        if tool.get('negative_conclusion_allowed') is False and status not in {'not-applicable'}:
            degraded.append(f'{name}: negative conclusion not allowed')
    negative_allowed = not blocking and tool_summary.get('strict_decision') != 'block'
    return blocking, list(dict.fromkeys(degraded)), negative_allowed


def _workflow_reasons(audit_root: pathlib.Path) -> tuple[list[str], list[str]]:
    steps_dir = audit_root / 'machine' / 'workflow-steps'
    blocking: list[str] = []
    degraded: list[str] = []
    if not steps_dir.is_dir():
        return ['workflow step directory missing'], degraded
    for step_path in sorted(steps_dir.glob('*.json')):
        step = _load_json(step_path, {}) or {}
        step_id = str(step.get('step_id') or step_path.stem)
        status = str(step.get('status') or 'missing')
        decision = str(step.get('decision') or '')
        issues = [str(x) for x in step.get('blocking_issues') or []]
        limitations = [str(x) for x in step.get('limitations') or []]
        issue_text = '; '.join(issues) if issues else status
        if status in FAILURE_WORKFLOW_STATUSES or decision == 'failed':
            blocking.append(f'{step_id}: {issue_text}')
        elif status in DEGRADED_WORKFLOW_STATUSES:
            degraded.append(f'{step_id}: completed with recovery')
        if limitations:
            degraded.extend(f'{step_id}: {item}' for item in limitations)
    return blocking, list(dict.fromkeys(degraded))


def _correlation_reasons(correlation: dict, validated_count: int) -> tuple[list[str], str, bool]:
    limitations: list[str] = []
    public_negative_allowed = True
    status = 'not_applicable' if validated_count == 0 else 'unknown'
    if not isinstance(correlation, dict) or not correlation:
        if validated_count:
            status = 'correlation_not_configured'
            public_negative_allowed = False
            limitations.append('public vulnerability correlation not configured for Validated findings')
        return limitations, status, public_negative_allowed

    status = str(correlation.get('status') or '') or 'configured'
    if status in {'unknown', 'correlation_not_configured'}:
        public_negative_allowed = False
        limitations.append(str(correlation.get('reason') or 'public vulnerability correlation status is unknown'))
    if correlation.get('negative_public_disclosure_conclusion_allowed') is False:
        public_negative_allowed = False
        limitations.append('public disclosure negative conclusion not allowed')
    if not correlation.get('correlations') and validated_count and status in {'configured', 'ok'}:
        limitations.append('public correlation returned no per-finding rows')
    return list(dict.fromkeys(limitations)), status, public_negative_allowed


def compute_report_status(
    *,
    audit_root: pathlib.Path,
    findings: list[dict],
    tool_summary: dict | None = None,
    correlation: dict | None = None,
) -> dict:
    """Return machine-readable report status and conclusion permissions."""
    tool_summary = tool_summary if isinstance(tool_summary, dict) else _load_json(audit_root / '02-tools' / 'tool-summary.json', {})
    correlation = correlation if isinstance(correlation, dict) else _load_json(audit_root / 'machine' / 'correlation' / 'public-vuln-correlation.json', {})
    validated, manual = _reportable_findings(findings)

    blocking_reasons: list[str] = []
    degraded_reasons: list[str] = []
    coverage_limitations: list[str] = []

    tool_blocking, tool_degraded, tool_negative_allowed = _tool_reasons(tool_summary or {})
    wf_blocking, wf_degraded = _workflow_reasons(audit_root)
    corr_limitations, corr_status, public_negative_allowed = _correlation_reasons(correlation or {}, len(validated))

    blocking_reasons.extend(tool_blocking)
    blocking_reasons.extend(wf_blocking)
    degraded_reasons.extend(tool_degraded)
    degraded_reasons.extend(wf_degraded)
    coverage_limitations.extend(corr_limitations)

    if manual:
        degraded_reasons.append(f'{len(manual)} finding(s) require manual review')
    if validated:
        degraded_reasons.append(f'{len(validated)} Validated finding(s) present; no-vulnerability conclusion is not allowed')

    if blocking_reasons:
        report_type = 'failure-summary-report'
    elif degraded_reasons or coverage_limitations:
        report_type = 'degraded-audit-report'
    else:
        report_type = 'complete-audit-report'

    negative_conclusion_allowed = (
        report_type == 'complete-audit-report'
        and tool_negative_allowed
        and public_negative_allowed
        and not validated
        and not manual
    )

    return {
        'schema_version': '1.0',
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'report_type': report_type,
        'negative_conclusion_allowed': negative_conclusion_allowed,
        'public_disclosure_negative_conclusion_allowed': public_negative_allowed,
        'public_correlation_status': corr_status,
        'validated_findings': len(validated),
        'needs_manual_review': len(manual),
        'blocking_reasons': list(dict.fromkeys(blocking_reasons)),
        'degraded_reasons': list(dict.fromkeys(degraded_reasons)),
        'coverage_limitations': list(dict.fromkeys(coverage_limitations)),
    }


def render_status_markdown(status: dict, *, locale: str = 'en-US') -> str:
    if locale == 'zh-CN':
        lines = [
            STATUS_MARKER,
            '## 审计结论状态',
            '',
            f"- 报告类型：`{status.get('report_type', 'unknown')}`",
            f"- 是否允许完整“未发现漏洞”结论：`{str(status.get('negative_conclusion_allowed', False)).lower()}`",
            f"- 公开漏洞关联状态：`{status.get('public_correlation_status', 'unknown')}`",
            f"- 已验证发现数量：{status.get('validated_findings', 0)}",
            f"- 需人工复核数量：{status.get('needs_manual_review', 0)}",
        ]
        headings = [('阻断原因', 'blocking_reasons'), ('降级原因', 'degraded_reasons'), ('覆盖限制', 'coverage_limitations')]
    else:
        lines = [
            STATUS_MARKER,
            '## Audit Conclusion Status',
            '',
            f"- Report type: `{status.get('report_type', 'unknown')}`",
            f"- Complete no-vulnerability conclusion allowed: `{str(status.get('negative_conclusion_allowed', False)).lower()}`",
            f"- Public correlation status: `{status.get('public_correlation_status', 'unknown')}`",
            f"- Validated findings: {status.get('validated_findings', 0)}",
            f"- Needs manual review: {status.get('needs_manual_review', 0)}",
        ]
        headings = [('Blocking reasons', 'blocking_reasons'), ('Degraded reasons', 'degraded_reasons'), ('Coverage limitations', 'coverage_limitations')]
    for heading, key in headings:
        values = status.get(key) or []
        lines.extend(['', f'### {heading}', ''])
        if values:
            lines.extend(f'- {value}' for value in values)
        else:
            lines.append('- none')
    lines.append('')
    return '\n'.join(lines)


def _insert_status_section(text: str, section: str) -> str:
    if STATUS_MARKER in text:
        return text
    lines = text.splitlines()
    if lines and lines[0].startswith('# '):
        return '\n'.join([lines[0], '', section, *lines[1:]]) + ('\n' if text.endswith('\n') else '')
    return section + '\n' + text


def postprocess_final_report(
    *,
    audit_root: pathlib.Path,
    out_root: pathlib.Path,
    findings_path: pathlib.Path | None = None,
    correlation_path: pathlib.Path | None = None,
) -> dict:
    findings_path = findings_path or (audit_root / '05-findings' / 'finding-index.json')
    correlation_path = correlation_path or (audit_root / 'machine' / 'correlation' / 'public-vuln-correlation.json')
    findings = _findings_from_path(findings_path)
    correlation = _load_json(correlation_path, {}) if correlation_path else {}
    status = compute_report_status(audit_root=audit_root, findings=findings, correlation=correlation)

    machine_dir = out_root / 'machine'
    final_report_path = machine_dir / 'final-report.json'
    machine_report = _load_json(final_report_path, {}) or {}
    if isinstance(machine_report, dict):
        machine_report['report_type'] = status['report_type']
        machine_report['negative_conclusion_allowed'] = status['negative_conclusion_allowed']
        machine_report['report_status'] = status
        _write_json(final_report_path, machine_report)
    _write_json(machine_dir / 'report-status.json', status)

    for rel, locale in [
        (pathlib.Path('en-US/final-summary-report.md'), 'en-US'),
        (pathlib.Path('zh-CN/final-summary-report.md'), 'zh-CN'),
        (pathlib.Path('final-summary-report.md'), 'en-US'),
    ]:
        path = out_root / rel
        if not path.is_file():
            continue
        section = render_status_markdown(status, locale=locale)
        path.write_text(_insert_status_section(path.read_text(), section))
    return status


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--audit-root', default='audit-output')
    ap.add_argument('--out', default='audit-output/06-report')
    ap.add_argument('--findings')
    ap.add_argument('--correlation')
    args = ap.parse_args()
    status = postprocess_final_report(
        audit_root=pathlib.Path(args.audit_root),
        out_root=pathlib.Path(args.out),
        findings_path=pathlib.Path(args.findings) if args.findings else None,
        correlation_path=pathlib.Path(args.correlation) if args.correlation else None,
    )
    print(json.dumps(status, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
