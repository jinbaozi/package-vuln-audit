#!/usr/bin/env python3
"""Validate enforced bilingual report completeness and public-correlation gates.

Also validates final summary report contains required data sections
(funnel statistics, severity distribution, risk overview, etc.).
"""
from __future__ import annotations
import argparse, json, pathlib, re, sys

from pvas_io import corr_map, findings_list, load_json, write_json

ABSOLUTE_UNPUBLISHED_PATTERNS = [
    '未公开', '绝对未公开', '从未公开', '不存在公开漏洞',
    'not publicly disclosed', 'never disclosed', 'no public vulnerability exists'
]
REQUIRED_ZH_HEADING = '公开披露状态与标准来源汇总表'
REQUIRED_EN_HEADING = 'Public Disclosure Status and Standard Source Summary'

# Required sections in the final summary report
REQUIRED_FINAL_REPORT_SECTIONS_EN = [
    'Executive Summary',
    'Audit Funnel Statistics',
    'Severity Distribution',
    'Risk Overview',
]
REQUIRED_FINAL_REPORT_SECTIONS_ZH = [
    '执行摘要',
    '审计漏斗统计',
    '严重程度分布',
    '风险概览',
]
BUSINESS_WORKFLOWS = [
    '00-intake', '01-package-profile', '02-scope-selection', '03-tool-scan',
    '04-ai-hypothesis', '05-candidate-review', '06-validation',
    '07-cvss-scoring', '08-report', '09-progressive-disclosure',
]

CJK = re.compile(r'[\u4e00-\u9fff]')
CODE_BLOCK = re.compile(r'```.*?```', re.S)
INLINE_CODE = re.compile(r'`[^`]+`')
ID_PAT = re.compile(
    r'\b(CVE-\d{4}-\d+|GHSA-[A-Za-z0-9-]+|OSV-[A-Za-z0-9-]+|CVSS:[0-9.]+/[^\s]+|'
    r'[A-Za-z0-9_./+-]+\.(c|h|cpp|md|json|sh))\b'
)


def natural_text(s: str) -> str:
    s = CODE_BLOCK.sub('', s)
    s = INLINE_CODE.sub('', s)
    return ID_PAT.sub('', s)


def check_language_isolation(report_root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    bm_path = report_root / 'machine' / 'bilingual-map.json'
    if not bm_path.is_file():
        return ['missing bilingual-map.json']
    bm = load_json(bm_path, required=True)
    for pair in bm.get('pairs', []):
        for k in ('zh', 'en'):
            if not (report_root / pair[k]).is_file():
                errors.append(f'missing {k}: {pair[k]}')
        zh = (report_root / pair['zh']).read_text() if (report_root / pair['zh']).exists() else ''
        en = (report_root / pair['en']).read_text() if (report_root / pair['en']).exists() else ''
        if len(CJK.findall(natural_text(zh))) < 5:
            errors.append(f'zh-CN output lacks Chinese prose: {pair["id"]}')
        if len(CJK.findall(natural_text(en))) > 10:
            errors.append(f'en-US output contains too much CJK prose: {pair["id"]}')
    return errors


def contains_skeleton(text: str) -> bool:
    skeletons = [
        '本目录包含中文审计输出',
        'This directory contains English audit output',
        'TODO', 'TBD'
    ]
    return any(x in text for x in skeletons)


def validate_final_report_sections(root: pathlib.Path, errors, warnings):
    """Validate that the final summary report contains required data sections."""
    en_final = root / 'final-summary-report.md'
    zh_final = root / 'zh-CN' / 'final-summary-report.md'

    for report_path, required_sections, label in [
        (en_final, REQUIRED_FINAL_REPORT_SECTIONS_EN, 'EN final report'),
        (zh_final, REQUIRED_FINAL_REPORT_SECTIONS_ZH, 'ZH final report'),
    ]:
        if not report_path.exists():
            # Final report is optional — only warn
            warnings.append(f'{label}: not found at {report_path}')
            continue

        text = report_path.read_text(errors='ignore')
        for section in required_sections:
            if section not in text:
                warnings.append(f'{label}: missing required section "{section}"')

        # Check that report has data tables (not just placeholders)
        table_count = text.count('|---|')
        if table_count < 3:
            warnings.append(f'{label}: fewer than 3 data tables detected ({table_count})')

        # Check for unfilled placeholders
        unfilled = re.findall(r'\{\{[a-z_]+\}\}', text)
        if unfilled:
            errors.append(f'{label}: unfilled template placeholders: {", ".join(unfilled[:5])}')


def validate_workflow_steps(root: pathlib.Path, errors: list[str]) -> None:
    for step_id in BUSINESS_WORKFLOWS:
        required_paths = [
            root / 'machine' / 'workflow-steps' / f'{step_id}.json',
            root / 'zh-CN' / 'workflow-steps' / f'{step_id}.md',
            root / 'en-US' / 'workflow-steps' / f'{step_id}.md',
        ]
        for path in required_paths:
            if not path.is_file():
                errors.append(f'missing workflow step conclusion: {path}')
        machine = required_paths[0]
        if machine.is_file():
            data = load_json(machine, {})
            if not isinstance(data, dict) or data.get('status') not in {'completed', 'completed-with-recovery', 'not-applicable', 'failed-after-retries'}:
                errors.append(f'{machine}: invalid or missing workflow step status')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--findings')
    ap.add_argument('--correlation')
    ap.add_argument('--report-root', default='audit-output')
    ap.add_argument('--poc-root')
    ap.add_argument('--manual-root')
    ap.add_argument('--check-language-isolation', action='store_true')
    ap.add_argument('--require-workflow-steps', action='store_true')
    ap.add_argument('--language-isolation-only', action='store_true',
                    help='Only run CJK isolation check (skip report completeness gates)')
    ap.add_argument('--out', default='audit-output/machine/report-completeness.json')
    args = ap.parse_args()
    root = pathlib.Path(args.report_root)

    if args.language_isolation_only:
        errors = check_language_isolation(root)
        result = {
            'status': 'failed' if errors else 'passed',
            'errors': errors,
            'warnings': [],
        }
        write_json(args.out, result)
        print(json.dumps({'status': result['status'], 'errors': len(errors), 'warnings': 0},
                         ensure_ascii=False, indent=2))
        return 1 if errors else 0

    if not args.findings or not args.correlation:
        print('error: --findings and --correlation are required unless --language-isolation-only', file=sys.stderr)
        return 2

    findings = findings_list(load_json(pathlib.Path(args.findings), {'findings': []}))
    correlations = corr_map(load_json(pathlib.Path(args.correlation), {'correlations': []}))
    zh_report = root / 'zh-CN' / '05-内部安全报告' / 'internal-security-report.md'
    en_report = root / 'en-US' / '05-internal-security-report' / 'internal-security-report.md'
    errors: list[str] = []
    warnings: list[str] = []

    validated = [f for f in findings if f.get('status') == 'Validated']
    manual = [f for f in findings if f.get('status') == 'Needs Manual Review']
    for f in validated:
        fid = f.get('id')
        if not fid:
            errors.append('Validated finding missing id')
            continue
        if fid not in correlations:
            errors.append(f'{fid}: missing public vulnerability correlation')

        # Check discovery_method is non-empty
        dm = f.get('discovery_method', [])
        if not dm or len(dm) == 0:
            errors.append(f'{fid}: discovery_method is required but empty')

        # Check poc_test_artifacts
        pocs = f.get('poc_test_artifacts', [])
        if not pocs or len(pocs) == 0:
            errors.append(f'{fid}: no poc_test_artifacts (generate via generate_poc_testcase.py)')

        # Check disclosure_status is not 'unknown'
        ds = f.get('disclosure_status', 'unknown')
        if ds == 'unknown':
            errors.append(f'{fid}: disclosure_status is still "unknown"')

        # Check publicly_disclosed findings have references
        refs = f.get('public_vulnerability_references', [])
        if ds == 'publicly_disclosed' and (not refs or len(refs) == 0):
            errors.append(f'{fid}: disclosure_status is publicly_disclosed but no public_vulnerability_references provided')

    for p, heading in [(zh_report, REQUIRED_ZH_HEADING), (en_report, REQUIRED_EN_HEADING)]:
        if not p.exists():
            errors.append(f'missing report: {p}')
            continue
        text = p.read_text(errors='ignore')
        if heading not in text:
            errors.append(f'{p}: missing required disclosure summary heading')
        if contains_skeleton(text):
            errors.append(f'{p}: skeleton/placeholder report rejected')
        for pat in ABSOLUTE_UNPUBLISHED_PATTERNS:
            if pat.lower() in text.lower():
                errors.append(f'{p}: forbidden absolute unpublished wording: {pat}')
        if '|' not in text:
            errors.append(f'{p}: no markdown summary table detected')

    # Validate final summary report sections
    validate_final_report_sections(root, errors, warnings)
    if args.require_workflow_steps:
        validate_workflow_steps(root, errors)

    if args.check_language_isolation:
        errors.extend(check_language_isolation(root))

    if args.poc_root:
        poc_root = pathlib.Path(args.poc_root)
        poc_index: dict[str, list[str]] = {}
        for p in poc_root.rglob('*'):
            if p.is_file():
                for f in validated:
                    fid = f.get('id')
                    if fid and fid in p.name:
                        poc_index.setdefault(fid, []).append(str(p))
        for f in validated:
            fid = f.get('id')
            if not fid: continue
            if fid not in poc_index:
                warnings.append(f'{fid}: no PoC/testcase summary found under poc-root')

    if args.manual_root:
        manual_root = pathlib.Path(args.manual_root)
        for f in manual:
            fid = f.get('id')
            if not fid:
                errors.append('Needs Manual Review item missing id')
                continue
            plan_json = manual_root / fid / 'manual-validation-plan.json'
            plan_md = manual_root / fid / 'manual-validation-plan.md'
            if not plan_json.exists() or not plan_md.exists():
                errors.append(f'{fid}: missing manual validation plan')

    result = {
        'status': 'failed' if errors else 'passed',
        'errors': errors,
        'warnings': warnings,
        'validated_findings': [f.get('id') for f in validated],
    }
    write_json(args.out, result)
    print(json.dumps({'status': result['status'], 'errors': len(errors), 'warnings': len(warnings)}, ensure_ascii=False, indent=2))
    return 1 if errors else 0

if __name__ == '__main__':
    raise SystemExit(main())
