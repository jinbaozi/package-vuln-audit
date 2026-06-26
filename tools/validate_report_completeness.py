#!/usr/bin/env python3
"""Validate enforced bilingual report completeness and public-correlation gates."""
from __future__ import annotations
import argparse, json, pathlib, re, sys

ABSOLUTE_UNPUBLISHED_PATTERNS = [
    '未公开', '绝对未公开', '从未公开', '不存在公开漏洞',
    'not publicly disclosed', 'never disclosed', 'no public vulnerability exists'
]
REQUIRED_ZH_HEADING = '公开披露状态与标准来源汇总表'
REQUIRED_EN_HEADING = 'Public Disclosure Status and Standard Source Summary'


def load_json(path: pathlib.Path, default):
    if not path or not path.exists(): return default
    return json.loads(path.read_text())


def findings_list(data):
    if isinstance(data, list): return data
    if isinstance(data, dict): return data.get('findings', [])
    return []


def corr_map(data):
    if not isinstance(data, dict): return {}
    return {c.get('finding_id'): c for c in data.get('correlations', [])}


def contains_skeleton(text: str) -> bool:
    skeletons = [
        '本目录包含中文审计输出',
        'This directory contains English audit output',
        'TODO', 'TBD'
    ]
    return any(x in text for x in skeletons)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--findings', required=True)
    ap.add_argument('--correlation', required=True)
    ap.add_argument('--report-root', default='audit-output')
    ap.add_argument('--poc-root')
    ap.add_argument('--out', default='audit-output/machine/report-completeness.json')
    args = ap.parse_args()

    findings = findings_list(load_json(pathlib.Path(args.findings), {'findings': []}))
    correlations = corr_map(load_json(pathlib.Path(args.correlation), {'correlations': []}))
    root = pathlib.Path(args.report_root)
    zh_report = root / 'zh-CN' / '05-内部安全报告' / 'internal-security-report.md'
    en_report = root / 'en-US' / '05-internal-security-report' / 'internal-security-report.md'
    errors: list[str] = []
    warnings: list[str] = []

    validated = [f for f in findings if f.get('status') == 'Validated']
    for f in validated:
        fid = f.get('id')
        if not fid:
            errors.append('Validated finding missing id')
            continue
        if fid not in correlations:
            errors.append(f'{fid}: missing public vulnerability correlation')

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

    if args.poc_root:
        poc_root = pathlib.Path(args.poc_root)
        for f in validated:
            fid = f.get('id')
            if not fid: continue
            candidates = list(poc_root.glob(f'**/*{fid}*'))
            if not candidates:
                warnings.append(f'{fid}: no PoC/testcase summary found under poc-root')

    result = {'status': 'failed' if errors else 'passed', 'errors': errors, 'warnings': warnings, 'validated_findings': [f.get('id') for f in validated]}
    out = pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(json.dumps({'status': result['status'], 'errors': len(errors), 'warnings': len(warnings)}, ensure_ascii=False, indent=2))
    return 1 if errors else 0

if __name__ == '__main__':
    raise SystemExit(main())
