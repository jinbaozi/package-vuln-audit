#!/usr/bin/env python3
import json
import pathlib

from tool_runner import run_subprocess, temp_audit_dir


def sample_findings():
    return {'findings':[{'id':'FINDING-001','status':'Validated','title':'buffer overflow in parser','summary':'buffer overflow in parser','affected_component':{'package':'demo','component':'parser'},'source_code_evidence':[{'file':'src/parser.c','function':'parse'}],'source_to_sink_path':'input -> parse -> overflow','validation':{},'cvss':{},'fix_recommendation':'add bounds check','disclosure_level':'D2-internal-validated','discovery_method':[{'type':'tool','tool_name':'cppcheck','description':'fixture'}],'disclosure_status':'not_found_in_configured_sources','poc_test_artifacts':[{'id':'FINDING-001-poc','path':'04-validation/poc/FINDING-001','status':'executed'}]}]}


def sample_manual_findings():
    return {'findings': sample_findings()['findings'] + [{
        'id': 'MANUAL-001',
        'status': 'Needs Manual Review',
        'title': 'manual review fixture',
        'summary': 'manual review fixture',
        'affected_component': {'package': 'demo', 'component': 'parser'},
        'source_code_evidence': [{'file': 'src/parser.c', 'function': 'parse'}],
        'source_to_sink_path': 'input -> parse -> sink',
        'validation': {'manual_review_reason': 'needs local target build'},
        'cvss': {},
        'fix_recommendation': 'review parser bounds',
        'disclosure_level': 'D1-internal-likely',
        'discovery_method': [{'type': 'tool', 'tool_name': 'semgrep', 'description': 'fixture'}],
        'disclosure_status': 'not_found_in_configured_sources',
    }]}


def sample_corr():
    return {'checked_sources':['NVD','OSV'], 'correlations':[{'finding_id':'FINDING-001','status':'not_found_in_configured_sources','match_level':'M0','matched_records':[],'checked_sources':['NVD','OSV'],'limitations':['offline fixture']}]}


def test_publish_and_validate_report_completeness():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        f = td / 'findings.json'
        c = td / 'corr.json'
        out = td / 'audit-output'
        f.write_text(json.dumps(sample_findings()))
        c.write_text(json.dumps(sample_corr()))
        run_subprocess('tools/publish_bilingual_reports.py', ['--findings', str(f), '--correlation', str(c), '--out', str(out)])
        run_subprocess('tools/validate_report_completeness.py', [
            '--findings', str(f), '--correlation', str(c),
            '--report-root', str(out),
            '--out', str(out / 'machine/report-completeness.json'),
        ])
        zh = (out / 'zh-CN/05-内部安全报告/internal-security-report.md').read_text()
        assert '公开披露状态与标准来源汇总表' in zh
        assert '未在已配置公开数据源中发现匹配记录' in zh


def write_manual_plan(root: pathlib.Path):
    d = root / 'MANUAL-001'
    d.mkdir(parents=True)
    (d / 'manual-validation-plan.json').write_text(json.dumps({
        'finding_id': 'MANUAL-001',
        'status': 'Needs Manual Review',
        'validation_steps': ['run local draft PoC'],
    }))
    (d / 'manual-validation-plan.md').write_text('# Manual validation plan\n')


def write_draft_poc(root: pathlib.Path, passed=True):
    d = root / 'MANUAL-001'
    d.mkdir(parents=True)
    (d / 'reproduce.sh').write_text('#!/usr/bin/env bash\ntimeout 1s true\n')
    (d / 'input-description.md').write_text('SHA256: abc\nPurpose: local validation\n')
    (d / 'poc-run-result.json').write_text(json.dumps({
        'status': 'passed' if passed else 'failed',
        'exit_code': 0 if passed else 1,
        'command': 'timeout 1s ./reproduce.sh',
    }))
    (d / 'poc-manifest.json').write_text(json.dumps({
        'finding_id': 'MANUAL-001',
        'status': 'draft',
        'verification': 'unverified',
        'poc_type': 'generated-reproducer',
        'safety_class': 'local-validation-only',
        'discovery_method_ref': 'tool(semgrep)',
        'artifacts': {'reproduce_script': 'reproduce.sh'},
        'commands': {'reproduce': './reproduce.sh'},
        'expected_results': {'vulnerable': 'x', 'fixed': 'y'},
        'disclosure_level': 'D3-maintainer-private',
    }))


def test_needs_manual_review_requires_manual_plan_and_passed_draft_poc():
    with temp_audit_dir() as td:
        td = pathlib.Path(td)
        f = td / 'findings.json'
        c = td / 'corr.json'
        out = td / 'audit-output'
        manual_root = td / 'manual-review'
        poc_root = td / 'poc-tests'
        f.write_text(json.dumps(sample_manual_findings()))
        c.write_text(json.dumps(sample_corr()))
        run_subprocess('tools/publish_bilingual_reports.py', ['--findings', str(f), '--correlation', str(c), '--out', str(out)])
        write_manual_plan(manual_root)
        write_draft_poc(poc_root, passed=True)
        run_subprocess('tools/publish_bilingual_reports.py', [
            '--findings', str(f), '--correlation', str(c),
            '--poc-root', str(poc_root),
            '--out', str(out),
        ])
        en_finding = (out / 'en-US/04-findings/MANUAL-001.md').read_text()
        assert 'Draft PoC / unverified, execution passed' in en_finding
        run_subprocess('tools/validate_report_completeness.py', [
            '--findings', str(f), '--correlation', str(c),
            '--report-root', str(out),
            '--manual-root', str(manual_root),
            '--poc-root', str(poc_root),
            '--out', str(out / 'machine/report-completeness.json'),
        ])

        (poc_root / 'MANUAL-001' / 'poc-run-result.json').write_text(json.dumps({
            'status': 'failed',
            'exit_code': 1,
            'command': 'timeout 1s ./reproduce.sh',
        }))
        failed = run_subprocess('tools/validate_report_completeness.py', [
            '--findings', str(f), '--correlation', str(c),
            '--report-root', str(out),
            '--manual-root', str(manual_root),
            '--poc-root', str(poc_root),
            '--out', str(out / 'machine/report-completeness.json'),
        ], check=False)
        assert failed.returncode == 1
        result = json.loads((out / 'machine/report-completeness.json').read_text())
        assert any('draft PoC validation failed' in e for e in result['errors'])


if __name__ == '__main__':
    test_publish_and_validate_report_completeness()
    test_needs_manual_review_requires_manual_plan_and_passed_draft_poc()
    print('report completeness enforcement tests passed')
