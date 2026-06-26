#!/usr/bin/env python3
import json, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]


def sample_findings():
    return {'findings':[{'id':'FINDING-001','status':'Validated','title':'buffer overflow in parser','summary':'buffer overflow in parser','affected_component':{'package':'demo','component':'parser'},'source_code_evidence':[{'file':'src/parser.c','function':'parse'}],'source_to_sink_path':'input -> parse -> overflow','validation':{},'cvss':{},'fix_recommendation':'add bounds check','disclosure_level':'D2-internal-validated','discovery_method':[{'type':'tool','tool_name':'cppcheck','description':'fixture'}],'disclosure_status':'not_found_in_configured_sources','poc_test_artifacts':[{'id':'FINDING-001-poc','path':'04-validation/poc/FINDING-001','status':'executed'}]}]} 


def sample_corr():
    return {'checked_sources':['NVD','OSV'], 'correlations':[{'finding_id':'FINDING-001','status':'not_found_in_configured_sources','match_level':'M0','matched_records':[],'checked_sources':['NVD','OSV'],'limitations':['offline fixture']}]} 


def test_publish_and_validate_report_completeness():
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td)
        f=td/'findings.json'; c=td/'corr.json'; out=td/'audit-output'
        f.write_text(json.dumps(sample_findings()))
        c.write_text(json.dumps(sample_corr()))
        subprocess.check_call([sys.executable, str(ROOT/'tools'/'publish_bilingual_reports.py'), '--findings', str(f), '--correlation', str(c), '--out', str(out)])
        subprocess.check_call([sys.executable, str(ROOT/'tools'/'validate_report_completeness.py'), '--findings', str(f), '--correlation', str(c), '--report-root', str(out), '--out', str(out/'machine/report-completeness.json')])
        zh=(out/'zh-CN/05-内部安全报告/internal-security-report.md').read_text()
        assert '公开披露状态与标准来源汇总表' in zh
        assert '未在已配置公开数据源中发现匹配记录' in zh


if __name__ == '__main__':
    test_publish_and_validate_report_completeness()
    print('report completeness enforcement tests passed')
