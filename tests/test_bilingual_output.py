#!/usr/bin/env python3
import json, pathlib, tempfile
from tool_runner import ROOT, run_tool

def main():
    with tempfile.TemporaryDirectory() as td:
        t=pathlib.Path(td); findings=t/'findings.json'; corr=t/'corr.json'
        findings.write_text(json.dumps({'findings':[{'id':'FINDING-001','status':'Validated','title':'local parser crash','summary':'Validated local parser crash','affected_component':{'package':'binutils','component':'readelf'},'source_code_evidence':[{'file':'binutils/readelf.c','function':'display_relocations'}],'source_to_sink_path':'input -> readelf -> crash','validation':{},'cvss':{'vector':'CVSS:4.0/AV:L'},'fix_recommendation':'add bounds check','disclosure_level':'D3-maintainer-private','discovery_method':[{'type':'tool','tool_name':'semgrep','description':'fixture'}],'disclosure_status':'publicly_disclosed'}]}))
        corr.write_text(json.dumps({'checked_sources':['NVD'],'correlations':[{'finding_id':'FINDING-001','status':'publicly_disclosed','match_level':'M3','matched_records':[{'id':'CVE-2026-0001','references':['https://example.invalid/CVE-2026-0001']}]}]}))
        out=t/'audit-output'
        run_tool('tools/publish_bilingual_reports.py', ['--findings', str(findings), '--correlation', str(corr), '--out', str(out)])
        run_tool('tools/validate_language_outputs.py', ['--audit-output', str(out)])
        bm=json.loads((out/'machine/bilingual-map.json').read_text())
        assert bm['pairs'][0]['id']=='FINDING-001'
        assert (out/bm['pairs'][0]['zh']).exists()
        assert (out/bm['pairs'][0]['en']).exists()
    print('bilingual output tests passed')
if __name__=='__main__': main()
