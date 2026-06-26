#!/usr/bin/env python3
import json, pathlib, tempfile
from tool_runner import ROOT, run_tool

def main():
    with tempfile.TemporaryDirectory() as td:
        t=pathlib.Path(td); testcase=t/'testcase.bin'; testcase.write_bytes(b'PVAS_TESTCASE')
        findings=t/'findings.json'
        findings.write_text(json.dumps({'findings':[
            {'id':'FINDING-001','status':'Validated','title':'fixture parsed crash','affected_component':{'package':'toy','component':'parser'},'source_code_evidence':[{'file':'src/parser.c'}],'source_to_sink_path':'file read -> parse -> memcpy','validation':{'command':'cat','testcase':str(testcase),'expected_vulnerable':'vulnerable output','expected_fixed':'fixed output'},'cvss':{},'fix_recommendation':'fix','disclosure_level':'D3-maintainer-private','discovery_method':[{'type':'tool','tool_name':'semgrep','description':'fixture'}],'disclosure_status':'not_found_in_configured_sources'},
            {'id':'FINDING-002','status':'Likely','validation':{'command':'cat','testcase':str(testcase)}}
        ]}))
        out=t/'poc'
        run_tool('tools/generate_poc_testcase.py', ['--findings', str(findings), '--out', str(out)])
        assert (out/'FINDING-001/poc-manifest.json').exists()
        assert not (out/'FINDING-002').exists()
        run_tool('tools/validate_poc_artifacts.py', ['--poc-root', str(out)])
    print('poc testcase generation tests passed')
if __name__=='__main__': main()
