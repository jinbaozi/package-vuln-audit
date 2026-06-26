#!/usr/bin/env python3
import json, pathlib, tempfile
from tool_runner import ROOT, run_tool

def main():
    with tempfile.TemporaryDirectory() as td:
        t=pathlib.Path(td)
        findings=t/'findings.json'
        findings.write_text(json.dumps({'findings':[
            {'id':'FINDING-001','status':'Validated','title':'readelf relocation crash','summary':'missing bounds check relocation sh_link','affected_component':{'package':'binutils','component':'readelf','version_or_commit':'2.44'},'source_code_evidence':[{'file':'binutils/readelf.c','function':'display_relocations'}],'source_to_sink_path':'readelf input -> sh_link -> out-of-bounds read','root_cause':'missing bounds check relocation sh_link','security_impact':'crash out-of-bounds read','validation':{},'cvss':{},'fix_recommendation':'add bounds check','disclosure_level':'D3-maintainer-private','discovery_method':[{'type':'manual','description':'fixture'}],'disclosure_status':'publicly_disclosed'},
            {'id':'FINDING-002','status':'Validated','title':'different','summary':'different parser issue','affected_component':{'package':'binutils','component':'objdump'},'source_code_evidence':[{'file':'binutils/objdump.c','function':'x'}],'source_to_sink_path':'input -> objdump -> crash','root_cause':'different issue','validation':{},'cvss':{},'fix_recommendation':'fix','disclosure_level':'D3-maintainer-private','discovery_method':[{'type':'manual','description':'fixture'}],'disclosure_status':'not_found_in_configured_sources'}]}))
        raw=t/'raw.json'; raw.write_text(json.dumps([
            {'source':'NVD','id':'CVE-2026-0001','aliases':['GHSA-abcd-1234'], 'summary':'binutils readelf missing bounds check relocation sh_link crash', 'package':'binutils','component':'readelf','affected_versions':['2.44'],'files':['binutils/readelf.c'],'functions':['display_relocations'],'root_cause':'missing bounds check relocation sh_link','references':['https://nvd.nist.gov/vuln/detail/CVE-2026-0001']},
            {'source':'OSV','id':'OSV-2026-0002','summary':'binutils objdump crash','package':'binutils','component':'objdump','impact':['crash'],'references':['https://osv.dev/vulnerability/OSV-2026-0002']}
        ]))
        norm=t/'records.json'; corr=t/'corr.json'
        run_tool('tools/normalize_public_vuln_records.py', ['--input', str(raw), '--out', str(norm)])
        run_tool('tools/correlate_public_vulns.py', ['--findings', str(findings), '--records', str(norm), '--out', str(corr)])
        data=json.loads(corr.read_text()); byid={c['finding_id']:c for c in data['correlations']}
        assert byid['FINDING-001']['status']=='publicly_disclosed'
        assert byid['FINDING-001']['match_level']=='M3'
        # FINDING-002 should not be incorrectly promoted by weak/partial evidence
        assert byid['FINDING-002']['status'] in {'possibly_public','not_found_in_configured_sources'}
        assert byid['FINDING-002']['match_level'] != 'M3'
    print('public vulnerability correlation tests passed')
if __name__=='__main__': main()
