#!/usr/bin/env python3
import json, pathlib, tempfile
from tool_runner import ROOT, run_tool

def main():
    with tempfile.TemporaryDirectory() as td:
        d=pathlib.Path(td)/'poc/FINDING-001'; d.mkdir(parents=True)
        (d/'testcase.bin').write_bytes(b'x')
        (d/'reproduce.sh').write_text('#!/usr/bin/env bash\ntimeout 10s curl http://example.com\n')
        (d/'poc-manifest.json').write_text(json.dumps({'finding_id':'FINDING-001','status':'Validated','poc_type':'local-reproducer','safety_class':'local-validation-only','artifacts':{'testcase':'testcase.bin'},'commands':{'reproduce':'./reproduce.sh'},'expected_results':{'vulnerable':'x','fixed':'y'},'testcase':{'path':'testcase.bin'},'disclosure_level':'D3-maintainer-private'}))
        failed=False
        try:
            run_tool('tools/validate_poc_artifacts.py', ['--poc-root', str(d.parent)])
        except AssertionError as e:
            failed=True
        assert failed
    with tempfile.TemporaryDirectory() as td:
        d=pathlib.Path(td)/'poc/FINDING-002'; d.mkdir(parents=True)
        (d/'reproduce.sh').write_text('#!/usr/bin/env bash\ntimeout 1s true\n')
        (d/'input-description.md').write_text('SHA256: abc\nPurpose: local validation\n')
        (d/'poc-manifest.json').write_text(json.dumps({
            'finding_id':'FINDING-002',
            'status':'draft',
            'poc_type':'generated-reproducer',
            'safety_class':'local-validation-only',
            'discovery_method_ref':'tool(semgrep)',
            'artifacts':{'reproduce_script':'reproduce.sh'},
            'commands':{'reproduce':'./reproduce.sh'},
            'expected_results':{'vulnerable':'x','fixed':'y'},
            'disclosure_level':'D3-maintainer-private',
        }))
        failed=False
        try:
            run_tool('tools/validate_poc_artifacts.py', ['--poc-root', str(d.parent)])
        except AssertionError:
            failed=True
        assert failed
    print('poc safety policy tests passed')
if __name__=='__main__': main()
