#!/usr/bin/env python3
"""Generate local-only PoC/reproducer artifacts for Validated findings."""
from __future__ import annotations
import argparse, json, pathlib, hashlib, shutil, os, platform, stat, sys

def load_findings(p):
    data=json.loads(pathlib.Path(p).read_text())
    if isinstance(data,list): return data
    if 'findings' in data: return data['findings']
    if 'id' in data: return [data]
    return []

def sha256_file(p):
    h=hashlib.sha256();
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(65536), b''): h.update(b)
    return h.hexdigest()

def get_testcase(f, explicit):
    if explicit: return pathlib.Path(explicit)
    val=f.get('validation',{}) if isinstance(f.get('validation'),dict) else {}
    for k in ['testcase','input','reproducer','testcase_path']:
        if val.get(k): return pathlib.Path(val[k])
    return None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--findings', required=True)
    ap.add_argument('--finding-id')
    ap.add_argument('--testcase')
    ap.add_argument('--out', default='audit-output/machine/poc-tests')
    ap.add_argument('--build-command', default='')
    ap.add_argument('--reproduce-command', default='')
    args=ap.parse_args()
    findings=load_findings(args.findings)
    outroot=pathlib.Path(args.out); outroot.mkdir(parents=True, exist_ok=True)
    generated=[]; skipped=[]
    for f in findings:
        fid=f.get('id','FINDING-UNKNOWN')
        if args.finding_id and fid != args.finding_id: continue
        if f.get('status') != 'Validated':
            skipped.append({'id':fid,'reason':'status-not-Validated'}); continue
        val=f.get('validation',{}) if isinstance(f.get('validation'),dict) else {}
        if not val:
            skipped.append({'id':fid,'reason':'missing-validation-evidence'}); continue
        testcase=get_testcase(f,args.testcase)
        if testcase is None or not testcase.exists():
            skipped.append({'id':fid,'reason':'missing-testcase-artifact'}); continue
        d=outroot/fid; d.mkdir(parents=True, exist_ok=True)
        dst=d/testcase.name; shutil.copyfile(testcase,dst)
        t_sha=sha256_file(dst)
        build=args.build_command or val.get('build_command') or '# Build the affected target with sanitizer/instrumentation as documented in the finding.'
        repro=args.reproduce_command or val.get('command') or './reproduce.sh'
        script=d/'reproduce.sh'
        script.write_text(f'''#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
TESTCASE="${{TESTCASE:-{dst.name}}}"
TIMEOUT="${{TIMEOUT:-10s}}"
# Local validation only. Do not use against third-party systems.
timeout "$TIMEOUT" {repro} "$TESTCASE"
''')
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        (d/'expected-vulnerable.txt').write_text(val.get('expected_vulnerable') or 'Vulnerable build triggers the validation signal described in the finding, such as ASan/UBSan/crash/assertion/incorrect output.\n')
        (d/'expected-fixed.txt').write_text(val.get('expected_fixed') or 'Fixed build rejects or handles the testcase without sanitizer errors, crash, assertion, or incorrect output.\n')
        (d/'input-description.md').write_text(f'# Testcase Input\n\n- File: `{dst.name}`\n- SHA256: `{t_sha}`\n- Purpose: local authorized validation and regression testing only.\n')
        manifest={
            'finding_id':fid,'status':'Validated','poc_type':'local-reproducer','safety_class':'local-validation-only',
            'affected_component':f.get('affected_component',{}),
            'artifacts':{'reproduce_script':'reproduce.sh','testcase':dst.name,'expected_vulnerable':'expected-vulnerable.txt','expected_fixed':'expected-fixed.txt'},
            'commands':{'build':build,'reproduce':'./reproduce.sh','regression':'./reproduce.sh'},
            'expected_results':{'vulnerable':(d/'expected-vulnerable.txt').read_text().strip(),'fixed':(d/'expected-fixed.txt').read_text().strip()},
            'environment':{'os':platform.platform(),'arch':platform.machine(),'python':platform.python_version(),'commit':f.get('affected_component',{}).get('version_or_commit','')},
            'testcase':{'path':dst.name,'sha256':t_sha,'size_bytes':dst.stat().st_size,'source':'existing-validation-artifact'},
            'disclosure_level':f.get('disclosure_level','D3-maintainer-private'),'public_release_allowed':False
        }
        (d/'poc-manifest.json').write_text(json.dumps(manifest,indent=2))
        generated.append(str(d))
    summary={'generated':generated,'skipped':skipped}
    (outroot/'poc-generation-summary.json').write_text(json.dumps(summary, indent=2))
    print(f'[PVAS-POC] generated {len(generated)} PoC testcase package(s)')
    return 0 if generated or skipped else 1
if __name__=='__main__': raise SystemExit(main())
