#!/usr/bin/env python3
"""Validate local-only PoC/reproducer artifacts."""
from __future__ import annotations
import argparse, json, pathlib, re, sys, hashlib
DENY=[r'\bcurl\b',r'\bwget\b',r'\bnc\b',r'\bnetcat\b',r'\bssh\b',r'\bscp\b',r'\bftp\b',r'\btelnet\b',r'\bsudo\b',r'\bsu\b',r'\bsetcap\b',r'chmod\s+u\+s',r'\|\s*sh\b',r'>\s*/etc/',r'>\s*/usr/',r'>\s*/var/lib/',r'>\s*/root/',r'\b(cp|mv|install)\b[^\n]*(/etc/|/usr/|/var/lib/|/root/)']

def sha256_file(p):
    h=hashlib.sha256();
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(65536), b''): h.update(b)
    return h.hexdigest()

def validate_dir(d: pathlib.Path):
    errs=[]; m=d/'poc-manifest.json'; s=d/'reproduce.sh'; desc=d/'input-description.md'
    if not m.exists(): return [f'{d}: missing poc-manifest.json']
    data=json.loads(m.read_text())
    for k in ['finding_id','status','safety_class','commands','expected_results','artifacts','disclosure_level']:
        if k not in data: errs.append(f'{d}: manifest missing {k}')
    if data.get('status')!='Validated': errs.append(f'{d}: manifest status is not Validated')
    if data.get('safety_class')!='local-validation-only': errs.append(f'{d}: safety_class not local-validation-only')

    # New check: discovery_method_ref must be non-empty
    dmr = data.get('discovery_method_ref', '')
    if not dmr or not dmr.strip():
        errs.append(f'{d}: manifest discovery_method_ref is empty')

    if not s.exists(): errs.append(f'{d}: missing reproduce.sh')
    else:
        txt=s.read_text()
        if 'timeout' not in txt: errs.append(f'{d}: reproduce.sh must use timeout')
        for pat in DENY:
            if re.search(pat, txt): errs.append(f'{d}: unsafe pattern in reproduce.sh: {pat}')

    # New check: input-description.md must exist and contain SHA256 + purpose
    if not desc.exists():
        errs.append(f'{d}: missing input-description.md')
    else:
        desc_text = desc.read_text()
        if 'SHA256' not in desc_text and 'sha256' not in desc_text:
            errs.append(f'{d}: input-description.md missing SHA256')
        if 'Purpose' not in desc_text and 'purpose' not in desc_text.lower():
            errs.append(f'{d}: input-description.md missing purpose')

    t=data.get('testcase',{})
    if t.get('path'):
        tp=d/t['path']
        if not tp.exists(): errs.append(f'{d}: missing testcase {t["path"]}')
        elif t.get('sha256') and sha256_file(tp)!=t['sha256']:
            errs.append(f'{d}: testcase sha256 mismatch')
    er=data.get('expected_results',{})
    if not er.get('vulnerable') or not er.get('fixed'):
        errs.append(f'{d}: expected vulnerable/fixed behavior required')
    return errs

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--poc-root', required=True); args=ap.parse_args()
    root=pathlib.Path(args.poc_root); errs=[]
    for d in sorted([p for p in root.iterdir() if p.is_dir()]): errs.extend(validate_dir(d))
    if errs:
        print('\n'.join(errs), file=sys.stderr); return 2
    print('poc artifact validation passed')
    return 0
if __name__=='__main__': raise SystemExit(main())
