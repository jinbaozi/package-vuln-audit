#!/usr/bin/env python3
"""Validate bilingual output separation and invariant consistency."""
from __future__ import annotations
import argparse, json, pathlib, re, sys
CJK=re.compile(r'[\u4e00-\u9fff]')
WORD=re.compile(r'[A-Za-z]{3,}')
CODE_BLOCK=re.compile(r'```.*?```', re.S)
INLINE_CODE=re.compile(r'`[^`]+`')
ID_PAT=re.compile(r'\b(CVE-\d{4}-\d+|GHSA-[A-Za-z0-9-]+|OSV-[A-Za-z0-9-]+|CVSS:[0-9.]+/[^\s]+|[A-Za-z0-9_./+-]+\.(c|h|cpp|md|json|sh))\b')

def natural_text(s):
    s=CODE_BLOCK.sub('',s); s=INLINE_CODE.sub('',s); s=ID_PAT.sub('',s)
    return s

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--audit-output', default='audit-output'); args=ap.parse_args()
    root=pathlib.Path(args.audit_output); bm_path=root/'machine'/'bilingual-map.json'
    if not bm_path.exists():
        print('missing bilingual-map.json', file=sys.stderr); return 2
    bm=json.loads(bm_path.read_text())
    errors=[]
    for pair in bm.get('pairs',[]):
        for k in ['zh','en']:
            if not (root/pair[k]).exists(): errors.append(f"missing {k}: {pair[k]}")
        zh=(root/pair['zh']).read_text() if (root/pair['zh']).exists() else ''
        en=(root/pair['en']).read_text() if (root/pair['en']).exists() else ''
        zhn=natural_text(zh); enn=natural_text(en)
        if len(CJK.findall(zhn)) < 5: errors.append(f"zh-CN output lacks Chinese prose: {pair['id']}")
        if len(CJK.findall(enn)) > 10: errors.append(f"en-US output contains too much CJK prose: {pair['id']}")
    if errors:
        print('\n'.join(errors), file=sys.stderr); return 3
    print('language output validation passed')
    return 0
if __name__=='__main__': raise SystemExit(main())
