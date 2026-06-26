#!/usr/bin/env python3
import argparse, json, pathlib, re

def add_candidate(cands, cid, title, component, file=None, line=None, evidence=None, score=0):
    loc={'file':file or 'unknown'}
    if line:
        loc['start_line']=int(line); loc['end_line']=int(line)
    cands.append({'id':cid,'type':'T-CAND','status':'Raw Tool Hit','title':title,'component':component,'profile':'unknown','source_locations':[loc],'evidence':evidence or {},'confidence':'low','provisional_severity':'unknown','rank_score':score,'missing_evidence':['source-to-sink','validation'],'disclosure_level':'D0-internal-candidate'})

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--tools-dir', default='audit-output/02-tools/raw'); ap.add_argument('--out', default='audit-output/03-candidates/raw-candidates.json'); args=ap.parse_args()
    raw=pathlib.Path(args.tools_dir); c=[]; n=1
    sem=raw/'semgrep.json'
    if sem.exists():
        try:
            data=json.loads(sem.read_text(errors='ignore') or '{}')
            for r in data.get('results',[])[:200]:
                add_candidate(c, f'T-CAND-{n:04d}', r.get('extra',{}).get('message','Semgrep result'), 'semgrep', r.get('path'), r.get('start',{}).get('line'), {'tool_refs':['semgrep']}, 10); n+=1
        except Exception: pass
    rg=raw/'rg.out'
    if rg.exists():
        for line in rg.read_text(errors='ignore').splitlines()[:300]:
            m=re.match(r'([^:]+):(\d+):(.*)', line)
            if m:
                add_candidate(c, f'T-CAND-{n:04d}', 'Dangerous API or high-risk pattern', 'rg', m.group(1), m.group(2), {'tool_refs':['rg'], 'sink':m.group(3).strip()[:200]}, 5); n+=1
    cpp=raw/'cppcheck.out'
    if cpp.exists():
        for line in cpp.read_text(errors='ignore').splitlines()[:200]:
            m=re.match(r'([^:]+):(\d+):.*?:\s*(.*)', line)
            if m:
                add_candidate(c, f'T-CAND-{n:04d}', m.group(3)[:120] or 'Cppcheck result', 'cppcheck', m.group(1), m.group(2), {'tool_refs':['cppcheck']}, 8); n+=1
    out=pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps({'candidates':c}, indent=2))
if __name__=='__main__': main()
