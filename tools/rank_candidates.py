#!/usr/bin/env python3
import argparse, json, pathlib
HIGH=['parser','parse','read','elf','dwarf','archive','bfd','crypto','auth','priv','setuid','network','socket','decode','compress']
SINK=['memcpy','strcpy','sprintf','free','system','popen','open','unlink','malloc','realloc','offset','size','count','length']
def score(c):
    s=float(c.get('rank_score',0)); text=json.dumps(c).lower()
    s += sum(4 for k in HIGH if k in text)
    s += sum(3 for k in SINK if k in text)
    if c.get('type')=='A-CAND': s += 4
    if c.get('type')=='F-CAND': s += 8
    if 'test/' in text or '/tests/' in text: s -= 6
    return s

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--input', default='audit-output/03-candidates/raw-candidates.json'); ap.add_argument('--out', default='audit-output/03-candidates/ranked-candidates.json'); ap.add_argument('--top', type=int, default=20); args=ap.parse_args()
    data=json.loads(pathlib.Path(args.input).read_text()); c=data.get('candidates', [])
    for x in c: x['rank_score']=score(x)
    c=sorted(c, key=lambda x:x['rank_score'], reverse=True)[:args.top]
    pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True); pathlib.Path(args.out).write_text(json.dumps({'candidates':c}, indent=2))
if __name__=='__main__': main()
