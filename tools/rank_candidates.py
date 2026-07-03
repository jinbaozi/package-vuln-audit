#!/usr/bin/env python3
import argparse, json, pathlib, sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_json, write_json

HIGH=['parser','parse','read','elf','dwarf','archive','bfd','crypto','auth','priv','setuid','network','socket','decode','compress']
SINK=['memcpy','strcpy','sprintf','free','system','popen','open','unlink','malloc','realloc','offset','size','count','length']


def _evidence(c):
    ev = c.get('evidence')
    return ev if isinstance(ev, dict) else {}


def _locations(c):
    locs = c.get('source_locations')
    return locs if isinstance(locs, list) else []


def _admission_policy(c):
    ev = _evidence(c)
    return str(c.get('admission_policy') or ev.get('admission_policy') or 'candidate_evidence_allowed')


def is_admissible(c):
    return _admission_policy(c) != 'not_admissible'


def score_breakdown(c):
    text=json.dumps(c).lower()
    ev = _evidence(c)
    tool_refs = ev.get('tool_refs') if isinstance(ev.get('tool_refs'), list) else []
    tool_weight = 0
    if 'semgrep' in tool_refs:
        tool_weight += 8
    if 'cppcheck' in tool_refs:
        tool_weight += 6
    if c.get('type')=='A-CAND':
        tool_weight += 4
    if c.get('type')=='F-CAND':
        tool_weight += 8
    sink_weight = sum(3 for k in SINK if k in text)
    profile_relevance = sum(4 for k in HIGH if k in text)
    locs = _locations(c)
    source_location_quality = 0
    if locs:
        source_location_quality += 4
        if any(isinstance(l, dict) and l.get('start_line') for l in locs):
            source_location_quality += 3
    test_vendor_penalty = -6 if any(x in text for x in ('test/', '/tests/', 'tests/', 'vendor/', '/vendor/', 'third_party/')) else 0
    admission = _admission_policy(c)
    coverage_admission_penalty = -12 if admission == 'manual_review_only' else -4 if admission == 'positive_only' else 0
    return {
        'base_score': float(c.get('rank_score',0)),
        'tool_weight': tool_weight,
        'sink_weight': sink_weight,
        'profile_relevance': profile_relevance,
        'source_location_quality': source_location_quality,
        'test_vendor_penalty': test_vendor_penalty,
        'coverage_admission_penalty': coverage_admission_penalty,
    }


def score(c):
    parts = score_breakdown(c)
    return sum(float(v) for v in parts.values())

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--input', default='audit-output/03-candidates/raw-candidates.json'); ap.add_argument('--out', default='audit-output/03-candidates/ranked-candidates.json'); ap.add_argument('--top', type=int, default=20); args=ap.parse_args()
    data=load_json(args.input, default={}, required=True); c=[x for x in data.get('candidates', []) if is_admissible(x)]
    for x in c:
        x['score_breakdown']=score_breakdown(x)
        x['rank_score']=score(x)
    c=sorted(c, key=lambda x:x['rank_score'], reverse=True)[:args.top]
    write_json(args.out, {'candidates': c})
if __name__=='__main__': main()
