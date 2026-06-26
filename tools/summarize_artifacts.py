#!/usr/bin/env python3
import argparse, json, pathlib

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--audit-output', default='audit-output'); ap.add_argument('--out', default='audit-output/summary.json'); args=ap.parse_args()
    root=pathlib.Path(args.audit_output); summary={'profiles':[], 'tool_summaries':[], 'candidate_files':[], 'validation_results':[], 'findings':[]}
    for p in root.rglob('*.json'):
        rel=str(p)
        if 'package-profile' in p.name: summary['profiles'].append(rel)
        elif 'tool-summary' in p.name: summary['tool_summaries'].append(rel)
        elif 'candidate' in p.name or 'candidates' in p.name: summary['candidate_files'].append(rel)
        elif 'validation-result' in p.name: summary['validation_results'].append(rel)
        elif 'finding' in p.name: summary['findings'].append(rel)
    pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True); pathlib.Path(args.out).write_text(json.dumps(summary, indent=2))
if __name__=='__main__': main()
