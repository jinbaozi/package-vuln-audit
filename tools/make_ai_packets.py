#!/usr/bin/env python3
import argparse, json, math, pathlib

DEFAULT_PACKET_BUDGET=8000
DEFAULT_BATCH_BUDGET=160000
DEFAULT_MAX_PACKETS=20

def est_tokens(text: str) -> int:
    return int(math.ceil(len(text) / 3.5))

def slice_file(path, start, end, max_lines):
    try:
        lines=path.read_text(errors='ignore').splitlines()
    except Exception:
        return '[source unavailable]'
    start=max(1,start); end=min(len(lines),end)
    if end-start+1>max_lines:
        end=start+max_lines-1
    return '\n'.join(f'{i+1}: {lines[i]}' for i in range(start-1,end))

def make_packet_text(c, loc, snippet):
    return f"""# {c.get('id')}: {c.get('title')}

## Status
{c.get('status')}

## Type
{c.get('type')}

## Component
{c.get('component')}

## Source Location
- File: {loc.get('file','unknown')}
- Function: {loc.get('function','unknown')}
- Lines: {loc.get('start_line','unknown')}-{loc.get('end_line','unknown')}

## Evidence
```json
{json.dumps(c.get('evidence',{}), indent=2)}
```

## Missing Evidence
{', '.join(c.get('missing_evidence',[]))}

## Code Slice
```text
{snippet}
```

## Review Contract
Return Reject / Candidate / Likely only. Do not claim Validated without validation evidence.
This packet is scoped for a single subagent invocation; do not request full-repository context.
"""

def batch_packets(entries, batch_budget, max_count):
    batches=[]; cur=[]; cur_tokens=0
    for e in entries:
        tok=e['estimated_tokens']
        if cur and (len(cur)>=max_count or cur_tokens+tok>batch_budget):
            batches.append({'batch_id':f'batch-{len(batches)+1:03d}','packet_count':len(cur),'estimated_tokens':cur_tokens,'packets':[x['id'] for x in cur]})
            cur=[]; cur_tokens=0
        cur.append(e); cur_tokens += tok
    if cur:
        batches.append({'batch_id':f'batch-{len(batches)+1:03d}','packet_count':len(cur),'estimated_tokens':cur_tokens,'packets':[x['id'] for x in cur]})
    return batches

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--candidates', default='audit-output/03-candidates/ranked-candidates.json')
    ap.add_argument('--source-root', default='.')
    ap.add_argument('--out', default='audit-output/03-candidates/packets')
    ap.add_argument('--context-lines', type=int, default=80)
    ap.add_argument('--max-lines', type=int, default=240)
    ap.add_argument('--max-packets', type=int, default=0, help='0 means include all candidates; review batches still limit per invocation')
    ap.add_argument('--packet-token-budget', type=int, default=DEFAULT_PACKET_BUDGET)
    ap.add_argument('--review-batch-token-budget', type=int, default=DEFAULT_BATCH_BUDGET)
    ap.add_argument('--max-packet-count-per-review', type=int, default=DEFAULT_MAX_PACKETS)
    args=ap.parse_args()
    data=json.loads(pathlib.Path(args.candidates).read_text())
    candidates=data.get('candidates',[])
    if args.max_packets and args.max_packets > 0:
        candidates=candidates[:args.max_packets]
    out=pathlib.Path(args.out); out.mkdir(parents=True, exist_ok=True); src=pathlib.Path(args.source_root)
    entries=[]
    for c in candidates:
        loc=(c.get('source_locations') or [{}])[0]
        line=loc.get('start_line') or 1
        fp=src/loc.get('file','')
        max_lines=args.max_lines
        snippet=slice_file(fp, line-args.context_lines, line+args.context_lines, max_lines)
        md=make_packet_text(c, loc, snippet)
        # Reduce code slice if the packet exceeds budget.
        while est_tokens(md) > args.packet_token_budget and max_lines > 40:
            max_lines=max(40, int(max_lines*0.75))
            snippet=slice_file(fp, line-args.context_lines, line+args.context_lines, max_lines)
            md=make_packet_text(c, loc, snippet)
        p=out/f"{c.get('id','CAND')}.md"
        p.write_text(md)
        tokens=est_tokens(md)
        entries.append({'id':c.get('id','CAND'), 'file':str(p), 'estimated_tokens':tokens, 'within_budget':tokens <= args.packet_token_budget, 'source_file':loc.get('file','unknown')})
    batches=batch_packets(entries, args.review_batch_token_budget, args.max_packet_count_per_review)
    index={
        'budget_model':'per-agent-independent-context',
        'packet_budget_tokens': args.packet_token_budget,
        'review_batch_token_budget': args.review_batch_token_budget,
        'max_packet_count_per_review': args.max_packet_count_per_review,
        'packets': entries,
        'batches': batches,
        'total_estimated_tokens': sum(e['estimated_tokens'] for e in entries),
        'max_single_batch_tokens': max([b['estimated_tokens'] for b in batches] or [0]),
        'merge_rule': 'summary-only; rejected details do not re-enter coordinator context'
    }
    (out/'packet-index.json').write_text(json.dumps(index, indent=2))
if __name__=='__main__': main()
