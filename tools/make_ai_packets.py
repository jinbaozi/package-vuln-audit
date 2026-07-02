#!/usr/bin/env python3
import argparse, json, os, pathlib, sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from budget_common import est_tokens, batch_packets
from pvas_io import write_json

DEFAULT_PACKET_BUDGET=8000
DEFAULT_BATCH_BUDGET=160000
DEFAULT_MAX_PACKETS=20

def slice_file(path, start, end, max_lines, line_cache=None):
    try:
        p = pathlib.Path(path)
        start = max(1, start)
        end = min(end, start + max_lines - 1)
        lines = []
        with p.open(errors='ignore') as fh:
            for i, line in enumerate(fh, start=1):
                if i < start:
                    continue
                if i > end:
                    break
                lines.append(f'{i}: {line.rstrip()}')
        return '\n'.join(lines) if lines else '[source unavailable]'
    except Exception as e:
        print(f'[PVAS-TOOL] Warning: failed to slice {path}: {e}', file=sys.stderr)
        return '[source unavailable]'

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
    strict_budget=os.environ.get('PVAS_PACKET_STRICT_BUDGET','1').lower() not in {'0','false','no','off'}
    data=json.loads(pathlib.Path(args.candidates).read_text())
    candidates=data.get('candidates',[])
    if args.max_packets and args.max_packets > 0:
        candidates=candidates[:args.max_packets]
    out=pathlib.Path(args.out); out.mkdir(parents=True, exist_ok=True); src=pathlib.Path(args.source_root)
    entries=[]
    slice_cache={}
    slice_ids={}
    blocked_count=0
    for c in candidates:
        loc=(c.get('source_locations') or [{}])[0]
        line=loc.get('start_line') or 1
        fp=src/loc.get('file','')
        max_lines=args.max_lines
        slice_start=line-args.context_lines
        slice_end=line+args.context_lines
        slice_key=(str(fp), slice_start, slice_end)
        def cached_slice(lines):
            cache_key=slice_key+(lines,)
            if cache_key not in slice_cache:
                slice_cache[cache_key]=slice_file(fp, slice_start, slice_end, lines)
            return slice_cache[cache_key]
        if slice_key not in slice_ids:
            slice_ids[slice_key]=f"slice-{len(slice_ids)+1:04d}"
        snippet=cached_slice(max_lines)
        md=make_packet_text(c, loc, snippet)
        # Reduce code slice if the packet exceeds budget.
        while est_tokens(md) > args.packet_token_budget and max_lines > 40:
            max_lines=max(40, int(max_lines*0.75))
            snippet=cached_slice(max_lines)
            md=make_packet_text(c, loc, snippet)
        tokens=est_tokens(md)
        p=out/f"{c.get('id','CAND')}.md"
        entry={'id':c.get('id','CAND'), 'file':str(p), 'estimated_tokens':tokens, 'within_budget':tokens <= args.packet_token_budget, 'source_file':loc.get('file','unknown'), 'slice_ref': slice_ids[slice_key]}
        if tokens > args.packet_token_budget and strict_budget:
            blocked_count += 1
            entry.update({
                'status':'blocked-recovery-required',
                'reason':'strict budget exceeded after source-slice reduction; split packet or reduce non-source evidence',
            })
        else:
            p.write_text(md)
            entry['status']='ready'
        entries.append(entry)
    reviewable=[e for e in entries if e.get('status') == 'ready']
    batches=batch_packets(reviewable, args.review_batch_token_budget, args.max_packet_count_per_review)
    coverage_complete=blocked_count == 0 and len(reviewable) == len(candidates)
    index={
        'budget_model':'per-agent-independent-context',
        'packet_budget_tokens': args.packet_token_budget,
        'review_batch_token_budget': args.review_batch_token_budget,
        'max_packet_count_per_review': args.max_packet_count_per_review,
        'expected_candidate_count': len(candidates),
        'packet_count': len(reviewable),
        'blocked_packet_count': blocked_count,
        'batch_count': len(batches),
        'deduplicated_slice_count': len(slice_ids),
        'coverage_complete': coverage_complete,
        'packets': entries,
        'batches': batches,
        'total_estimated_tokens': sum(e['estimated_tokens'] for e in reviewable),
        'max_single_batch_tokens': max([b['estimated_tokens'] for b in batches] or [0]),
        'merge_rule': 'summary-only; rejected details do not re-enter coordinator context'
    }
    write_json(out / 'packet-index.json', index)
    return 2 if blocked_count else 0
if __name__=='__main__': raise SystemExit(main())
