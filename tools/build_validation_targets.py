#!/usr/bin/env python3
"""Build validation targets from Likely candidate-review decisions."""
from __future__ import annotations

import argparse
import pathlib
import sys
from datetime import datetime, timezone

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_json, write_json


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _items(data: object, key: str) -> list[dict]:
    if isinstance(data, dict):
        value = data.get(key) or []
        return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def _candidate_id(item: dict) -> str:
    return str(item.get('id') or item.get('candidate_id') or '').strip()


def _decision(item: dict) -> str:
    return str(item.get('status') or item.get('decision') or item.get('state') or '').strip()


def _review_files(review_dir: pathlib.Path) -> dict[str, dict]:
    reviews: dict[str, dict] = {}
    if not review_dir.is_dir():
        return reviews
    for path in sorted(review_dir.glob('*.json')):
        data = load_json(path, default={})
        if isinstance(data, dict):
            cid = _candidate_id(data) or path.stem
            reviews[cid] = data
    return reviews


def _source_code_evidence(candidate: dict) -> list[dict]:
    evidence = []
    for loc in candidate.get('source_locations') or []:
        if not isinstance(loc, dict):
            continue
        row = {'file': str(loc.get('file') or 'unknown')}
        for src_key, dst_key in [('function', 'function'), ('start_line', 'start_line'), ('end_line', 'end_line')]:
            if loc.get(src_key) is not None:
                row[dst_key] = loc[src_key]
        evidence.append(row)
    return evidence or [{'file': 'unknown'}]


def _tool_name(candidate: dict) -> str:
    evidence = candidate.get('evidence') if isinstance(candidate.get('evidence'), dict) else {}
    refs = evidence.get('tool_refs') if isinstance(evidence, dict) else []
    if isinstance(refs, list) and refs:
        return str(refs[0])
    return str(candidate.get('component') or 'candidate-review')


def _target_from(candidate: dict, review: dict, packet_dir: pathlib.Path) -> dict:
    cid = _candidate_id(candidate) or _candidate_id(review)
    title = str(review.get('title') or candidate.get('title') or cid)
    analysis = str(review.get('analysis') or '')
    reasons = review.get('reasons') if isinstance(review.get('reasons'), list) else []
    source_to_sink = (
        candidate.get('source_to_sink_path')
        or analysis
        or '; '.join(str(r) for r in reasons)
        or 'validation target from Likely candidate review; source-to-sink path requires validation'
    )
    return {
        'id': cid,
        'status': 'Likely',
        'title': title,
        'summary': title,
        'affected_component': {
            'package': str(candidate.get('package') or 'unknown'),
            'component': str(candidate.get('component') or 'unknown'),
        },
        'source_code_evidence': _source_code_evidence(candidate),
        'source_to_sink_path': str(source_to_sink),
        'validation': {'method': 'pending-validation'},
        'cvss': candidate.get('cvss') if isinstance(candidate.get('cvss'), dict) else {},
        'fix_recommendation': str(candidate.get('fix_recommendation') or 'Validate the source-to-sink path and add an appropriate regression test before remediation.'),
        'discovery_method': [{
            'type': 'tool',
            'tool_name': _tool_name(candidate),
            'description': 'Promoted by candidate review for validation.',
        }],
        'disclosure_status': 'unknown',
        'disclosure_level': 'D1-internal-likely',
        'packet_ref': str(packet_dir / f'{cid}.md'),
        'candidate_ref': cid,
        'review_ref': review.get('packet') or str(packet_dir / f'{cid}.md'),
    }


def build_targets(ranked: dict, candidate_summary: dict, reviews: dict[str, dict], packet_dir: pathlib.Path) -> dict:
    ranked_by_id = {_candidate_id(c): c for c in _items(ranked, 'candidates') if _candidate_id(c)}
    summary_items = _items(candidate_summary, 'candidates')
    targets: list[dict] = []
    rejected: list[dict] = []
    for item in summary_items:
        cid = _candidate_id(item)
        decision = _decision(item)
        review = reviews.get(cid, {})
        review_decision = _decision(review)
        effective = review_decision or decision
        if effective == 'Likely':
            candidate = dict(ranked_by_id.get(cid) or {})
            candidate.update({k: v for k, v in item.items() if k not in candidate})
            targets.append(_target_from(candidate, review or item, packet_dir))
        elif effective in {'Reject', 'Rejected'}:
            rejected.append({
                'id': cid,
                'status': 'Rejected',
                'reason': '; '.join(str(r) for r in (review.get('reasons') or item.get('reasons') or [])) if isinstance(review or item, dict) else '',
            })
    return {
        'schema_version': '1.0',
        'targets': targets,
        'rejected_summary': rejected,
        'generated_at': _iso_now(),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--ranked-candidates', required=True)
    ap.add_argument('--candidate-summary', required=True)
    ap.add_argument('--review-dir', required=True)
    ap.add_argument('--packet-dir', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    payload = build_targets(
        load_json(args.ranked_candidates, default={}, required=True),
        load_json(args.candidate_summary, default={}, required=True),
        _review_files(pathlib.Path(args.review_dir)),
        pathlib.Path(args.packet_dir),
    )
    payload['candidate_summary_ref'] = str(args.candidate_summary)
    payload['validation_summary_ref'] = str(pathlib.Path(args.out).parent / 'validation-summary.json')
    write_json(args.out, payload)
    print(f"[PVAS-VALIDATION-TARGETS] wrote {args.out} ({len(payload['targets'])} target(s))")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
