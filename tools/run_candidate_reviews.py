#!/usr/bin/env python3
"""Execute bounded candidate-review semantics from candidate packets."""
from __future__ import annotations

import argparse
import pathlib
import sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_json, write_json


HIGH_SIGNAL = ("memcpy", "strcpy", "sprintf", "system(", "popen", "free(", "malloc", "realloc", "socket", "unlink")


def decision_for(candidate: dict, packet_text: str) -> tuple[str, list[str]]:
    if "[source unavailable]" in packet_text:
        return "Reject", ["source slice unavailable"]
    lower = packet_text.lower()
    reasons = []
    if any(token in lower for token in HIGH_SIGNAL):
        reasons.append("packet source slice contains high-risk sink token")
    if candidate.get("missing_evidence"):
        reasons.append("candidate still lacks validation evidence")
    if reasons and "source_locations" in candidate:
        return "Candidate", reasons
    return "Reject", reasons or ["insufficient grounded source evidence in packet"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ranked-candidates", required=True)
    ap.add_argument("--packet-dir", required=True)
    ap.add_argument("--review-dir", required=True)
    ap.add_argument("--summary-out", required=True)
    ap.add_argument("--max-candidates", type=int, default=20)
    args = ap.parse_args()

    ranked = load_json(args.ranked_candidates, default={}, required=True)
    candidates = ranked.get("candidates", []) if isinstance(ranked, dict) else []
    packet_dir = pathlib.Path(args.packet_dir)
    review_dir = pathlib.Path(args.review_dir)
    review_dir.mkdir(parents=True, exist_ok=True)
    summary = []
    for candidate in [c for c in candidates[: args.max_candidates] if isinstance(c, dict)]:
        cid = str(candidate.get("id") or "CAND")
        packet = packet_dir / f"{cid}.md"
        packet_text = packet.read_text(errors="ignore") if packet.exists() else "[source unavailable]"
        decision, reasons = decision_for(candidate, packet_text)
        review = {
            "candidate_id": cid,
            "decision": decision,
            "state": decision,
            "reviewer_role": "candidate-reviewer",
            "execution_mode": "deterministic-fresh-task-emulation",
            "packet": str(packet),
            "source_slice_reviewed": packet.exists() and "[source unavailable]" not in packet_text,
            "reasons": reasons,
            "missing_evidence": candidate.get("missing_evidence") or [],
        }
        write_json(review_dir / f"{cid}.json", review)
        summary.append({
            "id": cid,
            "decision": decision,
            "source_slice_reviewed": review["source_slice_reviewed"],
            "reasons": reasons,
        })
    write_json(args.summary_out, {
        "reviewed_count": len(summary),
        "candidates": summary,
        "execution": {
            "role": "candidate-reviewer",
            "mode": "deterministic-fresh-task-emulation",
        },
    })
    print(f"[PVAS-REVIEW] reviewed {len(summary)} candidate packet(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
