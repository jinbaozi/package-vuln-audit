#!/usr/bin/env python3
"""Generate grounded AI-hypothesis artifacts from ranked candidates and scope."""
from __future__ import annotations

import argparse
import pathlib
import sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_json, write_json


def _first_location(candidate: dict) -> dict:
    locs = candidate.get("source_locations") if isinstance(candidate.get("source_locations"), list) else []
    return locs[0] if locs and isinstance(locs[0], dict) else {}


def _confidence(candidate: dict) -> str:
    score = float(candidate.get("rank_score") or 0)
    if score >= 20:
        return "high"
    if score >= 8:
        return "medium"
    return "low"


def hypothesis_from_candidate(candidate: dict, index: int) -> dict:
    loc = _first_location(candidate)
    component = str(candidate.get("component") or loc.get("file") or "selected component")
    evidence = candidate.get("evidence") if isinstance(candidate.get("evidence"), dict) else {}
    sink = evidence.get("sink") or candidate.get("title") or "candidate sink"
    missing = candidate.get("missing_evidence") or []
    return {
        "id": f"AI-HYP-{index:04d}",
        "profile": str(candidate.get("profile") or "selected-scope"),
        "component": component,
        "assumption": f"Candidate {candidate.get('id')} may rely on unchecked input assumptions in {component}.",
        "attacker_controlled_input": str(loc.get("file") or "package input surface from selected scope"),
        "possible_gap": ", ".join(map(str, missing)) if missing else "needs source-to-sink review",
        "possible_sink": str(sink),
        "validation_method": "candidate-reviewer source-slice review followed by validator local reproduction or static refutation",
        "confidence": _confidence(candidate),
        "source_candidate_id": str(candidate.get("id") or ""),
    }


def fallback_hypothesis(scope: dict) -> dict:
    recipes = scope.get("selected_recipes") if isinstance(scope.get("selected_recipes"), list) else []
    component = recipes[0] if recipes else "selected audit scope"
    return {
        "id": "AI-HYP-0001",
        "profile": "selected-scope",
        "component": str(component),
        "assumption": "The selected audit scope may contain input parsing or trust-boundary assumptions not covered by traditional tools.",
        "attacker_controlled_input": "package inputs identified during scope selection",
        "possible_gap": "traditional tools produced no ranked candidate for this scope",
        "possible_sink": "scope-dependent parser, decoder, filesystem, process, or memory operation",
        "validation_method": "bounded source-slice review before any vulnerability claim",
        "confidence": "low",
        "source_candidate_id": "",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ranked-candidates", required=True)
    ap.add_argument("--selected-scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-candidates", type=int, default=20)
    args = ap.parse_args()

    ranked = load_json(args.ranked_candidates, default={}, required=True)
    scope = load_json(args.selected_scope, default={}, required=True)
    candidates = ranked.get("candidates", []) if isinstance(ranked, dict) else []
    selected = [c for c in candidates[: args.max_candidates] if isinstance(c, dict)]
    hypotheses = [hypothesis_from_candidate(c, i + 1) for i, c in enumerate(selected)]
    if not hypotheses:
        hypotheses = [fallback_hypothesis(scope if isinstance(scope, dict) else {})]
    out = pathlib.Path(args.out)
    write_json(out, {
        "hypotheses": hypotheses,
        "execution": {
            "role": "hypothesis-hunter",
            "mode": "deterministic-fresh-task-emulation",
            "input_candidates": len(selected),
        },
    })
    print(f"[PVAS-AI-HYP] generated {len(hypotheses)} hypothesis artifact(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
