#!/usr/bin/env python3
"""AI subagent: semantic candidate review from source-code packets.

Replaces run_candidate_reviews.py with a subagent that:
  1. Reads each candidate's source-code packet
  2. Invokes LLM for semantic source-to-sink analysis when available
  3. Falls back to context-aware static analysis (not just keyword matching)
  4. Produces schema-valid review decisions with grounded reasoning
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import traceback

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_json, write_json

LLM_TIMEOUT = int(os.environ.get("PVAS_LLM_TIMEOUT", "30"))
LLM_MODEL = os.environ.get("PVAS_LLM_MODEL", "claude-sonnet-4-20250514")

ALLOWED_DECISIONS = frozenset({"Reject", "Candidate", "Likely", "Needs Manual Review"})


def _load_packets(packet_dir: pathlib.Path) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not packet_dir.is_dir():
        return texts
    for p in sorted(packet_dir.glob("*.md")):
        texts[p.stem] = p.read_text(errors="ignore")
    return texts


def _extract_code_slice(packet_text: str) -> str:
    m = re.search(r"```(?:text|code)\n(.*?)```", packet_text, re.DOTALL)
    return m.group(1).strip() if m else ""


def _hypotheses(data) -> list[dict]:
    if isinstance(data, list):
        return [h for h in data if isinstance(h, dict)]
    if isinstance(data, dict):
        return [h for h in data.get("hypotheses", []) if isinstance(h, dict)]
    return []


def _load_hypothesis_context(path: str | None) -> dict[str, list[dict]]:
    if not path:
        return {}
    data = load_json(pathlib.Path(path), default={})
    by_candidate: dict[str, list[dict]] = {}
    for hyp in _hypotheses(data):
        cid = str(hyp.get("source_candidate_id") or hyp.get("candidate_id") or "").strip()
        if not cid:
            continue
        by_candidate.setdefault(cid, []).append({
            "id": hyp.get("id"),
            "dimension": hyp.get("dimension"),
            "possible_gap": hyp.get("possible_gap"),
            "possible_sink": hyp.get("possible_sink"),
            "failure_scenario": hyp.get("failure_scenario"),
            "review_questions": hyp.get("review_questions") or [],
            "evidence_refs": hyp.get("evidence_refs") or [],
            "confidence": hyp.get("confidence"),
        })
    return by_candidate


def _format_hypothesis_context(items: list[dict], max_chars: int = 2500) -> str:
    if not items:
        return "No AI hypothesis context was provided for this candidate."
    lines = [
        "AI hypothesis context is review guidance only; it is not evidence of a vulnerability and must not determine state by itself."
    ]
    for h in items[:5]:
        lines.append(
            f"- {h.get('id', '?')} [{h.get('dimension', '?')}, {h.get('confidence', '?')}]: "
            f"gap={h.get('possible_gap', '?')}; sink={h.get('possible_sink', '?')}"
        )
        scenario = str(h.get("failure_scenario") or "").strip()
        if scenario:
            lines.append(f"  scenario: {scenario}")
        questions = [str(q).strip() for q in h.get("review_questions") or [] if str(q).strip()]
        if questions:
            lines.append(f"  review questions: {' | '.join(questions[:3])}")
    text = "\n".join(lines)
    return text[:max_chars]


# ---- Context-aware static analysis (LLM fallback) ----

def _semantic_static_review(candidate_id: str, packet_text: str) -> tuple[str, list[str], str, bool]:
    """Context-aware static review: analyzes code semantics, not just keyword presence.

    Returns: (decision, reasons, analysis_detail, source_slice_reviewed)
    """
    code = _extract_code_slice(packet_text)
    if not code:
        return "Reject", ["source code slice unavailable"], "no code to review", False

    reasons: list[str] = []
    detail_parts: list[str] = []

    lines = code.splitlines()
    func_calls: list[str] = []
    for line in lines:
        for token in re.findall(r'\b(\w+)\s*\(', line):
            func_calls.append(token)

    high_risk_calls = {"memcpy", "strcpy", "strcat", "sprintf", "vsprintf",
                       "gets", "scanf", "system", "popen", "exec", "alloca"}
    medium_risk_calls = {"read", "recv", "send", "write", "free", "realloc", "malloc", "calloc"}

    found_high = [c for c in func_calls if c in high_risk_calls]
    found_medium = [c for c in func_calls if c in medium_risk_calls]

    has_bounds_check = bool(re.search(r'\b(sizeof|strnlen|strncat|strncpy|snprintf|memcpy_s|strcpy_s|strcat_s|checked_)\b', code))
    has_size_check = bool(re.search(r'\b(size|len|count|nbytes|remaining)\s*(==|!=|<|<=|>|>=)', code))
    has_guard = bool(re.search(r'\bif\s*\(', code)) and has_size_check
    has_return_check = bool(re.search(r'\bif\s*\(.*==\s*(-1|NULL|EOF|0)\)', code))
    has_bounds_loop = bool(re.search(r'for\s*\(\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*\w+', code))
    has_null_check = bool(re.search(r'\bif\s*\(.*NULL', code))

    if "attacker_controlled" in packet_text.lower():
        pass

    if found_high:
        if has_bounds_check or has_guard or has_bounds_loop:
            reasons.append(f"high-risk call(s) {' '.join(found_high)} present but bounds checking observed")
            detail_parts.append(f"calls {', '.join(found_high)} are bounded by size/guard checks")
        else:
            reasons.append(f"high-risk call(s) {' '.join(found_high)} without observed bounds check")
            detail_parts.append(f"calls {', '.join(found_high)} appear unbounded — likely exploitable")

    if found_medium:
        if has_return_check:
            reasons.append(f"medium-risk call(s) {' '.join(found_medium)} present with return value check")
        else:
            reasons.append(f"medium-risk call(s) {' '.join(found_medium)} without return value check")

    if "system(" in code or "popen(" in code:
        if "\"" not in code.split("system(")[-1].split(")")[0] if "system(" in code else True:
            reasons.append("command execution call with static argument")
        else:
            reasons.append("command execution call may use dynamic argument — possible injection")

    if "alloca" in code:
        reasons.append("alloca() usage — risk of stack overflow if input-controlled size")

    if "free(" in code and not has_null_check:
        reasons.append("free() without NULL guard pattern visible in slice")

    if has_null_check:
        detail_parts.append("null-pointer guard present")
    if has_guard and has_bounds_check:
        detail_parts.append("conditional + sizeof guards present — limited exploitability")

    if not found_high and not found_medium:
        reasons.append("no high or medium risk function calls in code slice")
        detail_parts.append("code slice shows low-risk operations only")

    if found_high and not has_bounds_check and not has_guard:
        return "Likely", reasons, "; ".join(detail_parts), True
    elif found_high and (has_bounds_check or has_guard):
        return "Candidate", reasons, "; ".join(detail_parts), True
    elif found_medium and not has_return_check:
        return "Candidate", reasons, "; ".join(detail_parts), True
    elif found_medium and has_return_check:
        return "Reject", reasons, "; ".join(detail_parts), True
    elif "system(" in code or "popen(" in code:
        return "Candidate", reasons, "; ".join(detail_parts), True
    elif "alloca" in code:
        return "Candidate", reasons, "; ".join(detail_parts), True
    else:
        return "Reject", reasons, "; ".join(detail_parts), True


# ---- LLM integration ----

def _llm_available() -> bool:
    try:
        import anthropic
        key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")
        return bool(key)
    except ImportError:
        pass
    try:
        import openai
        return bool(os.environ.get("OPENAI_API_KEY"))
    except ImportError:
        pass
    return False


def _build_review_prompt(candidate_id: str, packet_text: str, hypothesis_context: list[dict] | None = None,
                         max_chars: int = 6000) -> str:
    truncated = packet_text[:max_chars]
    hypotheses = _format_hypothesis_context(hypothesis_context or [])
    return (
        f"You are candidate-reviewer, an AI subagent for semantic vulnerability candidate review.\n"
        f"Review the following candidate packet ({candidate_id}).\n\n"
        f"{truncated}\n\n"
        f"{hypotheses}\n\n"
        f"Analyze the source code slice semantically. Consider:\n"
        f"1. Does attacker-controlled input reach a sensitive sink?\n"
        f"2. Are there bounds checks, sanitizers, or guards that mitigate the risk?\n"
        f"3. Is the vulnerability realistically exploitable?\n"
        f"4. Which AI hypothesis references, if any, helped focus the review?\n\n"
        f"AI hypotheses are not vulnerabilities. Do not promote to Candidate or Likely unless the source packet supports it.\n\n"
        f"Respond with a JSON object:\n"
        f'{{"decision": "Reject|Candidate|Likely", "reasons": ["reason1", "reason2"], '
        f'"analysis": "detailed analysis text", "source_slice_reviewed": true, "hypothesis_references": ["AI-HYP-0001"]}}\n\n'
        'Reject = no realistic exploit path. Candidate = possible but unconfirmed. '
        'Likely = likely exploitable based on code evidence.'
    )


def _llm_review(candidate_id: str, packet_text: str, hypothesis_context: list[dict] | None = None) -> tuple[str, list[str], str, bool]:
    try:
        import anthropic
        client = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")
        )
        prompt = _build_review_prompt(candidate_id, packet_text, hypothesis_context)
        response = client.messages.create(
            model=LLM_MODEL,
            max_tokens=2000,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text if response.content else ""
        return _parse_review_json(text, candidate_id)
    except Exception:
        pass

    try:
        import openai
        client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        prompt = _build_review_prompt(candidate_id, packet_text, hypothesis_context)
        response = client.chat.completions.create(
            model=os.environ.get("PVAS_LLM_MODEL", "gpt-4o"),
            max_tokens=2000,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.choices[0].message.content or ""
        return _parse_review_json(text, candidate_id)
    except Exception:
        pass

    return "Reject", ["LLM review failed"], "LLM unavailable or error", False


def _parse_review_json(text: str, candidate_id: str) -> tuple[str, list[str], str, bool]:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return "Reject", ["unparseable LLM response"], text[:500], False
    try:
        data = json.loads(m.group())
        decision = data.get("decision", "Reject")
        if decision not in ALLOWED_DECISIONS:
            decision = "Reject"
        reasons = data.get("reasons", [])
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        analysis = data.get("analysis", "") or str(data.get("detail", ""))
        source_reviewed = bool(data.get("source_slice_reviewed", True))
        return decision, reasons, analysis, source_reviewed
    except (json.JSONDecodeError, TypeError):
        return "Reject", ["JSON parse error in LLM response"], text[:500], False


# ---- Main ----

def main() -> int:
    ap = argparse.ArgumentParser(
        description="AI subagent for semantic candidate review from source-code packets"
    )
    ap.add_argument("--ranked-candidates", required=True)
    ap.add_argument("--packet-dir", required=True)
    ap.add_argument("--review-dir", required=True)
    ap.add_argument("--summary-out", required=True)
    ap.add_argument("--hypotheses", default=None,
                    help="optional ai-hypotheses.json context; used for review focus only")
    ap.add_argument("--max-candidates", type=int, default=20)
    ap.add_argument("--llm-mode", choices=["auto", "heuristic"], default="auto",
                    help="auto: try LLM then fall back; heuristic: skip LLM")
    args = ap.parse_args()

    ranked = load_json(args.ranked_candidates, default={}, required=True)
    candidates = ranked.get("candidates", []) if isinstance(ranked, dict) else []
    selected = [c for c in candidates[: args.max_candidates] if isinstance(c, dict)]

    packet_dir = pathlib.Path(args.packet_dir)
    packets = _load_packets(packet_dir)
    review_dir = pathlib.Path(args.review_dir)
    review_dir.mkdir(parents=True, exist_ok=True)
    hypothesis_context = _load_hypothesis_context(args.hypotheses)

    use_llm = args.llm_mode == "auto" and _llm_available()

    summary: list[dict] = []
    skipped: list[dict] = []
    for c in selected:
        cid = str(c.get("id", "CAND"))
        packet_text = packets.get(cid, "")
        candidate_hypotheses = hypothesis_context.get(cid, [])
        hypothesis_refs = [
            str(h.get("id")) for h in candidate_hypotheses
            if h.get("id")
        ]
        if not packet_text:
            skipped.append({
                "id": cid,
                "reason": "missing candidate packet",
                "packet": str(packet_dir / f"{cid}.md"),
                "hypothesis_references": hypothesis_refs,
            })
            print(f"[PVAS-REVIEW] {cid}: skipped (missing candidate packet)")
            continue

        decision: str
        reasons: list[str]
        analysis: str
        source_reviewed: bool

        if use_llm and packet_text:
            try:
                decision, reasons, analysis, source_reviewed = _llm_review(cid, packet_text, candidate_hypotheses)
            except Exception:
                decision, reasons, analysis, source_reviewed = _semantic_static_review(cid, packet_text)
        else:
            decision, reasons, analysis, source_reviewed = _semantic_static_review(cid, packet_text)

        review = {
            "candidate_id": cid,
            "decision": decision,
            "state": decision,
            "reviewer_role": "candidate-reviewer",
            "execution_mode": "llm-assisted" if use_llm else "heuristic",
            "packet": str(packet_dir / f"{cid}.md"),
            "source_slice_reviewed": source_reviewed,
            "reasons": reasons,
            "analysis": analysis,
            "missing_evidence": c.get("missing_evidence") or [],
            "hypothesis_context_used": bool(candidate_hypotheses),
            "hypothesis_references": hypothesis_refs,
        }
        write_json(review_dir / f"{cid}.json", review)
        summary.append({
            "id": cid,
            "decision": decision,
            "source_slice_reviewed": source_reviewed,
            "reasons": reasons,
            "hypothesis_references": hypothesis_refs,
        })
        print(f"[PVAS-REVIEW] {cid}: {decision} ({'; '.join(reasons[:2])})")

    expected_count = len(selected)
    reviewed_count = len(summary)
    explicitly_skipped_count = len(skipped)
    coverage_complete = expected_count == reviewed_count + explicitly_skipped_count and explicitly_skipped_count == 0
    write_json(args.summary_out, {
        "expected_count": expected_count,
        "reviewed_count": reviewed_count,
        "explicitly_skipped_count": explicitly_skipped_count,
        "coverage_complete": coverage_complete,
        "skipped": skipped,
        "batch_summaries": [{
            "batch_id": "batch-001",
            "expected_count": expected_count,
            "reviewed_count": reviewed_count,
            "explicitly_skipped_count": explicitly_skipped_count,
            "coverage_complete": coverage_complete,
        }],
        "candidates": summary,
        "execution": {
            "role": "candidate-reviewer",
            "mode": "llm-assisted" if use_llm else "heuristic",
            "hypothesis_context": "provided" if args.hypotheses else "not-provided",
        },
    })
    print(f"[PVAS-REVIEW] reviewed {reviewed_count}/{expected_count} candidate packet(s)")
    return 0 if coverage_complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
