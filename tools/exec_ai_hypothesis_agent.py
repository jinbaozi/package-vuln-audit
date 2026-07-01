#!/usr/bin/env python3
"""AI subagent: grounded hypothesis generation from source-code packets.

Replaces generate_ai_hypotheses.py with a subagent that:
  1. Reads each candidate's source-code packet (with code slices)
  2. Invokes LLM (Claude/OpenAI) for semantic analysis when available
  3. Falls back to structured heuristic code analysis
  4. Produces schema-valid hypotheses with specific code references
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


def _extract_source_location(packet_text: str) -> dict[str, str]:
    loc: dict[str, str] = {}
    for line in packet_text.splitlines():
        line_s = line.strip()
        if line_s.startswith("- File:"):
            loc["file"] = line_s.split(":", 1)[1].strip()
        elif line_s.startswith("- Function:"):
            loc["function"] = line_s.split(":", 1)[1].strip()
        elif line_s.startswith("- Lines:"):
            loc["lines"] = line_s.split(":", 1)[1].strip()
    return loc


def _extract_title_and_id(packet_text: str) -> tuple[str, str]:
    first = packet_text.splitlines()[0] if packet_text else ""
    title = first.lstrip("# ").strip() if first.startswith("#") else ""
    parts = title.split(":", 1)
    cid = parts[0].strip() if parts else "CAND"
    ctitle = parts[1].strip() if len(parts) > 1 else title
    return cid, ctitle


def _high_risk_patterns(code: str) -> list[str]:
    patterns = []
    risk_tokens = {
        "memcpy": "unbounded memcpy may overflow destination buffer",
        "strcpy": "unbounded strcpy may overflow destination buffer",
        "sprintf": "unbounded sprintf may overflow buffer",
        "vsprintf": "unbounded vsprintf may overflow buffer",
        "scanf": "unbounded scanf may overflow buffer",
        "gets(": "gets() has no bounds checking",
        "read(": "read() without size validation may underflow",
        "system(": "system() call may allow command injection",
        "popen": "popen() call may allow command injection",
        "alloca": "alloca() may cause stack overflow",
    }
    for token, desc in risk_tokens.items():
        if token in code:
            patterns.append(desc)
    return patterns


def _check_sanitization(code: str) -> list[str]:
    sanitizers = []
    safe_patterns = [
        (r"sizeof\s*\([^)]*\)", "uses sizeof for bounds"),
        (r"snprintf", "uses bounded snprintf"),
        (r"strncpy", "uses bounded strncpy"),
        (r"strncat", "uses bounded strncat"),
        (r"memcpy_s", "uses safe memcpy_s"),
        (r"strcpy_s", "uses safe strcpy_s"),
        (r"n < sizeof", "explicit bounds check"),
        (r"len\s*<\s*sizeof", "length vs size check"),
        (r"if\s*\(.*size", "conditional size guard"),
    ]
    for pat, desc in safe_patterns:
        if re.search(pat, code):
            sanitizers.append(desc)
    return sanitizers


def _heuristic_hypothesis(candidate: dict, packet_text: str, index: int) -> dict:
    cid = str(candidate.get("id", f"CAND-{index:04d}"))
    code = _extract_code_slice(packet_text)
    loc = _extract_source_location(packet_text)
    _, title = _extract_title_and_id(packet_text)
    risks = _high_risk_patterns(code)
    sanitizers = _check_sanitization(code)
    component = loc.get("file", str(candidate.get("component", "unknown")))
    func = loc.get("function", "unknown")
    file_path = loc.get("file", "unknown")

    if not code:
        return {
            "id": f"AI-HYP-{index:04d}",
            "profile": str(candidate.get("profile", "selected-scope")),
            "component": component,
            "assumption": (
                f"Candidate {cid} may rely on unchecked input assumptions "
                f"in {file_path}:{loc.get('lines', '?')} (source code unavailable)."
            ),
            "attacker_controlled_input": f"package input surface reaching {file_path}",
            "possible_gap": "needs source-to-sink review (no code slice available)",
            "possible_sink": f"{func} in {file_path}" if func != "unknown" else "scope-dependent parser or memory operation",
            "validation_method": "candidate-reviewer source-slice review followed by local reproduction",
            "confidence": "low",
            "candidate_id": cid,
            "source_candidate_id": cid,
        }

    evidence_parts: list[str] = []
    if risks:
        evidence_parts.extend(risks)
    if sanitizers:
        evidence_parts.append(f"mitigation observed: {'; '.join(sanitizers)}")
    evidence_str = "; ".join(evidence_parts) if evidence_parts else "observed code paths require manual sink-to-source review"

    gap_parts: list[str] = []
    if risks:
        gap_parts.append(f"risk pattern(s) detected: {'; '.join(risks)}")
    if sanitizers:
        gap_parts.append(f"partial sanitization present but coverage unverified")
    if not risks and not sanitizers:
        gap_parts.append("no obvious unsafe pattern in slice; needs full source-to-sink analysis")
    possible_gap = "; ".join(gap_parts)

    confidence = "high" if risks and not sanitizers else "medium" if risks else "low"
    possible_sink = f"{func} in {file_path}" if func != "unknown" else f"parsing or memory operation in {file_path}"

    return {
        "id": f"AI-HYP-{index:04d}",
        "profile": str(candidate.get("profile", "selected-scope")),
        "component": component,
        "assumption": (
            f"Candidate {cid}: {title} in {file_path}:{loc.get('lines', '?')} "
            f"({func}) may allow attacker-controlled input to reach unsafe operations "
            f"without adequate validation. Evidence: {evidence_str}"
        ),
        "attacker_controlled_input": f"input surface reaching {file_path} via {func}",
        "possible_gap": possible_gap,
        "possible_sink": possible_sink,
        "validation_method": "candidate-reviewer source-slice review followed by validator local reproduction or static refutation",
        "confidence": confidence,
        "candidate_id": cid,
        "source_candidate_id": cid,
    }


def _llm_available() -> bool:
    try:
        import anthropic  # noqa: F401
        key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")
        return bool(key)
    except ImportError:
        pass
    try:
        import openai  # noqa: F401
        key = os.environ.get("OPENAI_API_KEY")
        return bool(key)
    except ImportError:
        pass
    return False


def _llm_hypothesis_batch(candidates: list[dict], packets: dict[str, str], scope: dict, max_candidates: int) -> list[dict]:
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY"))
        return _call_claude_hypotheses(client, candidates, packets, scope, max_candidates)
    except Exception:
        pass
    try:
        import openai
        client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        return _call_openai_hypotheses(client, candidates, packets, scope, max_candidates)
    except Exception:
        pass
    return []


def _build_hypothesis_prompt(candidates: list[dict], packets: dict[str, str], scope: dict) -> str:
    scope_summary = json.dumps(scope, indent=2)[:2000]
    parts = [
        "You are hypothesis-hunter, an AI subagent for vulnerability hypothesis generation.",
        "For each candidate below, read the source-code packet and produce a grounded hypothesis.",
        "Each hypothesis must identify:",
        "- What unchecked assumption the candidate may rely on",
        "- What attacker-controlled input could reach the potential sink",
        "- What specific code gap exists",
        "- What sink could be triggered",
        "- Confidence level (low/medium/high)",
        "",
        f"Selected scope: {scope_summary}",
        "---",
    ]
    for i, c in enumerate(candidates[:10]):
        cid = str(c.get("id", f"CAND-{i:04d}"))
        packet = packets.get(cid, "[no packet]")
        parts.append(f"\n### Candidate {i+1}: {cid}")
        parts.append(packet[:4000])
    parts.append(
        "\n\nRespond with a JSON object containing a single key 'hypotheses' which is an array of hypothesis objects. "
        "Each hypothesis object must have: id, profile, component, assumption, attacker_controlled_input, possible_gap, "
        "possible_sink, validation_method, confidence, candidate_id."
    )
    return "\n".join(parts)


def _call_claude_hypotheses(client, candidates, packets, scope, max_candidates):
    prompt = _build_hypothesis_prompt(candidates[:max_candidates], packets, scope)
    response = client.messages.create(
        model=LLM_MODEL,
        max_tokens=4000,
        temperature=0.1,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text if response.content else ""
    return _parse_hypotheses_json(text)


def _call_openai_hypotheses(client, candidates, packets, scope, max_candidates):
    prompt = _build_hypothesis_prompt(candidates[:max_candidates], packets, scope)
    response = client.chat.completions.create(
        model=os.environ.get("PVAS_LLM_MODEL", "gpt-4o"),
        max_tokens=4000,
        temperature=0.1,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.choices[0].message.content or ""
    return _parse_hypotheses_json(text)


def _parse_hypotheses_json(text: str) -> list[dict]:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group())
        if isinstance(data, dict) and "hypotheses" in data:
            return data["hypotheses"]
        if isinstance(data, list):
            return data
        return []
    except (json.JSONDecodeError, TypeError):
        return []


def main() -> int:
    ap = argparse.ArgumentParser(
        description="AI subagent for grounded hypothesis generation from source-code packets"
    )
    ap.add_argument("--ranked-candidates", required=True)
    ap.add_argument("--packet-dir", default=None)
    ap.add_argument("--selected-scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-candidates", type=int, default=20)
    ap.add_argument("--llm-mode", choices=["auto", "heuristic"], default="auto",
                    help="auto: try LLM then fall back; heuristic: skip LLM")
    args = ap.parse_args()

    ranked = load_json(args.ranked_candidates, default={}, required=True)
    scope = load_json(args.selected_scope, default={}, required=True)
    candidates = ranked.get("candidates", []) if isinstance(ranked, dict) else []
    selected = [c for c in candidates[: args.max_candidates] if isinstance(c, dict)]

    packet_dir = pathlib.Path(args.packet_dir) if args.packet_dir else None
    packets: dict[str, str] = {}
    if packet_dir and packet_dir.is_dir():
        packets = _load_packets(packet_dir)

    hypotheses: list[dict] = []

    if args.llm_mode == "auto" and _llm_available() and packets:
        try:
            llm_result = _llm_hypothesis_batch(selected, packets, scope, args.max_candidates)
            if llm_result:
                hypotheses = llm_result
                print(f"[PVAS-AI-HYP] LLM generated {len(hypotheses)} hypothesis(es)")
        except Exception:
            print(f"[PVAS-AI-HYP] LLM attempt failed, falling back to heuristic: {traceback.format_exc()}")

    if not hypotheses:
        for i, c in enumerate(selected):
            cid = str(c.get("id", f"CAND-{i:04d}"))
            packet_text = packets.get(cid, "")
            hypotheses.append(_heuristic_hypothesis(c, packet_text, i + 1))
        print(f"[PVAS-AI-HYP] heuristic generated {len(hypotheses)} hypothesis(es)")

    if not hypotheses:
        hypotheses = [_fallback_hypothesis(scope)]

    out = pathlib.Path(args.out)
    write_json(out, {
        "hypotheses": hypotheses,
        "execution": {
            "role": "hypothesis-hunter",
            "mode": "llm-assisted" if args.llm_mode != "heuristic" and _llm_available() else "heuristic",
            "input_candidates": len(selected),
        },
    })
    return 0


def _fallback_hypothesis(scope: dict) -> dict:
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


if __name__ == "__main__":
    raise SystemExit(main())
