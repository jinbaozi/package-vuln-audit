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
DIMENSIONS = ("dataflow", "semantic-invariant", "attack-surface")
CONFIDENCE_SCORE = {"low": 1, "medium": 2, "high": 3}


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
        "read(": "read() without size validation may overflow or truncate buffers",
        "recv(": "recv() without size validation may overflow or truncate buffers",
        "system(": "system() call may allow command injection",
        "popen": "popen() call may allow command injection",
        "execl": "exec-family call may allow command or argument injection",
        "execv": "exec-family call may allow command or argument injection",
        "alloca": "alloca() may cause stack overflow",
    }
    for token, desc in risk_tokens.items():
        if token in code:
            patterns.append(desc)
    return patterns


def _semantic_invariant_patterns(code: str) -> list[str]:
    patterns: list[str] = []
    if re.search(r"\b(len|length|size|count|nbytes|remaining|capacity)\b", code, re.IGNORECASE):
        patterns.append("length or size invariant controls memory/resource access")
    if re.search(r"\b(offset|index|idx|pos|cursor)\b", code, re.IGNORECASE):
        patterns.append("offset or index invariant controls object addressing")
    if re.search(r"\b(state|phase|initialized|closed|freed|owner)\b", code, re.IGNORECASE):
        patterns.append("state or lifecycle invariant controls operation ordering")
    if re.search(r"\b\w+\s*[\+\-\*]\s*\w+", code) and re.search(r"\b(if|while|for)\s*\(", code):
        patterns.append("arithmetic invariant may require overflow or boundary review")
    return patterns


def _attack_surface_patterns(code: str) -> list[str]:
    tokens = {
        "system(": "dynamic command execution surface",
        "popen": "dynamic command execution surface",
        "execl": "process execution surface",
        "execv": "process execution surface",
        "fopen": "filesystem path surface",
        "open(": "filesystem path surface",
        "unlink": "filesystem mutation surface",
        "rename": "filesystem mutation surface",
        "mktemp": "temporary file race surface",
        "socket": "network resource surface",
        "pthread": "concurrency surface",
        "mutex": "concurrency/lifecycle surface",
        "free(": "object lifecycle surface",
        "realloc": "object lifecycle surface",
    }
    patterns: list[str] = []
    for token, desc in tokens.items():
        if token in code:
            patterns.append(desc)
    if re.search(r"\b(path|filename|argv|env|HOME|TMPDIR|command|cmd)\b", code, re.IGNORECASE):
        patterns.append("path, environment, or command input influences a sensitive surface")
    return list(dict.fromkeys(patterns))


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


def _evidence_refs(cid: str, packet_text: str, loc: dict[str, str]) -> list[str]:
    refs = [f"packet:{cid}.md"]
    file_path = loc.get("file")
    lines = loc.get("lines")
    if file_path:
        refs.append(f"source:{file_path}:{lines or '?'}")
    refs.append("selected-scope.json")
    return list(dict.fromkeys(refs))


def _questions_for_dimension(dimension: str, sink: str) -> list[str]:
    if dimension == "dataflow":
        return [
            "What concrete attacker-controlled field reaches this sink?",
            "Which bounds, sanitizer, or type checks dominate the sink on every path?",
            f"Can candidate review prove or refute reachability to {sink} from the packet slice?",
        ]
    if dimension == "semantic-invariant":
        return [
            "Which length, offset, state, or lifecycle invariant must hold before the operation?",
            "Can arithmetic overflow, stale state, or inconsistent units break that invariant?",
            "Does the surrounding caller enforce the invariant before this function executes?",
        ]
    return [
        "Can external input influence the command, path, resource, concurrency, or lifecycle operation?",
        "Are canonicalization, authorization, quoting, locking, or ownership checks complete?",
        f"Does source review show a real path from the package input surface to {sink}?",
    ]


def _failure_scenario(dimension: str, cid: str, file_path: str, func: str, sink: str) -> str:
    if dimension == "dataflow":
        return (
            f"If candidate {cid} accepts a crafted input that reaches {func} in {file_path}, "
            f"the input may flow to {sink} without a complete dominating validation check."
        )
    if dimension == "semantic-invariant":
        return (
            f"If a crafted input violates a length, offset, arithmetic, or state invariant before "
            f"{func} in {file_path}, the checked assumption may no longer match the operation at {sink}."
        )
    return (
        f"If a crafted input influences the command, path, resource, concurrency, or lifecycle surface in "
        f"{func} at {file_path}, {sink} may be reachable with attacker-controlled parameters."
    )


def _make_hypothesis(candidate: dict, packet_text: str, index: int, dimension: str, evidence: list[str],
                     possible_gap: str, possible_sink: str, confidence: str) -> dict:
    cid = str(candidate.get("id", f"CAND-{index:04d}"))
    loc = _extract_source_location(packet_text)
    _, title = _extract_title_and_id(packet_text)
    component = loc.get("file", str(candidate.get("component", "unknown")))
    func = loc.get("function", "unknown")
    file_path = loc.get("file", "unknown")
    lines = loc.get("lines", "?")
    evidence_str = "; ".join(evidence) if evidence else "source packet requires manual review"
    return {
        "id": f"AI-HYP-{index:04d}",
        "dimension": dimension,
        "profile": str(candidate.get("profile", "selected-scope")),
        "component": component,
        "assumption": (
            f"Candidate {cid}: {title or 'source packet'} in {file_path}:{lines} ({func}) "
            f"may rely on an unchecked {dimension} assumption. Evidence: {evidence_str}"
        ),
        "attacker_controlled_input": f"package input surface reaching {file_path} via {func}",
        "possible_gap": possible_gap,
        "possible_sink": possible_sink,
        "evidence_refs": _evidence_refs(cid, packet_text, loc),
        "failure_scenario": _failure_scenario(dimension, cid, file_path, func, possible_sink),
        "review_questions": _questions_for_dimension(dimension, possible_sink),
        "validation_method": "candidate-reviewer source-slice review followed by validator local reproduction or static refutation",
        "confidence": confidence,
        "candidate_id": cid,
        "source_candidate_id": cid,
    }


def _heuristic_hypotheses(candidate: dict, packet_text: str, index: int) -> list[dict]:
    code = _extract_code_slice(packet_text)
    loc = _extract_source_location(packet_text)
    func = loc.get("function", "unknown")
    file_path = loc.get("file", "unknown")
    if not code:
        sink = f"{func} in {file_path}" if func != "unknown" else "scope-dependent parser, resource, or memory operation"
        return [_make_hypothesis(
            candidate, packet_text, index, "attack-surface",
            ["source code slice unavailable; selected scope still requires bounded review"],
            "needs source-to-sink review (no code slice available)",
            sink,
            "low",
        )]

    hypotheses: list[dict] = []
    risks = _high_risk_patterns(code)
    invariants = _semantic_invariant_patterns(code)
    surfaces = _attack_surface_patterns(code)
    sanitizers = _check_sanitization(code)
    sink = f"{func} in {file_path}" if func != "unknown" else f"operation in {file_path}"

    if risks:
        evidence = list(risks)
        if sanitizers:
            evidence.append(f"mitigation observed but coverage unverified: {'; '.join(sanitizers)}")
        hypotheses.append(_make_hypothesis(
            candidate, packet_text, index, "dataflow", evidence,
            f"input-to-sink path may lack complete validation: {'; '.join(risks)}",
            sink,
            "medium" if sanitizers else "high",
        ))

    if invariants:
        evidence = list(invariants)
        if sanitizers:
            evidence.append(f"guarding pattern observed but dominance unverified: {'; '.join(sanitizers)}")
        hypotheses.append(_make_hypothesis(
            candidate, packet_text, index, "semantic-invariant", evidence,
            f"length, offset, arithmetic, state, or lifecycle invariant may be incomplete: {'; '.join(invariants)}",
            sink,
            "medium" if risks or surfaces else "low",
        ))

    if surfaces:
        hypotheses.append(_make_hypothesis(
            candidate, packet_text, index, "attack-surface", surfaces,
            f"command, path, resource, concurrency, or lifecycle surface needs reachability and guard review: {'; '.join(surfaces)}",
            sink,
            "medium" if risks or any("command" in s for s in surfaces) else "low",
        ))

    if not hypotheses:
        hypotheses.append(_make_hypothesis(
            candidate, packet_text, index, "dataflow",
            ["observed code slice has no obvious risky token; source-to-sink assumptions still need bounded review"],
            "no obvious unsafe pattern in slice; needs full source-to-sink analysis before accepting or rejecting",
            sink,
            "low",
        ))

    return hypotheses


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
        "For each candidate below, review the source-code packet across exactly these dimensions:",
        "- dataflow: attacker-controlled input to memory, parser, type, or resource sink",
        "- semantic-invariant: length, offset, arithmetic, state, or lifecycle invariant failures",
        "- attack-surface: path, command, resource, concurrency, or lifecycle exposure",
        "After reviewing all three dimensions, output only the strongest source-grounded hypotheses.",
        "Do not create hypotheses to satisfy a quota, and do not present hypotheses as vulnerabilities.",
        "Each hypothesis must identify:",
        "- dimension (dataflow|semantic-invariant|attack-surface)",
        "- What unchecked assumption the candidate may rely on",
        "- What attacker-controlled input could reach the potential sink",
        "- What specific code gap exists",
        "- What sink could be triggered",
        "- Evidence references from the packet or selected scope",
        "- A concise failure scenario",
        "- Concrete review questions for the candidate reviewer",
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
        "Each hypothesis object must have: id, dimension, profile, component, assumption, attacker_controlled_input, possible_gap, "
        "possible_sink, evidence_refs, failure_scenario, review_questions, validation_method, confidence, candidate_id, source_candidate_id."
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


def _as_nonempty_list(value, fallback: list[str]) -> list[str]:
    if isinstance(value, list):
        items = [str(v).strip() for v in value if str(v).strip()]
        if items:
            return items
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return fallback


def _normalize_hypothesis(hyp: dict, candidates_by_id: dict[str, dict], packets: dict[str, str], index: int) -> dict | None:
    if not isinstance(hyp, dict):
        return None
    cid = str(hyp.get("source_candidate_id") or hyp.get("candidate_id") or "").strip()
    if not cid:
        return None
    candidate = candidates_by_id.get(cid, {"id": cid})
    packet_text = packets.get(cid, "")
    loc = _extract_source_location(packet_text)
    component = str(hyp.get("component") or loc.get("file") or candidate.get("component") or "unknown")
    possible_sink = str(hyp.get("possible_sink") or "candidate-reviewer source-slice sink review").strip()
    dimension = str(hyp.get("dimension") or "").strip()
    if dimension not in DIMENSIONS:
        # Keep LLM output schema-valid without upgrading the hypothesis; candidate review still decides from source.
        dimension = "dataflow"
    normalized = {
        "id": str(hyp.get("id") or f"AI-HYP-{index:04d}").strip(),
        "dimension": dimension,
        "profile": str(hyp.get("profile") or candidate.get("profile") or "selected-scope").strip(),
        "component": component,
        "assumption": str(hyp.get("assumption") or "source-grounded assumption requires candidate review").strip(),
        "attacker_controlled_input": str(hyp.get("attacker_controlled_input") or "package input surface identified in selected scope").strip(),
        "possible_gap": str(hyp.get("possible_gap") or "needs candidate-reviewer source-to-sink review").strip(),
        "possible_sink": possible_sink,
        "evidence_refs": _as_nonempty_list(hyp.get("evidence_refs"), _evidence_refs(cid, packet_text, loc)),
        "failure_scenario": str(hyp.get("failure_scenario") or _failure_scenario(dimension, cid, loc.get("file", "unknown"), loc.get("function", "unknown"), possible_sink)).strip(),
        "review_questions": _as_nonempty_list(hyp.get("review_questions"), _questions_for_dimension(dimension, possible_sink)),
        "validation_method": str(hyp.get("validation_method") or "candidate-reviewer source-slice review followed by local reproduction or static refutation").strip(),
        "confidence": str(hyp.get("confidence") or "low").strip(),
        "candidate_id": cid,
        "source_candidate_id": cid,
    }
    if normalized["confidence"] not in CONFIDENCE_SCORE:
        normalized["confidence"] = "low"
    for key in ("assumption", "attacker_controlled_input", "possible_gap", "possible_sink",
                "failure_scenario", "validation_method"):
        if not normalized[key]:
            return None
    return normalized


def _hypothesis_quality(hyp: dict) -> tuple[int, int, int]:
    confidence = CONFIDENCE_SCORE.get(str(hyp.get("confidence")), 0)
    evidence_count = len(hyp.get("evidence_refs") or [])
    question_count = len(hyp.get("review_questions") or [])
    return confidence, evidence_count, question_count


def _synthesize_hypotheses(hypotheses: list[dict]) -> list[dict]:
    by_key: dict[tuple[str, str, str, str], dict] = {}
    order: list[tuple[str, str, str, str]] = []
    for hyp in hypotheses:
        key = (
            str(hyp.get("source_candidate_id") or hyp.get("candidate_id") or ""),
            str(hyp.get("dimension") or ""),
            str(hyp.get("possible_gap") or "").strip().lower(),
            str(hyp.get("possible_sink") or "").strip().lower(),
        )
        if key not in by_key:
            by_key[key] = hyp
            order.append(key)
            continue
        if _hypothesis_quality(hyp) > _hypothesis_quality(by_key[key]):
            by_key[key] = hyp
    synthesized = [by_key[key] for key in order]
    for i, hyp in enumerate(synthesized, 1):
        hyp["id"] = f"AI-HYP-{i:04d}"
    return synthesized


def _normalize_and_synthesize(hypotheses: list[dict], selected: list[dict], packets: dict[str, str]) -> list[dict]:
    candidates_by_id = {str(c.get("id")): c for c in selected if isinstance(c, dict) and c.get("id")}
    normalized = [
        h for i, raw in enumerate(hypotheses, 1)
        if (h := _normalize_hypothesis(raw, candidates_by_id, packets, i)) is not None
    ]
    return _synthesize_hypotheses(normalized)


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
                hypotheses = _normalize_and_synthesize(llm_result, selected, packets)
                print(f"[PVAS-AI-HYP] LLM generated {len(hypotheses)} hypothesis(es)")
        except Exception:
            print(f"[PVAS-AI-HYP] LLM attempt failed, falling back to heuristic: {traceback.format_exc()}")

    if not hypotheses:
        for i, c in enumerate(selected):
            cid = str(c.get("id", f"CAND-{i:04d}"))
            packet_text = packets.get(cid, "")
            hypotheses.extend(_heuristic_hypotheses(c, packet_text, i + 1))
        hypotheses = _synthesize_hypotheses(hypotheses)
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
        "dimension": "attack-surface",
        "profile": "selected-scope",
        "component": str(component),
        "assumption": "The selected audit scope may contain input parsing or trust-boundary assumptions not covered by traditional tools.",
        "attacker_controlled_input": "package inputs identified during scope selection",
        "possible_gap": "traditional tools produced no ranked candidate for this scope",
        "possible_sink": "scope-dependent parser, decoder, filesystem, process, or memory operation",
        "evidence_refs": ["selected-scope.json"],
        "failure_scenario": "If the selected scope contains an input surface not represented by ranked candidates, candidate review must first locate concrete source evidence before any vulnerability claim.",
        "review_questions": [
            "Which selected recipe input surfaces did traditional tools fail to cover?",
            "Is there any bounded source slice that links package input to a parser, filesystem, process, or memory operation?",
            "Should this remain a low-confidence hypothesis or be rejected for lack of source grounding?",
        ],
        "validation_method": "bounded source-slice review before any vulnerability claim",
        "confidence": "low",
        "candidate_id": "",
        "source_candidate_id": "",
    }


if __name__ == "__main__":
    raise SystemExit(main())
