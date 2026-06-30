#!/usr/bin/env python3
"""Shared report rendering helpers and finding statistics (stdlib only)."""
from __future__ import annotations

from collections import Counter, defaultdict


def finding_status(f: dict) -> str:
    return f.get('status') or f.get('validated_status') or ''


def safe_str(v, fallback='—'):
    if v is None:
        return fallback
    s = str(v)
    return s if s.strip() else fallback


def fmt_list(items, sep=', '):
    if not items:
        return '—'
    return sep.join(str(x) for x in items)


def flatten_discovery(dm):
    if not dm:
        return []
    if isinstance(dm, list):
        return [d for d in dm if isinstance(d, dict)]
    return []


def discovery_summary_str(dm) -> str:
    parts = flatten_discovery(dm)
    if not parts:
        return 'unknown'
    return '; '.join(
        f"{p.get('type', '?')}({p.get('tool_name', '') or p.get('hypothesis_id', '') or '—'})"
        for p in parts
    )


def compute_funnel(findings, candidate_summary, tool_summary):
    validated = sum(1 for f in findings if finding_status(f) == 'Validated')
    needs_review = sum(1 for f in findings if finding_status(f) == 'Needs Manual Review')
    rejected = sum(1 for f in findings if finding_status(f) == 'Rejected')
    likely = sum(1 for f in findings if finding_status(f) == 'Likely')
    candidate = sum(1 for f in findings if finding_status(f) == 'Candidate')

    raw_hits = 0
    if tool_summary and isinstance(tool_summary, dict):
        for tool in (tool_summary.get('tools', []) or tool_summary.get('results', []) or []):
            if isinstance(tool, dict):
                raw_hits += tool.get('hit_count', tool.get('findings_count', 0))
    if not raw_hits and candidate_summary and isinstance(candidate_summary, dict):
        raw_hits = candidate_summary.get('total_raw_hits', candidate_summary.get('raw_hit_count', 0))

    total = len(findings)
    if not raw_hits:
        raw_hits = total

    return {
        'raw_hits': max(raw_hits, total),
        'candidates': candidate + likely + validated + needs_review + rejected,
        'likely': likely,
        'validated': validated,
        'needs_review': needs_review,
        'rejected': rejected,
        'total': total,
    }


def compute_severity_distribution(findings):
    dist = Counter()
    for f in findings:
        if finding_status(f) not in ('Validated', 'Needs Manual Review'):
            continue
        sev = (f.get('cvss', {}) or {}).get('severity', 'Unknown')
        if sev is None:
            sev = 'Unknown'
        dist[sev] += 1
    return dict(dist)


def compute_discovery_method_stats(findings):
    method_counts = Counter()
    method_validated = Counter()
    for f in findings:
        st = finding_status(f)
        if st not in ('Validated', 'Needs Manual Review'):
            continue
        for dm in f.get('discovery_method') or []:
            if isinstance(dm, dict):
                mt = dm.get('type', 'unknown')
                method_counts[mt] += 1
                if st == 'Validated':
                    method_validated[mt] += 1
    return dict(method_counts), dict(method_validated)


def compute_tool_output_stats(findings, tool_summary):
    tool_candidates = Counter()
    tool_validated = Counter()

    for f in findings:
        st = finding_status(f)
        if st not in ('Validated', 'Needs Manual Review'):
            continue
        for dm in f.get('discovery_method') or []:
            if isinstance(dm, dict) and dm.get('type') == 'tool':
                tool_name = dm.get('tool_name', 'unknown')
                tool_candidates[tool_name] += 1
                if st == 'Validated':
                    tool_validated[tool_name] += 1

    if tool_summary and isinstance(tool_summary, dict):
        for tool in (tool_summary.get('tools', []) or tool_summary.get('results', []) or []):
            if isinstance(tool, dict):
                name = tool.get('name', tool.get('tool', 'unknown'))
                if name not in tool_candidates:
                    tool_candidates[name] = tool.get('hit_count', tool.get('findings_count', 0))

    return dict(tool_candidates), dict(tool_validated)


def compute_component_summary(findings):
    comp_counts = Counter()
    comp_findings = defaultdict(list)
    for f in findings:
        st = finding_status(f)
        if st not in ('Validated', 'Needs Manual Review'):
            continue
        comp = (f.get('affected_component', {}) or {}).get('component', 'unknown')
        comp_counts[comp] += 1
        comp_findings[comp].append({
            'id': f.get('id', '?'),
            'severity': (f.get('cvss', {}) or {}).get('severity', '?'),
            'status': st,
        })
    return dict(comp_counts), dict(comp_findings)


def compute_risk_overview(findings):
    scores = []
    for f in findings:
        if finding_status(f) not in ('Validated', 'Needs Manual Review'):
            continue
        score = (f.get('cvss', {}) or {}).get('base_score')
        if score is not None:
            try:
                scores.append(float(score))
            except (ValueError, TypeError):
                pass

    if not scores:
        return {
            'avg_score': '—',
            'max_score': '—',
            'min_score': '—',
            'total_scored': 0,
            'risk_level': '—',
        }

    avg = sum(scores) / len(scores)
    mx = max(scores)
    mn = min(scores)

    if avg >= 9.0:
        risk = 'Critical'
    elif avg >= 7.0:
        risk = 'High'
    elif avg >= 4.0:
        risk = 'Medium'
    elif avg > 0:
        risk = 'Low'
    else:
        risk = 'None'

    return {
        'avg_score': f'{avg:.1f}',
        'max_score': f'{mx:.1f}',
        'min_score': f'{mn:.1f}',
        'total_scored': len(scores),
        'risk_level': risk,
    }


def compute_all_stats(findings, candidate_summary=None, tool_summary=None):
    """Compute all finding statistics once for reuse across report builders."""
    method_counts, method_validated = compute_discovery_method_stats(findings)
    tool_candidates, tool_validated = compute_tool_output_stats(findings, tool_summary)
    comp_counts, comp_findings = compute_component_summary(findings)
    return {
        'funnel': compute_funnel(findings, candidate_summary, tool_summary),
        'severity_distribution': compute_severity_distribution(findings),
        'discovery_methods': {'total': method_counts, 'validated': method_validated},
        'tool_output': {'candidates': tool_candidates, 'validated': tool_validated},
        'component_summary': {'counts': comp_counts, 'findings': comp_findings},
        'risk_overview': compute_risk_overview(findings),
    }
