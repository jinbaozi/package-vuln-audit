#!/usr/bin/env python3
"""Generate final summary report aggregating all 10 audit workflow steps.

Enhanced with:
- Audit funnel statistics
- Severity distribution
- Discovery method analysis
- Tool output statistics
- Risk overview
- Affected component summary
- Enhanced per-finding details
"""
from __future__ import annotations
import argparse, json, pathlib, sys
from datetime import datetime

from pvas_io import load_json
from report_render import (
    compute_all_stats,
    compute_component_summary,
    compute_discovery_method_stats,
    compute_funnel,
    compute_risk_overview,
    compute_severity_distribution,
    compute_tool_output_stats,
    finding_status,
    fmt_list,
    safe_str,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / 'templates'


def read_text(p: pathlib.Path, default=''):
    if p and p.exists():
        try:
            return p.read_text()
        except Exception:
            return default
    return default


# ---------------------------------------------------------------------------
# Content builders
# ---------------------------------------------------------------------------

def build_manual_review_table(findings, audit_root):
    rows = ['| ID | 组件 | 阻断原因 | 人工验证计划 |', '|---|---|---|---|']
    for f in findings:
        if finding_status(f) != 'Needs Manual Review':
            continue
        fid = f.get('id', '?')
        comp = f.get('affected_component', {}).get('component', '?')
        mr = f.get('manual_review') if isinstance(f.get('manual_review'), dict) else {}
        reason = mr.get('blocked_reason') or f.get('manual_review_reason') or '自动验证条件不足'
        plan = audit_root / '04-validation' / 'manual-review' / fid / 'manual-validation-plan.md'
        rows.append(f'| {fid} | {comp} | {reason} | `{plan}` |')
    if len(rows) == 2:
        rows.append('| 无 | 无 | 无 | 无 |')
    return '\n'.join(rows)


def build_tool_matrix_content(audit_root):
    matrix = load_json(audit_root / '01-profile' / 'required-tools-matrix.json', {})
    summary = load_json(audit_root / '02-tools' / 'tool-summary.json', {})
    by_name = {
        t.get('name'): t for t in summary.get('tools', [])
        if isinstance(t, dict) and t.get('name')
    } if isinstance(summary, dict) else {}
    tools = matrix.get('tools', [])
    rows = ['| 工具 | 适用性 | 最终状态 | 覆盖 | 准入策略 | 可支持未发现结论 | 理由 |', '|---|---|---|---|---|---|---|']
    for t in tools:
        row = by_name.get(t.get('name')) or {}
        rows.append(
            f"| {t.get('name','?')} | {t.get('applicability','?')} | {row.get('status') or t.get('final_status') or t.get('status','?')} "
            f"| {row.get('coverage_profile','?')} | {row.get('admission_policy','?')} "
            f"| {row.get('negative_conclusion_allowed', False)} | {row.get('reason') or t.get('final_decision_rationale') or t.get('evidence','')} |"
        )
    if len(rows) == 2:
        rows.append('| 无 | 无 | 无 | 无 | 无 | False | 无 |')
    return '\n'.join(rows)


def build_executive_summary(findings, all_tools, environment, intake, profile, stats=None):
    validated = [f for f in findings if finding_status(f) == 'Validated']
    needs_review = [f for f in findings if finding_status(f) == 'Needs Manual Review']
    candidates = [f for f in findings if finding_status(f) not in ('Validated', 'Needs Manual Review')]

    tool_available = sum(1 for t in all_tools if t.get('status') == 'installed')
    tool_total = len(all_tools)
    profile_name = profile.get('package_name', '?') if profile else '?'
    primary_lang = fmt_list(profile.get('primary_language', [])) if profile else '?'

    if stats is None:
        stats = compute_all_stats(findings)
    sev_dist = stats['severity_distribution']
    risk = stats['risk_overview']

    lines = [
        f'- **Package**: `{profile_name}`',
        f'- **Primary Language(s)**: {primary_lang}',
        f'- **Tools Available**: {tool_available}/{tool_total}',
        f'- **Validated Findings**: {len(validated)}',
        f'- **Needs Manual Review**: {len(needs_review)}',
        f'- **Other Candidates**: {len(candidates)}',
        f'- **Overall Risk Level**: {risk["risk_level"]} (avg CVSS: {risk["avg_score"]})',
        '',
    ]

    # Severity breakdown
    if sev_dist:
        lines.append('#### Severity Distribution')
        lines.append('')
        lines.append('| Severity | Count |')
        lines.append('|----------|-------|')
        for sev in ['Critical', 'High', 'Medium', 'Low', 'None', 'Unknown']:
            if sev in sev_dist:
                lines.append(f'| {sev} | {sev_dist[sev]} |')
        lines.append('')

    if intake:
        lines.append(f'- **Scope**: {intake.get("scope_summary", "see 01-intake")}')
        lines.append(f'- **Authorization**: {intake.get("authorization", "not specified")}')
        lines.append(f'- **Network Policy**: {intake.get("network_policy", "not specified")}')
    if environment:
        lines.append(f'- **Environment Mode**: {environment.get("mode", "?")}')
        lines.append(f'- **Environment Profile**: {environment.get("environment_profile", "?")}')
        lines.append(f'- **Decision**: {environment.get("decision", "?")}')
    lines.extend(['', '### Funnel Summary', ''])
    source_count = len(candidates) + len(validated) + len(needs_review)
    lines.append(f'Total Candidates → **{source_count}** → Validated: **{len(validated)}** → Needs Review: **{len(needs_review)}** → Rejected/Other: **{len(candidates)}**')
    return '\n'.join(lines)


def build_validated_table(findings, correlations):
    if not findings:
        return '| — | — | — | — | — | — | — |'
    rows = []
    for f in findings:
        if finding_status(f) not in ('Validated', 'Needs Manual Review'):
            continue
        fid = f.get('id', '?')
        sev = f.get('cvss', {}).get('severity', '?')
        score = f.get('cvss', {}).get('base_score', '?')
        comp = f.get('affected_component', {}).get('component', '?')
        dm_list = f.get('discovery_method') or []
        dm_strs = []
        for d in dm_list:
            tool = d.get('tool_name', '') or d.get('hypothesis_id', '') or ''
            dm_strs.append(f"{d.get('type','?')}({tool})" if tool else d.get('type', '?'))
        dm = '; '.join(dm_strs) if dm_strs else '?'
        ds = f.get('disclosure_status', 'unknown')
        refs = '—'
        corr = correlations.get(fid) if correlations else None
        if corr:
            records = corr.get('matched_records', [])
            ref_parts = []
            for r in records:
                rid = r.get('id', '')
                url = r.get('url', '')
                source = r.get('source', '')
                if url:
                    ref_parts.append(f'[{source}/{rid}]({url})' if source else f'[{rid}]({url})')
                elif rid:
                    ref_parts.append(f'{source}/{rid}' if source else rid)
            if ref_parts:
                refs = '; '.join(ref_parts)
        rows.append(f'| {fid} | {sev} | {score} | {comp} | {dm} | {ds} | {refs} |')
    if not rows:
        return '| — | — | — | — | — | — | — |'
    return '\n'.join(rows)


def build_funnel_table(findings, candidate_summary, tool_summary):
    """Build the audit funnel statistics table."""
    funnel = compute_funnel(findings, candidate_summary, tool_summary)
    rows = [
        '| Stage | Count | Description |',
        '|-------|-------|-------------|',
        f'| Raw Tool Hits | {funnel["raw_hits"]} | Total hits from traditional security tools |',
        f'| Candidates | {funnel["candidates"]} | After normalization and deduplication |',
        f'| Likely | {funnel["likely"]} | Passed candidate review |',
        f'| **Validated** | **{funnel["validated"]}** | Confirmed via validation |',
        f'| Needs Manual Review | {funnel["needs_review"]} | Cannot be auto-validated |',
        f'| Rejected | {funnel["rejected"]} | False positives or out-of-scope |',
    ]
    return '\n'.join(rows)


def build_severity_table(findings):
    """Build severity distribution table."""
    dist = compute_severity_distribution(findings)
    if not dist:
        return 'No severity data available.'

    rows = [
        '| Severity | Count | Percentage |',
        '|----------|-------|------------|',
    ]
    total = sum(dist.values()) or 1
    for sev in ['Critical', 'High', 'Medium', 'Low', 'None', 'Unknown']:
        count = dist.get(sev, 0)
        if count > 0 or sev in ('Critical', 'High', 'Medium', 'Low'):
            pct = f'{count/total*100:.0f}%'
            rows.append(f'| {sev} | {count} | {pct} |')
    return '\n'.join(rows)


def build_discovery_method_table(findings):
    """Build discovery method analysis table."""
    method_counts, method_validated = compute_discovery_method_stats(findings)
    if not method_counts:
        return 'No discovery method data available.'

    rows = [
        '| Method | Total Findings | Validated | Validation Rate |',
        '|--------|---------------|-----------|-----------------|',
    ]
    type_labels = {
        'tool': 'Traditional Tool',
        'ai': 'AI Hypothesis',
        'manual': 'Manual Review',
        'fuzz': 'Fuzz Testing',
    }
    for method in ['tool', 'ai', 'fuzz', 'manual']:
        total = method_counts.get(method, 0)
        validated = method_validated.get(method, 0)
        rate = f'{validated/total*100:.0f}%' if total > 0 else '—'
        label = type_labels.get(method, method)
        if total > 0:
            rows.append(f'| {label} | {total} | {validated} | {rate} |')

    # Add any methods not in the predefined list
    for method, total in sorted(method_counts.items()):
        if method not in type_labels:
            validated = method_validated.get(method, 0)
            rate = f'{validated/total*100:.0f}%' if total > 0 else '—'
            rows.append(f'| {method} | {total} | {validated} | {rate} |')

    return '\n'.join(rows)


def build_tool_output_table(findings, tool_summary):
    """Build tool output statistics table."""
    tool_candidates, tool_validated = compute_tool_output_stats(findings, tool_summary)
    if not tool_candidates:
        return 'No tool output data available.'

    rows = [
        '| Tool | Candidates Produced | Validated | Effectiveness |',
        '|------|--------------------:|----------:|---------------|',
    ]
    for tool in sorted(tool_candidates.keys()):
        total = tool_candidates[tool]
        validated = tool_validated.get(tool, 0)
        rate = f'{validated/total*100:.0f}%' if total > 0 else '—'
        rows.append(f'| {tool} | {total} | {validated} | {rate} |')
    return '\n'.join(rows)


def build_risk_overview(findings):
    """Build risk overview section."""
    risk = compute_risk_overview(findings)
    sev_dist = compute_severity_distribution(findings)

    lines = [
        '| Metric | Value |',
        '|--------|-------|',
        f'| Average CVSS Score | {risk["avg_score"]} |',
        f'| Maximum CVSS Score | {risk["max_score"]} |',
        f'| Minimum CVSS Score | {risk["min_score"]} |',
        f'| Total Scored Findings | {risk["total_scored"]} |',
        f'| **Overall Risk Level** | **{risk["risk_level"]}** |',
    ]

    # Severity heatmap
    if sev_dist:
        lines.append('')
        lines.append('#### Severity Heatmap')
        lines.append('')
        critical = sev_dist.get('Critical', 0)
        high = sev_dist.get('High', 0)
        medium = sev_dist.get('Medium', 0)
        low = sev_dist.get('Low', 0)

        if critical > 0:
            lines.append(f'- 🔴 **Critical**: {critical} finding(s) — immediate action required')
        if high > 0:
            lines.append(f'- 🟠 **High**: {high} finding(s) — priority remediation')
        if medium > 0:
            lines.append(f'- 🟡 **Medium**: {medium} finding(s) — scheduled remediation')
        if low > 0:
            lines.append(f'- 🟢 **Low**: {low} finding(s) — monitor and address')
        if not any([critical, high, medium, low]):
            needs_review = any(finding_status(f) == 'Needs Manual Review' for f in findings)
            if needs_review:
                lines.append('- Needs Manual Review items remain unresolved; no significant-vulnerability conclusion is emitted.')
            else:
                lines.append('- No validated high-impact vulnerabilities are represented in the current findings set.')

    return '\n'.join(lines)


def build_component_table(findings):
    """Build affected component summary table."""
    comp_counts, comp_findings = compute_component_summary(findings)
    if not comp_counts:
        return 'No affected component data available.'

    rows = [
        '| Component | Finding Count | Severity Range | Finding IDs |',
        '|-----------|:-------------:|----------------|-------------|',
    ]
    for comp in sorted(comp_counts, key=comp_counts.get, reverse=True):
        count = comp_counts[comp]
        flist = comp_findings[comp]
        ids = ', '.join(f'`{f["id"]}`' for f in flist)
        severities = [f['severity'] for f in flist if f['severity'] != '?']
        sev_range = ', '.join(sorted(set(severities))) if severities else '—'
        rows.append(f'| {comp} | {count} | {sev_range} | {ids} |')
    return '\n'.join(rows)


def build_finding_details(findings, correlations):
    """Build enhanced per-finding detail section."""
    validated = [f for f in findings if finding_status(f) in ('Validated', 'Needs Manual Review')]
    if not validated:
        return 'No validated findings to detail.'

    parts = []
    for f in validated:
        fid = f.get('id', '?')
        title = f.get('title', 'Untitled')
        status = finding_status(f)
        cvss = f.get('cvss', {}) or {}

        parts.append(f'### {fid}: {title}')
        parts.append('')
        parts.append(f'**Status:** {status}  ')
        parts.append(f'**Severity:** {cvss.get("severity", "?")} (CVSS {cvss.get("base_score", "?")})  ')
        parts.append(f'**CVSS Vector:** `{cvss.get("vector", "—")}`  ')
        parts.append('')

        # Affected component
        ac = f.get('affected_component', {}) or {}
        parts.append(f'**Package:** {ac.get("package", "?")}  ')
        parts.append(f'**Component:** {ac.get("component", "?")}  ')
        if ac.get('version_or_commit'):
            parts.append(f'**Version/Commit:** {ac["version_or_commit"]}  ')
        parts.append('')

        # Source code evidence
        evidence = f.get('source_code_evidence') or []
        if evidence:
            parts.append('#### Source Code Evidence')
            parts.append('')
            for ev in evidence:
                if isinstance(ev, dict):
                    parts.append(f'- **File:** `{ev.get("file", "?")}`')
                    if ev.get('function'):
                        parts.append(f'  - **Function:** `{ev["function"]}`')
                    if ev.get('line') or ev.get('line_range'):
                        lr = ev.get('line_range') or ev.get('line')
                        parts.append(f'  - **Line(s):** {lr}')
                    if ev.get('description'):
                        parts.append(f'  - {ev["description"]}')
            parts.append('')

        # Source-to-sink path
        ssp = f.get('source_to_sink_path', '')
        if ssp:
            parts.append('#### Source-to-Sink Path')
            parts.append('')
            if isinstance(ssp, list):
                for step in ssp:
                    if isinstance(step, dict):
                        parts.append(f'1. **{step.get("stage", "?")}**: {step.get("description", "")}')
                    else:
                        parts.append(f'1. {step}')
            else:
                parts.append(f'```\n{ssp}\n```')
            parts.append('')

        # Validation evidence
        val = f.get('validation', {})
        if isinstance(val, dict) and val:
            parts.append('#### Validation Evidence')
            parts.append('')
            method = val.get('method', '?')
            parts.append(f'- **Method:** {method}')
            if val.get('command'):
                parts.append(f'- **Command:** `{val["command"]}`')
            if val.get('result_summary'):
                parts.append(f'- **Result:** {val["result_summary"]}')
            parts.append('')

        # POC status
        poc = f.get('poc_test_artifacts') or []
        if poc:
            parts.append('#### PoC Test Artifacts')
            parts.append('')
            for p in poc:
                if isinstance(p, dict):
                    parts.append(f'- **{p.get("type", "?")}**: `{p.get("path", "?")}` — {p.get("purpose", "")}')
            parts.append('')

        # Discovery method
        dm_list = f.get('discovery_method') or []
        if dm_list:
            parts.append('#### Discovery Method')
            parts.append('')
            for dm in dm_list:
                if isinstance(dm, dict):
                    parts.append(f'- **{dm.get("type", "?")}**: {dm.get("description", "")}')
                    if dm.get('tool_name'):
                        parts.append(f'  - Tool: {dm["tool_name"]}')
                    if dm.get('hypothesis_id'):
                        parts.append(f'  - Hypothesis: {dm["hypothesis_id"]}')
            parts.append('')

        # Fix recommendation
        fix = f.get('fix_recommendation', '')
        if fix:
            parts.append('#### Fix Recommendation')
            parts.append('')
            parts.append(fix if isinstance(fix, str) else json.dumps(fix, indent=2, ensure_ascii=False))
            parts.append('')

        # Public vulnerability correlation
        corr = correlations.get(fid) if correlations else None
        if corr:
            parts.append('#### Public Vulnerability Correlation')
            parts.append('')
            parts.append(f'- **Status:** {corr.get("status", "?")}')
            parts.append(f'- **Match Level:** {corr.get("match_level", "?")}')
            records = corr.get('matched_records', [])
            if records:
                for r in records:
                    rid = r.get('id', '')
                    url = r.get('url', '')
                    source = r.get('source', '')
                    if url:
                        parts.append(f'- [{source}/{rid}]({url})')
                    elif rid:
                        parts.append(f'- {source}/{rid}')
            parts.append('')

        parts.append('---')
        parts.append('')

    return '\n'.join(parts)


# ---------------------------------------------------------------------------
# Existing builders (kept for backward compatibility)
# ---------------------------------------------------------------------------

def build_intake_content(intake, scope_md):
    parts = []
    if intake:
        parts.append('**Intake Metadata:**')
        parts.append('')
        parts.append(f'```json\n{json.dumps(intake, indent=2, ensure_ascii=False)}\n```')
        parts.append('')
    if scope_md:
        parts.append('**Scope Document:**')
        parts.append('')
        parts.append('```text')
        parts.append(scope_md[:5000])
        if len(scope_md) > 5000:
            parts.append('...(truncated)')
        parts.append('```')
    return '\n'.join(parts) if parts else 'No intake data recorded.'


def build_profile_content(profile):
    if not profile:
        return 'No package profile data recorded.'
    return f'```json\n{json.dumps(profile, indent=2, ensure_ascii=False)}\n```'


def build_scope_content(scope):
    if not scope:
        return 'No scope selection data recorded.'
    return f'```json\n{json.dumps(scope, indent=2, ensure_ascii=False)}\n```'


def build_tool_scan_content(environment, tool_summary):
    parts = []
    if environment:
        parts.append('**Environment Check:**')
        parts.append('')
        env_lines = ['| Tool | Binary | Status | Version | Path | Requirement Level |']
        env_lines.append('|---|---|---|---|---|---|')
        for t in environment.get('tools', []):
            env_lines.append(
                f"| {t.get('name','?')} | {t.get('binary','?')} | {t.get('status','?')} "
                f"| {t.get('version','')} | {t.get('path','')} | {t.get('requirement_level','?')} |"
            )
        parts.append('\n'.join(env_lines))
        parts.append('')
        caps = environment.get('capability_summary', {})
        if caps:
            parts.append('**Capability Summary:**')
            parts.append('')
            for cap, st in sorted(caps.items()):
                parts.append(f'- {cap}: **{st}**')
            parts.append('')
        missing = environment.get('missing_tools', [])
        if missing:
            parts.append(f'**Missing Tools:** {fmt_list(missing)}')
            parts.append('')
    if tool_summary:
        parts.append('**Tool Execution Summary:**')
        parts.append('')
        parts.append(f'```json\n{json.dumps(tool_summary, indent=2, ensure_ascii=False)}\n```')
    return '\n'.join(parts) if parts else 'No tool scan data recorded.'


def build_ai_hypothesis_content(hypotheses):
    if not hypotheses:
        return 'AI hypothesis artifact missing; enforced driver must fail before final report generation.'
    hyps = hypotheses if isinstance(hypotheses, list) else hypotheses.get('hypotheses', [])
    if not hyps:
        return 'AI hypothesis artifact is empty; enforced driver must fail before final report generation.'
    parts = [f'**Total Hypotheses Generated:** {len(hyps)}', '']
    for h in hyps:
        hid = h.get('id', '?')
        dimension = h.get('dimension', '?')
        gap = h.get('possible_gap', h.get('summary', '?'))
        sink = h.get('possible_sink', '?')
        refs = ', '.join(h.get('evidence_refs', []) or [])
        parts.append(f'- **{hid}** [{dimension}]: {gap}')
        parts.append(f'  - Possible sink: {sink}')
        parts.append(f'  - Evidence refs: {refs or "?"}')
    return '\n'.join(parts)


def build_candidate_content(candidate_summary, reviews):
    if not candidate_summary:
        return 'No candidate review data recorded.'
    parts = []
    summary_text = candidate_summary if isinstance(candidate_summary, str) else json.dumps(candidate_summary, indent=2, ensure_ascii=False)
    parts.append(f'```json\n{summary_text}\n```')
    if reviews:
        parts.append('')
        parts.append('**Candidate Reviews:**')
        parts.append('')
        for r in reviews:
            rid = r.get('id', pathlib.Path(r.get('path', '?')).stem) if isinstance(r, dict) else '?'
            parts.append(f'- `{rid}`')
    return '\n'.join(parts)


def build_validation_content(validation_summary):
    if not validation_summary:
        return 'No validation data recorded.'
    return f'```json\n{json.dumps(validation_summary, indent=2, ensure_ascii=False)}\n```'


def build_cvss_content(findings):
    scored = [f for f in findings if f.get('cvss', {}).get('base_score')]
    if not scored:
        return 'No CVSS scores assigned.'
    parts = ['| ID | Vector | Score | Severity | Rationale |', '|---|---|---|---|---|']
    for f in scored:
        cvss = f.get('cvss', {})
        parts.append(
            f"| {f.get('id','?')} | {cvss.get('vector','?')} "
            f"| {cvss.get('base_score','?')} | {cvss.get('severity','?')} "
            f"| {cvss.get('rationale','—')} |"
        )
    return '\n'.join(parts)


def build_report_generation_content(report, bilingual_map):
    parts = []
    if report:
        parts.append('**Machine Report:**')
        parts.append(f'- Path: `{report.get("_path", "?")}`')
        parts.append(f'- Findings: {len(report.get("findings", []))}')
        parts.append('')
    if bilingual_map:
        parts.append('**Bilingual Map:**')
        parts.append(f'```json\n{json.dumps(bilingual_map, indent=2, ensure_ascii=False)}\n```')
    return '\n'.join(parts) if parts else 'No report generation data recorded.'


def build_disclosure_content(findings, correlations):
    parts = ['| Finding ID | Disclosure Level | Disclosure Status | Match Level | Public References |', '|---|---|---|---|---|']
    disclosed = 0
    not_found = 0
    for f in findings:
        fid = f.get('id', '?')
        dl = f.get('disclosure_level', '—')
        ds = f.get('disclosure_status', 'unknown')
        corr = correlations.get(fid) if correlations else None
        ml = corr.get('match_level', 'M0') if corr else 'M0'
        refs = '—'
        if corr:
            records = corr.get('matched_records', [])
            ref_parts = []
            for r in records:
                rid = r.get('id', '')
                url = r.get('url', '')
                source = r.get('source', '')
                if url:
                    ref_parts.append(f'[{source}/{rid}]({url})' if source else f'[{rid}]({url})')
                elif rid:
                    ref_parts.append(f'{source}/{rid}' if source else rid)
            if ref_parts:
                refs = '; '.join(ref_parts)
        if ds == 'publicly_disclosed':
            disclosed += 1
        elif ds == 'not_found_in_configured_sources':
            not_found += 1
        parts.append(f'| {fid} | {dl} | {ds} | {ml} | {refs} |')
    summary = [
        '### Disclosure Summary',
        '',
        f'- **D2 (Internal Validated)**: {sum(1 for f in findings if f.get("disclosure_level","").startswith("D2"))}',
        f'- **D3 (Maintainer Private)**: {sum(1 for f in findings if f.get("disclosure_level","").startswith("D3"))}',
        f'- **D4 (Public After Fix)**: {sum(1 for f in findings if f.get("disclosure_level","").startswith("D4"))}',
        f'- Publicly disclosed: {disclosed}',
        f'- Not found in configured sources: {not_found}',
        '',
    ]
    return '\n'.join(summary + parts)


def gather_disclosure_stats(findings, correlations):
    matched = 0
    not_found = 0
    sources = set()
    for f in findings:
        fid = f.get('id', '?')
        ds = f.get('disclosure_status', 'unknown')
        if ds == 'publicly_disclosed':
            matched += 1
        elif ds == 'not_found_in_configured_sources':
            not_found += 1
        corr = correlations.get(fid) if correlations else None
        if corr:
            for r in corr.get('matched_records', []):
                src = r.get('source', '')
                if src:
                    sources.add(src)
            for cs in corr.get('checked_sources', []):
                sources.add(cs)
    return matched, not_found, sources



def build_workflow_summary(audit_root):
    expected = [
        '00-intake', '01-package-profile', '02-scope-selection', '03-tool-scan',
        '04-ai-hypothesis', '05-candidate-review', '06-validation',
        '07-cvss-scoring', '08-report', '09-progressive-disclosure',
    ]
    rows = ['| Workflow | Status | Attempts | Decision | Issues |', '|---|---|---:|---|---|']
    steps_dir = audit_root / 'machine' / 'workflow-steps'
    for step_id in expected:
        step = load_json(steps_dir / f'{step_id}.json', {})
        if not isinstance(step, dict) or not step:
            rows.append(f'| `{step_id}` | missing | 0 | failed | workflow step artifact missing |')
            continue
        issues = step.get('blocking_issues') or step.get('limitations') or []
        issue_text = '; '.join(str(x).replace('|', '\\|') for x in issues) if issues else 'none'
        rows.append(
            f"| `{step_id}` | {step.get('status', '?')} | {step.get('attempt_count', 0)} | "
            f"{step.get('decision', '?')} | {issue_text} |"
        )
    return '\n'.join(rows)

def render_template(template_path: pathlib.Path, values: dict) -> str:
    template = template_path.read_text()
    for key, val in values.items():
        placeholder = '{{' + key + '}}'
        template = template.replace(placeholder, val)
    return template


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--audit-root', default='audit-output')
    ap.add_argument('--findings', help='Path to finding-index.json (default: <audit-root>/05-findings/finding-index.json)')
    ap.add_argument('--correlation', help='Path to public-vuln-correlation.json')
    ap.add_argument('--out', default='audit-output/06-report')
    args = ap.parse_args()

    audit_root = pathlib.Path(args.audit_root)
    out_root = pathlib.Path(args.out)

    # ---- gather all artifacts ----
    intake = load_json(audit_root / '00-intake' / 'intake.json')
    scope_md = read_text(audit_root / '00-intake' / 'scope.md')
    profile = load_json(audit_root / '01-profile' / 'package-profile.json')
    scope_sel = load_json(audit_root / '01-profile' / 'selected-scope.json')
    environment = load_json(audit_root / '00-environment' / 'environment-check.json')
    tool_summary = load_json(audit_root / '02-tools' / 'tool-summary.json')
    hypotheses = load_json(audit_root / '03-candidates' / 'ai-hypotheses.json')
    candidate_summary = load_json(audit_root / '03-candidates' / 'candidate-summary.json')
    validation_summary = load_json(audit_root / '04-validation' / 'validation-summary.json')

    findings_path = args.findings or str(audit_root / '05-findings' / 'finding-index.json')
    findings = load_json(pathlib.Path(findings_path), [])
    if isinstance(findings, dict):
        findings = findings.get('findings', [])

    correlations = {}
    if args.correlation:
        corr_data = load_json(pathlib.Path(args.correlation))
        if corr_data:
            for c in corr_data.get('correlations', []):
                correlations[c.get('finding_id')] = c

    report = load_json(out_root / 'machine' / 'report.json')
    bilingual_map = load_json(out_root / 'machine' / 'bilingual-map.json')

    disclosure_artifacts = list((audit_root / '07-disclosure').rglob('*')) if (audit_root / '07-disclosure').exists() else []

    # ---- gather reviews ----
    reviews_dir = audit_root / '03-candidates' / 'reviews'
    reviews = []
    if reviews_dir.exists():
        for f in sorted(reviews_dir.glob('*.json')):
            reviews.append(load_json(f, {}))

    # ---- build all sections ----
    matched_count, not_found_count, sources_set = gather_disclosure_stats(findings, correlations)

    environment = environment or {}
    tool_list = environment.get('tools', []) or (tool_summary or {}).get('tools', [])

    stats = compute_all_stats(findings, candidate_summary, tool_summary)

    values = {
        'executive_summary': build_executive_summary(findings, tool_list, environment, intake, profile, stats),
        'workflow_execution_summary': build_workflow_summary(audit_root),
        'public_matched_count': str(matched_count),
        'public_not_found_count': str(not_found_count),
        'sources_checked': fmt_list(sorted(sources_set)) if sources_set else 'configured sources checked',
        'offline_db_freshness': safe_str(environment.get('offline_db_freshness', '—')),
        'validated_findings_table': build_validated_table(findings, correlations),
        'funnel_table': build_funnel_table(findings, candidate_summary, tool_summary),
        'severity_table': build_severity_table(findings),
        'discovery_method_table': build_discovery_method_table(findings),
        'tool_output_table': build_tool_output_table(findings, tool_summary),
        'risk_overview': build_risk_overview(findings),
        'component_table': build_component_table(findings),
        'finding_details': build_finding_details(findings, correlations),
        'tool_matrix_content': build_tool_matrix_content(audit_root),
        'manual_review_table': build_manual_review_table(findings, audit_root),
        'intake_content': build_intake_content(intake, scope_md),
        'package_profile_content': build_profile_content(profile),
        'scope_selection_content': build_scope_content(scope_sel),
        'tool_scan_content': build_tool_scan_content(environment, tool_summary),
        'ai_hypothesis_content': build_ai_hypothesis_content(hypotheses),
        'candidate_review_content': build_candidate_content(candidate_summary, reviews),
        'validation_content': build_validation_content(validation_summary),
        'cvss_content': build_cvss_content(findings),
        'report_generation_content': build_report_generation_content(report, bilingual_map),
        'disclosure_content': build_disclosure_content(findings, correlations),
    }

    # ---- write outputs ----
    machine_dir = out_root / 'machine'
    machine_dir.mkdir(parents=True, exist_ok=True)
    en_dir = out_root / 'en-US'
    zh_dir = out_root / 'zh-CN'

    for d in [machine_dir, en_dir, zh_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # machine JSON (enhanced with statistics)
    machine_report = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'generator': 'generate_final_report.py',
        'executive_summary': values['executive_summary'],
        'statistics': {
            'funnel': stats['funnel'],
            'severity_distribution': stats['severity_distribution'],
            'discovery_methods': stats['discovery_methods'],
            'tool_output': stats['tool_output'],
            'risk_overview': stats['risk_overview'],
        },
        'public_disclosure': {
            'matched_count': matched_count,
            'not_found_count': not_found_count,
            'sources_checked': sorted(sources_set) if sources_set else [],
            'offline_db_freshness': safe_str(environment.get('offline_db_freshness', '')),
        },
        'steps': {
            '01_intake': {'intake': intake, 'scope_length': len(scope_md)},
            '02_package_profile': profile,
            '03_scope_selection': scope_sel,
            '04_tool_scan': {'environment': environment, 'tool_summary': tool_summary},
            '05_ai_hypotheses': hypotheses,
            '06_candidate_review': {'summary': candidate_summary, 'review_count': len(reviews)},
            '07_validation': validation_summary,
            '08_cvss_scoring': {'scored_findings': len([f for f in findings if f.get('cvss',{}).get('base_score')])},
            '09_bilingual_report': {
                'report_path': str(out_root / 'machine' / 'report.json') if report else None,
                'bilingual_map': bilingual_map,
            },
            '10_progressive_disclosure': {
                'finding_count': len(findings),
                'disclosure_artifact_count': len(disclosure_artifacts),
            },
        },
        'findings': findings,
        'correlations': correlations,
    }
    (machine_dir / 'final-report.json').write_text(json.dumps(machine_report, indent=2, ensure_ascii=False))

    # human-readable reports
    en_template = TEMPLATES / 'en-US' / 'final-summary-report.md'
    zh_template = TEMPLATES / 'zh-CN' / 'final-summary-report.md'

    if en_template.exists():
        en_report = render_template(en_template, values)
        (en_dir / 'final-summary-report.md').write_text(en_report)
        (out_root / 'final-summary-report.md').write_text(en_report)
        print(f'[PVAS-FINAL-REPORT] wrote {en_dir / "final-summary-report.md"}')
    else:
        print(f'[PVAS-FINAL-REPORT] template not found: {en_template}', file=sys.stderr)

    if zh_template.exists():
        zh_report = render_template(zh_template, values)
        (zh_dir / 'final-summary-report.md').write_text(zh_report)
        print(f'[PVAS-FINAL-REPORT] wrote {zh_dir / "final-summary-report.md"}')
    else:
        print(f'[PVAS-FINAL-REPORT] template not found: {zh_template}', file=sys.stderr)

    print(f'[PVAS-FINAL-REPORT] wrote {machine_dir / "final-report.json"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
