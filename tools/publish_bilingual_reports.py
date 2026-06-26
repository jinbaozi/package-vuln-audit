#!/usr/bin/env python3
"""Publish zh-CN and en-US human-readable reports from machine artifacts."""
from __future__ import annotations
import argparse, json, pathlib


def load_json(p, default):
    path=pathlib.Path(p) if p else None
    if path and path.exists(): return json.loads(path.read_text())
    return default


def findings_list(data):
    if isinstance(data,list): return data
    return data.get('findings',[]) if isinstance(data,dict) else []


def corr_map(data):
    return {c.get('finding_id'):c for c in data.get('correlations',[])} if isinstance(data,dict) else {}


def zh_status(s):
    return {'publicly_disclosed':'已在公开标准来源中匹配到披露记录','possibly_public':'疑似可关联公开记录','not_found_in_configured_sources':'未在已配置公开数据源中发现匹配记录','unknown':'未知'}.get(s,s)


def zh_type(t):
    return {'tool':'传统工具','ai':'AI大模型','manual':'人工审查','fuzz':'模糊测试'}.get(t,t)


def safe_str(v, fallback='—'):
    if v is None: return fallback
    s = str(v)
    return s if s.strip() else fallback


def flatten_poc(pocs):
    if not pocs: return []
    if isinstance(pocs, list):
        return [p for p in pocs if isinstance(p, dict)]
    return []


def flatten_discovery(dm):
    if not dm: return []
    if isinstance(dm, list):
        return [d for d in dm if isinstance(d, dict)]
    return []


def flatten_refs(refs):
    if not refs: return []
    if isinstance(refs, list):
        return [r for r in refs if isinstance(r, dict)]
    return []


def discovery_summary_str(dm):
    parts = flatten_discovery(dm)
    if not parts: return 'unknown'
    return '; '.join(f"{p.get('type','?')}({p.get('tool_name','') or p.get('hypothesis_id','') or '—'})" for p in parts)


def write_finding(lang_root, f, c, en=False):
    fid=f.get('id','FINDING-UNKNOWN')
    dm=flatten_discovery(f.get('discovery_method'))
    pocs=flatten_poc(f.get('poc_test_artifacts'))
    refs=flatten_refs(f.get('public_vulnerability_references'))
    if en:
        d=lang_root/'04-findings'; d.mkdir(parents=True, exist_ok=True)
        lines=[
            f'# Finding {fid}', '',
            '## Summary', safe_str(f.get('summary','—')), '',
            '## Root Cause', safe_str(f.get('root_cause','—')), '',
            '## Source Code Evidence',
            f'- File: `{f.get("source_code_evidence",[{}])[0].get("file","?") if isinstance(f.get("source_code_evidence"),list) and f.get("source_code_evidence") else "?"}`',
            f'- Function: {safe_str(f.get("source_code_evidence",[{}])[0].get("function","?")) if isinstance(f.get("source_code_evidence"),list) and f.get("source_code_evidence") else "?"}',
            f'- Lines: {safe_str(str(f.get("source_code_evidence",[{}])[0].get("start_line","?"))+"-"+str(f.get("source_code_evidence",[{}])[0].get("end_line","?"))) if isinstance(f.get("source_code_evidence"),list) and f.get("source_code_evidence") else "?"}',
            '',
            '## Source-to-Sink Path',
            '```text',
            safe_str(f.get('source_to_sink_path','—')),
            '```', '',
            '## Validation Evidence', safe_str(str(f.get('validation',{}))), '',
            '## CVSS',
            f'- Vector: {safe_str(f.get("cvss",{}).get("vector","—"))}',
            f'- Score: {safe_str(f.get("cvss",{}).get("base_score","—"))}',
            f'- Severity: {safe_str(f.get("cvss",{}).get("severity","—"))}', '',
            '## Fix Recommendation', safe_str(f.get('fix_recommendation','—')), '',
            '## PoC / Test Artifacts',
        ]
        if pocs:
            for p in pocs:
                lang=f" [{p.get('language','')}]" if p.get('language') else ''
                lines.append(f"- `{p.get('path','')}` — {safe_str(p.get('purpose',''))} ({p.get('type','?')}, {p.get('safety_class','?')}){lang}")
        else:
            lines.append('_No PoC artifacts generated for this finding._')
        lines.extend(['', '## Discovery Method'])
        if dm:
            for disc in dm:
                tool=f" (tool: `{disc.get('tool_name','')}`)" if disc.get('tool_name') else ''
                hyp=f" (hypothesis: `{disc.get('hypothesis_id','')}`)" if disc.get('hypothesis_id') else ''
                lines.append(f"- **{disc.get('type','?')}**{tool}{hyp}")
                lines.append(f"  {safe_str(disc.get('description',''))}")
        else:
            lines.append('- Not recorded.')
        lines.extend(['', '## Public Vulnerability Correlation'])
        lines.append(f"- Disclosure status: {safe_str(f.get('disclosure_status','unknown'))}")
        lines.append(f"- Match level: {safe_str(c.get('match_level','M0') if c else 'M0')}")
        if refs:
            for r in refs:
                url=f" ({r.get('url','')})" if r.get('url') else ''
                lines.append(f"- {r.get('source','?')} / {r.get('id','?')}{url}")
        elif c and c.get('matched_records'):
            for m in c['matched_records']:
                links=', '.join(m.get('references',[]) or ([m.get('url')] if m.get('url') else []))
                lines.append(f"- {m.get('source','?')} / {m.get('id','?')} ({links or 'no link'})")
        else:
            lines.append('- No public vulnerability records matched in configured sources.')
        lines.extend(['', '## Disclosure Level', safe_str(f.get('disclosure_level','—')), ''])
    else:
        d=lang_root/'04-漏洞发现'; d.mkdir(parents=True, exist_ok=True)
        lines=[
            f'# 漏洞发现 {fid}', '',
            '## 摘要', safe_str(f.get('summary','—')), '',
            '## 根因', safe_str(f.get('root_cause','—')), '',
            '## 源代码证据',
            f'- 文件：`{f.get("source_code_evidence",[{}])[0].get("file","?") if isinstance(f.get("source_code_evidence"),list) and f.get("source_code_evidence") else "?"}`',
            f'- 函数：{safe_str(f.get("source_code_evidence",[{}])[0].get("function","?")) if isinstance(f.get("source_code_evidence"),list) and f.get("source_code_evidence") else "?"}',
            f'- 行号：{safe_str(str(f.get("source_code_evidence",[{}])[0].get("start_line","?"))+"-"+str(f.get("source_code_evidence",[{}])[0].get("end_line","?"))) if isinstance(f.get("source_code_evidence"),list) and f.get("source_code_evidence") else "?"}',
            '',
            '## 源到汇路径',
            '```text',
            safe_str(f.get('source_to_sink_path','—')),
            '```', '',
            '## 验证证据', safe_str(str(f.get('validation',{}))), '',
            '## CVSS',
            f'- 向量：{safe_str(f.get("cvss",{}).get("vector","—"))}',
            f'- 分数：{safe_str(f.get("cvss",{}).get("base_score","—"))}',
            f'- 严重性：{safe_str(f.get("cvss",{}).get("severity","—"))}', '',
            '## 修复建议', safe_str(f.get('fix_recommendation','—')), '',
            '## PoC / 测试工件',
        ]
        if pocs:
            for p in pocs:
                lang=f" [{p.get('language','')}]" if p.get('language') else ''
                lines.append(f"- `{p.get('path','')}` — {safe_str(p.get('purpose',''))}（{p.get('type','?')}，{p.get('safety_class','?')}）{lang}")
        else:
            lines.append('_此发现未生成 PoC 工件。_')
        lines.extend(['', '## 发现方式'])
        if dm:
            for disc in dm:
                tool=f"（工具：`{disc.get('tool_name','')}`）" if disc.get('tool_name') else ''
                hyp=f"（假设：`{disc.get('hypothesis_id','')}`）" if disc.get('hypothesis_id') else ''
                lines.append(f"- **{zh_type(disc.get('type','?'))}**{tool}{hyp}")
                lines.append(f"  {safe_str(disc.get('description',''))}")
        else:
            lines.append('- 未记录。')
        lines.extend(['', '## 公开漏洞比对结果'])
        lines.append(f"- 公开披露状态：{safe_str(zh_status(f.get('disclosure_status','unknown')))}")
        lines.append(f"- 匹配等级：{safe_str(c.get('match_level','M0') if c else 'M0')}")
        if refs:
            for r in refs:
                url=f"（{r.get('url','')}）" if r.get('url') else ''
                lines.append(f"- {r.get('source','?')} / {r.get('id','?')}{url}")
        elif c and c.get('matched_records'):
            for m in c['matched_records']:
                links='，'.join(m.get('references',[]) or ([m.get('url')] if m.get('url') else []))
                lines.append(f"- {m.get('source','?')} / {m.get('id','?')}（{links or '无链接'}）")
        else:
            lines.append('- 未在已配置公开数据源中发现匹配记录。')
        lines.extend(['', '## 披露等级', safe_str(f.get('disclosure_level','—')), ''])
    path=d/f'{fid}.md'; path.write_text('\n'.join(lines)+'\n'); return path


def disclosure_summary(findings, cm):
    rows=[]
    for f in findings:
        fid=f.get('id','FINDING-UNKNOWN')
        c=cm.get(fid, {})
        dm=flatten_discovery(f.get('discovery_method'))
        matched=[]
        refs=flatten_refs(f.get('public_vulnerability_references'))
        if refs:
            matched=[(r.get('source','?'), r.get('id','?'), '') for r in refs]
        elif c:
            for m in c.get('matched_records',[]):
                matched.append((m.get('source','?'), m.get('id') or ','.join(m.get('aliases',[]) or []) or '?', (m.get('summary','') or '')[:120]))
        rows.append({
            'finding_id': fid,
            'status': f.get('disclosure_status', c.get('status','unknown')),
            'match_level': c.get('match_level','M0'),
            'standard_sources': sorted({x[0] for x in matched}) if matched else list(c.get('checked_sources',[]) or []),
            'record_ids': [x[1] for x in matched],
            'evidence_summary': '; '.join(x[2] for x in matched if x[2]) or 'No matched public record in configured sources.',
            'limitations': c.get('limitations', []) or ([] if c else ['missing correlation artifact']),
            'discovery_method_summary': discovery_summary_str(dm),
        })
    return rows


def write_internal_report(path: pathlib.Path, findings, summary, en=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if en:
        lines=[
            '# Internal Security Report', '',
            '## Executive Summary', '',
            f'**Validated Findings**: {len([f for f in findings if f.get("status")=="Validated"])}',
            f'**Needs Manual Review**: {len([f for f in findings if f.get("status")=="Needs Manual Review"])}',
            '', '## Validated Findings', '',
            '| ID | Severity | CVSS | Component | Discovery | Disclosure Status |',
            '|---|---|---|---|---|---|',
        ]
        for f in findings:
            dm=flatten_discovery(f.get('discovery_method'))
            dms='; '.join(f"{d.get('type','?')}({d.get('tool_name','') or d.get('hypothesis_id','') or '—'})" for d in dm) if dm else 'unknown'
            lines.append(f"| {f.get('id','?')} | {f.get('cvss',{}).get('severity','?')} | {f.get('cvss',{}).get('base_score','?')} | {f.get('affected_component',{}).get('component','?')} | {dms} | {f.get('disclosure_status','unknown')} |")
        lines.extend(['', '## Finding Details', ''])
        for f in findings:
            fid=f.get('id','?')
            dm=flatten_discovery(f.get('discovery_method'))
            pocs=flatten_poc(f.get('poc_test_artifacts'))
            refs=flatten_refs(f.get('public_vulnerability_references'))
            lines.append(f'### {fid}: {f.get("title","?")}')
            lines.append('')
            lines.append(f'- **CVSS**: {f.get("cvss",{}).get("vector","?")} ({f.get("cvss",{}).get("base_score","?")}, {f.get("cvss",{}).get("severity","?")})')
            lines.append(f'- **Component**: {f.get("affected_component",{}).get("component","?")}')
            lines.append(f'- **Disclosure Status**: {f.get("disclosure_status","unknown")}')
            lines.append(f'- **Disclosure Level**: {f.get("disclosure_level","?")}')
            lines.append('')
            lines.append('**Discovery Method**:')
            if dm:
                for d in dm:
                    lines.append(f'- {d.get("type","?")} via `{d.get("tool_name","") or d.get("hypothesis_id","") or "—"}`: {d.get("description","")}')
            else:
                lines.append('- Not recorded.')
            lines.append('')
            lines.append('**PoC Artifacts**:')
            if pocs:
                for p in pocs:
                    lines.append(f'- `{p.get("path","")}` — {p.get("purpose","")}')
            else:
                lines.append('- None generated.')
            lines.append('')
            lines.append('**Public References**:')
            if refs:
                for r in refs:
                    lines.append(f'- {r.get("source","?")} / {r.get("id","?")}{" ("+r.get("url","")+")" if r.get("url") else ""}')
            elif f.get('disclosure_status')=='publicly_disclosed':
                lines.append('- WARNING: disclosed but no references recorded.')
            else:
                lines.append('- None matched.')
            lines.append('')
        lines.extend(['## Candidates', ''])
        cands=[f for f in findings if f.get('status') not in ('Validated','Needs Manual Review')]
        if cands:
            for f in cands:
                lines.append(f'- {f.get("id","?")}: {f.get("title","?")}')
        else:
            lines.append('- No candidate items.')
        lines.extend(['', '## Rejected Summary', '', 'See finding-index.json for rejected items.', ''])
        lines.extend(['## Public Disclosure Status and Standard Source Summary', '',
            '| Finding ID | Disclosure Status | Match Level | Standard Source | Record ID | Evidence Summary | Limitations | Discovery Method |',
            '|---|---|---|---|---|---|---|---|'])
        for r in summary:
            lines.append(f"| {r['finding_id']} | {r['status']} | {r['match_level']} | {', '.join(r['standard_sources']) or 'configured sources checked'} | {', '.join(r['record_ids']) or '—'} | {r['evidence_summary'].replace('|','/')} | {'; '.join(r['limitations']) or '—'} | {r['discovery_method_summary']} |")
        lines.append('')
        lines.append('## Tool Coverage')
        lines.append('See audit-output/02-tools/tool-summary.json for complete tool coverage details.')
    else:
        lines=[
            '# 内部安全报告', '',
            '## 执行摘要', '',
            f'**已验证发现**：{len([f for f in findings if f.get("status")=="Validated"])}',
            f'**需要人工审查**：{len([f for f in findings if f.get("status")=="Needs Manual Review"])}',
            '', '## 已验证发现', '',
            '| ID | 严重性 | CVSS | 组件 | 发现方式 | 披露状态 |',
            '|---|---|---|---|---|---|',
        ]
        for f in findings:
            dm=flatten_discovery(f.get('discovery_method'))
            dms='；'.join(f"{zh_type(d.get('type','?'))}({d.get('tool_name','') or d.get('hypothesis_id','') or '—'})" for d in dm) if dm else '未知'
            lines.append(f"| {f.get('id','?')} | {f.get('cvss',{}).get('severity','?')} | {f.get('cvss',{}).get('base_score','?')} | {f.get('affected_component',{}).get('component','?')} | {dms} | {zh_status(f.get('disclosure_status','unknown'))} |")
        lines.extend(['', '## 发现详情', ''])
        for f in findings:
            fid=f.get('id','?')
            dm=flatten_discovery(f.get('discovery_method'))
            pocs=flatten_poc(f.get('poc_test_artifacts'))
            refs=flatten_refs(f.get('public_vulnerability_references'))
            lines.append(f'### {fid}：{f.get("title","?")}')
            lines.append('')
            lines.append(f'- **CVSS**：{f.get("cvss",{}).get("vector","?")}（{f.get("cvss",{}).get("base_score","?")}，{f.get("cvss",{}).get("severity","?")}）')
            lines.append(f'- **组件**：{f.get("affected_component",{}).get("component","?")}')
            lines.append(f'- **披露状态**：{zh_status(f.get("disclosure_status","unknown"))}')
            lines.append(f'- **披露等级**：{f.get("disclosure_level","?")}')
            lines.append('')
            lines.append('**发现方式**：')
            if dm:
                for d in dm:
                    lines.append(f'- {zh_type(d.get("type","?"))} via `{d.get("tool_name","") or d.get("hypothesis_id","") or "—"}`：{d.get("description","")}')
            else:
                lines.append('- 未记录。')
            lines.append('')
            lines.append('**PoC 工件**：')
            if pocs:
                for p in pocs:
                    lines.append(f'- `{p.get("path","")}` — {p.get("purpose","")}')
            else:
                lines.append('- 未生成。')
            lines.append('')
            lines.append('**公开参考**：')
            if refs:
                for r in refs:
                    lines.append(f'- {r.get("source","?")} / {r.get("id","?")}{"（"+r.get("url","")+"）" if r.get("url") else ""}')
            elif f.get('disclosure_status')=='publicly_disclosed':
                lines.append('- 警告：标记为已披露但未记录参考来源。')
            else:
                lines.append('- 未匹配。')
            lines.append('')
        lines.extend(['## 候选问题', ''])
        cands=[f for f in findings if f.get('status') not in ('Validated','Needs Manual Review')]
        if cands:
            for f in cands:
                lines.append(f'- {f.get("id","?")}：{f.get("title","?")}')
        else:
            lines.append('- 无候选项目。')
        lines.extend(['', '## 已拒绝问题摘要', '', '参见 finding-index.json。', ''])
        lines.extend(['## 公开披露状态与标准来源汇总表', '',
            '| Finding ID | 公开披露状态 | 匹配等级 | 标准来源 | 记录 ID | 证据摘要 | 限制说明 | 发现方法 |',
            '|---|---|---|---|---|---|---|---|'])
        for r in summary:
            zs=zh_status(r['status'])
            lines.append(f"| {r['finding_id']} | {zs} | {r['match_level']} | {', '.join(r['standard_sources']) or '已配置来源'} | {', '.join(r['record_ids']) or '—'} | {r['evidence_summary'].replace('|','/')} | {'；'.join(r['limitations']) or '—'} | {r['discovery_method_summary']} |")
        lines.append('')
        lines.append('## 工具覆盖')
        lines.append('详见 audit-output/02-tools/tool-summary.json。')
    path.write_text('\n'.join(lines)+'\n')


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--findings', required=True)
    ap.add_argument('--correlation')
    ap.add_argument('--poc-root')
    ap.add_argument('--out', default='audit-output')
    args=ap.parse_args()
    out=pathlib.Path(args.out); machine=out/'machine'; zh=out/'zh-CN'; en=out/'en-US'
    for p in [machine, zh, en]: p.mkdir(parents=True, exist_ok=True)
    findings=findings_list(load_json(args.findings, {'findings':[]}))
    cm=corr_map(load_json(args.correlation, {'correlations':[]}))
    pairs=[]
    for f in findings:
        fid=f.get('id','')
        zh_path=write_finding(zh,f,cm.get(fid),en=False)
        en_path=write_finding(en,f,cm.get(fid),en=True)
        pairs.append({'id':fid,'zh':str(zh_path.relative_to(out)),'en':str(en_path.relative_to(out)),'invariants':{'cvss':f.get('cvss',{}),'source_code_evidence':f.get('source_code_evidence',[])}})
    summary = disclosure_summary(findings, cm)
    write_internal_report(zh/'05-内部安全报告'/'internal-security-report.md', findings, summary, en=False)
    write_internal_report(en/'05-internal-security-report'/'internal-security-report.md', findings, summary, en=True)
    report={'package':'','scope':'','findings':findings,'public_disclosure_summary':summary,'generated_outputs':[str(zh),str(en)]}
    (machine/'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False))
    bm={'outputs':{'machine':str(machine.relative_to(out)),'zh_CN':str(zh.relative_to(out)),'en_US':str(en.relative_to(out))},'pairs':pairs}
    (machine/'bilingual-map.json').write_text(json.dumps(bm, indent=2, ensure_ascii=False))
    print(f'[PVAS-BILINGUAL] wrote {machine/"bilingual-map.json"}')
if __name__=='__main__': main()
