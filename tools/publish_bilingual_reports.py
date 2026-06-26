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


def source_ids(c):
    rows=[]
    if not c: return rows
    for m in c.get('matched_records',[]):
        rows.append((m.get('source') or 'unknown', m.get('id') or ','.join(m.get('aliases',[]) or []) or 'unknown', m.get('summary','')[:120]))
    return rows


def write_finding(lang_root, f, c, en=False):
    fid=f.get('id','FINDING-UNKNOWN')
    if en:
        d=lang_root/'04-findings'; d.mkdir(parents=True, exist_ok=True)
        lines=[f'# Finding {fid}', '', '## Summary', f.get('summary','—'), '', '## Public Vulnerability Correlation']
        lines.append(f"- Disclosure status: {c.get('status','unknown') if c else 'unknown'}")
        lines.append(f"- Match level: {c.get('match_level','M0') if c else 'M0'}")
        if not c:
            lines.append('- Limitation: no correlation artifact was provided for this finding.')
    else:
        d=lang_root/'04-漏洞发现'; d.mkdir(parents=True, exist_ok=True)
        lines=[f'# 漏洞发现 {fid}', '', '## 摘要', f.get('summary','—'), '', '## 公开漏洞比对结果']
        lines.append(f"- 公开披露状态：{zh_status(c.get('status','unknown')) if c else '未知'}")
        lines.append(f"- 匹配等级：{c.get('match_level','M0') if c else 'M0'}")
        if not c:
            lines.append('- 限制说明：未提供该发现的公开漏洞关联产物。')
    if c:
        for m in c.get('matched_records',[]):
            links=', '.join(m.get('references',[]) or ([m.get('url')] if m.get('url') else []))
            if en:
                lines.append(f"- Public record: {m.get('source','unknown')} / {m.get('id')} ({links or 'no link'})")
            else:
                lines.append(f"- 标准来源记录：{m.get('source','unknown')} / {m.get('id')}（{links or '无链接'}）")
        for lim in c.get('limitations',[]) or []:
            lines.append(('- Limitation: ' if en else '- 限制说明：') + str(lim))
    path=d/f'{fid}.md'; path.write_text('\n'.join(lines)+'\n'); return path


def disclosure_summary(findings, cm):
    rows=[]
    for f in findings:
        fid=f.get('id','FINDING-UNKNOWN')
        c=cm.get(fid, {})
        matched=source_ids(c)
        rows.append({
            'finding_id': fid,
            'status': c.get('status','unknown'),
            'match_level': c.get('match_level','M0'),
            'standard_sources': sorted({x[0] for x in matched}) if matched else list(c.get('checked_sources',[]) or []),
            'record_ids': [x[1] for x in matched],
            'evidence_summary': '; '.join(x[2] for x in matched if x[2]) or 'No matched public record in configured sources.',
            'limitations': c.get('limitations', []) or ([] if c else ['missing correlation artifact'])
        })
    return rows


def write_internal_report(path: pathlib.Path, findings, summary, en=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if en:
        lines=['# Internal Security Report', '', '## Findings', '']
        if findings:
            for f in findings:
                lines.append(f"- `{f.get('id','FINDING-UNKNOWN')}` — {f.get('summary','No summary')}")
        else:
            lines.append('No admitted findings were provided.')
        lines.extend(['', '## Public Disclosure Status and Standard Source Summary', '', '| Finding ID | Disclosure Status | Match Level | Standard Source | Record ID | Evidence Summary | Limitations |', '|---|---|---|---|---|---|---|'])
        for r in summary:
            lines.append(f"| {r['finding_id']} | {r['status']} | {r['match_level']} | {', '.join(r['standard_sources']) or 'configured sources checked'} | {', '.join(r['record_ids']) or '—'} | {r['evidence_summary'].replace('|','/')} | {'; '.join(r['limitations']) or '—'} |")
    else:
        lines=['# 内部安全报告', '', '## 漏洞发现', '']
        if findings:
            for f in findings:
                lines.append(f"- `{f.get('id','FINDING-UNKNOWN')}` — {f.get('summary','无摘要')}")
        else:
            lines.append('未提供已准入的漏洞发现。')
        lines.extend(['', '## 公开披露状态与标准来源汇总表', '', '| Finding ID | 公开披露状态 | 匹配等级 | 标准来源 | 记录 ID | 证据摘要 | 限制说明 |', '|---|---|---|---|---|---|---|'])
        for r in summary:
            lines.append(f"| {r['finding_id']} | {zh_status(r['status'])} | {r['match_level']} | {', '.join(r['standard_sources']) or '已配置来源'} | {', '.join(r['record_ids']) or '—'} | {r['evidence_summary'].replace('|','/')} | {'；'.join(r['limitations']) or '—'} |")
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
