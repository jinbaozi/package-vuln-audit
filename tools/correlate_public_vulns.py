#!/usr/bin/env python3
"""Correlate Validated Findings with normalized public vulnerability records."""
from __future__ import annotations
import argparse, json, pathlib, re

def load_findings(path: pathlib.Path):
    data=json.loads(path.read_text())
    if isinstance(data, list): return data
    if 'findings' in data: return data['findings']
    if 'id' in data: return [data]
    return []

def load_records(path: pathlib.Path):
    data=json.loads(path.read_text())
    if isinstance(data, list): return data
    return data.get('records', [])

def toks(s):
    return set(re.findall(r'[A-Za-z0-9_./+-]{3,}', (s or '').lower()))

def finding_fp(f):
    comp=f.get('affected_component',{})
    src=f.get('source_code_evidence',[]) or []
    files=[x.get('file','') for x in src if isinstance(x,dict)]
    funcs=[x.get('function','') for x in src if isinstance(x,dict) and x.get('function')]
    val=f.get('validation',{}) if isinstance(f.get('validation'),dict) else {}
    return {
        'id':f.get('id',''), 'status':f.get('status',''),
        'package': comp.get('package','') or f.get('package',''),
        'version': comp.get('version_or_commit','') or f.get('version',''),
        'component': comp.get('component','') or f.get('component',''),
        'files': files, 'functions': funcs,
        'root_cause': f.get('root_cause','') or f.get('summary','') or f.get('title',''),
        'summary': f.get('summary','') or f.get('title',''),
        'cwe': f.get('cwe',[]) if isinstance(f.get('cwe'),list) else [],
        'impact': toks(f.get('security_impact','') + ' ' + json.dumps(val)),
    }

def score_record(fp, r):
    evidence=[]; score=0
    pkg=(r.get('package') or '').lower(); fpkg=fp['package'].lower()
    if pkg and fpkg and (pkg==fpkg or pkg in fpkg or fpkg in pkg):
        score+=30; evidence.append('package')
    comp=(r.get('component') or '').lower(); fcomp=fp['component'].lower()
    if comp and fcomp and (comp==fcomp or comp in fcomp or fcomp in comp):
        score+=20; evidence.append('component')
    if fp['version'] and fp['version'] in ' '.join(r.get('affected_versions',[])):
        score+=15; evidence.append('version-range')
    rfiles=set(r.get('files') or [])
    if rfiles and any(any(rf and (rf in ff or ff in rf) for rf in rfiles) for ff in fp['files']):
        score+=25; evidence.append('source-file')
    rfuncs=set(r.get('functions') or [])
    if rfuncs and any(fn in rfuncs for fn in fp['functions']):
        score+=25; evidence.append('function')
    # root-cause weighted token overlap
    rt=toks(r.get('root_cause','')+' '+r.get('summary',''))
    ft=toks(fp['root_cause']+' '+fp['summary'])
    overlap=rt & ft
    if len(overlap) >= 5:
        score+=20; evidence.append('root-cause')
    elif len(overlap) >= 2:
        score+=8; evidence.append('textual-similarity')
    rcwe=set(r.get('cwe') or [])
    if rcwe and rcwe & set(fp['cwe']):
        score+=10; evidence.append('cwe')
    if r.get('references'):
        score+=5; evidence.append('public-link')
    # Determine level conservatively
    if 'package' in evidence and ('source-file' in evidence or 'function' in evidence or ('component' in evidence and 'root-cause' in evidence)):
        level='M3'
    elif score >= 45 and 'package' in evidence:
        level='M2'
    elif score >= 15:
        level='M1'
    else:
        level='M0'
    return score, level, evidence

def status_for(level, source_ok=True):
    if not source_ok: return 'unknown'
    return {'M3':'publicly_disclosed','M2':'possibly_public','M1':'possibly_public','M0':'not_found_in_configured_sources'}[level]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--findings', required=True)
    ap.add_argument('--records', required=True)
    ap.add_argument('--out', default='audit-output/machine/correlation/public-vuln-correlation.json')
    ap.add_argument('--checked-sources', default='NVD,OSV,GHSA,CVE,CISA-KEV')
    args=ap.parse_args()
    findings=load_findings(pathlib.Path(args.findings))
    records=load_records(pathlib.Path(args.records))
    corrs=[]
    for f in findings:
        fp=finding_fp(f)
        if fp['status'] != 'Validated':
            continue
        ranked=[]
        for r in records:
            score, level, evidence=score_record(fp,r)
            if level!='M0':
                ranked.append({'record':r,'score':score,'match_level':level,'match_evidence':evidence})
        ranked.sort(key=lambda x:x['score'], reverse=True)
        if ranked:
            best=ranked[0]
            level=best['match_level']
            status=status_for(level)
            matched=[{
                'source':m['record'].get('source'), 'id':m['record'].get('id'), 'aliases':m['record'].get('aliases',[]),
                'url': (m['record'].get('references') or [''])[0], 'references':m['record'].get('references',[]),
                'summary':m['record'].get('summary',''), 'confidence':min(1.0, m['score']/100),
                'match_evidence':m['match_evidence'], 'match_level':m['match_level'], 'provenance':m['record'].get('provenance',{})
            } for m in ranked[:3]]
        else:
            level='M0'; status='not_found_in_configured_sources'; matched=[]
        corrs.append({'finding_id':fp['id'],'status':status,'match_level':level,'matched_records':matched,'checked_sources':[s.strip() for s in args.checked_sources.split(',') if s.strip()],'limitations':[]})
    out=pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({'checked_sources':[s.strip() for s in args.checked_sources.split(',') if s.strip()],'correlations':corrs}, indent=2))
    print(f'[PVAS-CORRELATION] wrote {out}')
if __name__=='__main__': main()
