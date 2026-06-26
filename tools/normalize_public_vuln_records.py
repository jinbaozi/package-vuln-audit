#!/usr/bin/env python3
"""Normalize public vulnerability records from offline JSON exports.

Supports small OSV/NVD/GHSA/KEV/project-style fixtures. This tool intentionally
normalizes data; it does not decide whether a finding matches.
"""
from __future__ import annotations
import argparse, json, hashlib, pathlib, datetime, sys
VERSION = "0.9.0-alpha9"

def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def as_list(x):
    if x is None: return []
    if isinstance(x, list): return x
    return [x]

def refs_from(obj):
    refs=[]
    for r in as_list(obj.get('references') or obj.get('refs')):
        if isinstance(r, str): refs.append(r)
        elif isinstance(r, dict):
            u=r.get('url') or r.get('href')
            if u: refs.append(u)
    return refs

def normalize_one(obj: dict, source_hint: str, source_file: pathlib.Path) -> dict:
    source = (obj.get('source') or source_hint or 'PROJECT').upper()
    # Detect formats
    if 'cve' in obj and isinstance(obj['cve'], dict):  # NVD v2-ish
        cve = obj['cve']
        vid = cve.get('id') or obj.get('id') or 'UNKNOWN'
        descs = cve.get('descriptions') or []
        summary = ''
        for d in descs:
            if d.get('lang') == 'en': summary = d.get('value',''); break
        refs = [r.get('url') for r in cve.get('references',{}).get('referenceData',[]) if r.get('url')]
        aliases = [vid]
        cwes=[]
        for w in cve.get('weaknesses',[]):
            for d in w.get('description',[]):
                if d.get('value'): cwes.append(d['value'])
        pkg = obj.get('package') or obj.get('project') or ''
        comp = obj.get('component') or ''
        root = summary
        impact = []
    else:
        vid = obj.get('id') or obj.get('cveID') or obj.get('ghsaId') or obj.get('osv_id') or 'UNKNOWN'
        aliases = list(dict.fromkeys([vid] + [str(a) for a in as_list(obj.get('aliases')) if a]))
        summary = obj.get('summary') or obj.get('details') or obj.get('description') or obj.get('shortDescription') or ''
        refs = refs_from(obj)
        if obj.get('source_url'): refs.append(obj['source_url'])
        pkg = obj.get('package') or obj.get('project') or obj.get('product') or ''
        comp = obj.get('component') or obj.get('module') or obj.get('binary') or ''
        cwes = [str(x) for x in as_list(obj.get('cwe') or obj.get('cwes') or obj.get('problem_types'))]
        impact = [str(x) for x in as_list(obj.get('impact') or obj.get('impacts'))]
        root = obj.get('root_cause') or summary
    raw = json.dumps(obj, sort_keys=True)
    return {
        'id': str(vid), 'source': source, 'aliases': aliases,
        'summary': summary, 'package': pkg, 'component': comp,
        'affected_versions': [str(x) for x in as_list(obj.get('affected_versions') or obj.get('versions'))],
        'cwe': cwes, 'impact': impact,
        'references': list(dict.fromkeys([r for r in refs if r])),
        'published': obj.get('published') or obj.get('dateAdded') or '',
        'modified': obj.get('modified') or obj.get('lastModified') or '',
        'files': [str(x) for x in as_list(obj.get('files') or obj.get('source_files'))],
        'functions': [str(x) for x in as_list(obj.get('functions') or obj.get('symbols'))],
        'root_cause': root,
        'provenance': {
            'source': source, 'source_url': obj.get('source_url',''),
            'retrieved_at': obj.get('retrieved_at') or datetime.datetime.utcnow().isoformat()+'Z',
            'source_file': str(source_file), 'record_hash': sha(raw),
            'normalizer_version': VERSION,
        }
    }

def iter_records(path: pathlib.Path):
    if path.is_dir():
        for p in sorted(path.rglob('*.json')):
            yield from iter_records(p)
        return
    try:
        data=json.loads(path.read_text())
    except Exception as e:
        print(f"[PVAS-WARN] failed to read {path}: {e}", file=sys.stderr); return
    source_hint = path.parent.name or path.stem
    if isinstance(data, list):
        for obj in data:
            if isinstance(obj, dict): yield normalize_one(obj, source_hint, path)
    elif isinstance(data, dict):
        # NVD collections, OSV lists, or single record
        if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list):
            for obj in data['vulnerabilities']:
                if isinstance(obj, dict): yield normalize_one(obj, 'NVD', path)
        elif 'advisories' in data and isinstance(data['advisories'], list):
            for obj in data['advisories']:
                if isinstance(obj, dict): yield normalize_one(obj, 'GHSA', path)
        elif 'vulns' in data and isinstance(data['vulns'], list):
            for obj in data['vulns']:
                if isinstance(obj, dict): yield normalize_one(obj, 'OSV', path)
        else:
            yield normalize_one(data, source_hint, path)

def merge_aliases(records):
    # merge duplicate aliases conservatively
    by_alias={}; out=[]
    for r in records:
        key=None
        for a in r.get('aliases',[]):
            if a in by_alias:
                key=by_alias[a]; break
        if key is None:
            idx=len(out); out.append(r)
            for a in r.get('aliases',[]): by_alias[a]=idx
        else:
            base=out[key]
            for fld in ['aliases','references','affected_versions','cwe','impact','files','functions']:
                base[fld]=list(dict.fromkeys(base.get(fld,[])+r.get(fld,[])))
            for fld in ['summary','package','component','root_cause','published','modified']:
                if not base.get(fld) and r.get(fld): base[fld]=r[fld]
    return out

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--input', action='append', help='Input JSON file or directory', default=[])
    ap.add_argument('--sources-dir', help='Offline vuln-db directory')
    ap.add_argument('--out', default='audit-output/machine/correlation/public-vuln-records.json')
    args=ap.parse_args()
    paths=[pathlib.Path(p) for p in args.input]
    if args.sources_dir: paths.append(pathlib.Path(args.sources_dir))
    if not paths: ap.error('provide --input or --sources-dir')
    recs=[]
    for p in paths: recs.extend(iter_records(p))
    recs=merge_aliases(recs)
    out=pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({'records': recs, 'count': len(recs)}, indent=2))
    print(f'[PVAS-PUBLIC-RECORDS] normalized {len(recs)} records -> {out}')
if __name__=='__main__': main()
