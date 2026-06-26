#!/usr/bin/env python3
"""Fetch public vulnerability source metadata or emit a fetch plan.

This tool is conservative: without --allow-network it writes a plan describing
what would be fetched, which supports offline/air-gapped environments.
"""
from __future__ import annotations
import argparse, json, pathlib, datetime, urllib.request, urllib.parse
SOURCES={
  'nvd':'https://services.nvd.nist.gov/rest/json/cves/2.0',
  'osv':'https://api.osv.dev/v1/query',
  'ghsa':'https://api.github.com/graphql',
  'cve':'https://cveawg.mitre.org/api/cve',
  'kev':'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--sources', default='nvd,osv,ghsa,kev')
    ap.add_argument('--package', default='')
    ap.add_argument('--cve', default='')
    ap.add_argument('--out', default='audit-output/machine/correlation/cache')
    ap.add_argument('--allow-network', action='store_true')
    args=ap.parse_args()
    out=pathlib.Path(args.out); out.mkdir(parents=True, exist_ok=True)
    rows=[]
    for src in [s.strip() for s in args.sources.split(',') if s.strip()]:
        url=SOURCES.get(src, src)
        row={'source':src,'url':url,'retrieved_at':datetime.datetime.utcnow().isoformat()+'Z','status':'planned'}
        if args.allow_network and src=='kev':
            data=urllib.request.urlopen(url, timeout=30).read()
            p=out/f'{src}.json'; p.write_bytes(data)
            row.update({'status':'fetched','source_file':str(p),'bytes':len(data)})
        elif args.allow_network and src=='nvd' and args.cve:
            full=url+'?cveId='+urllib.parse.quote(args.cve)
            data=urllib.request.urlopen(full, timeout=30).read()
            p=out/f'{args.cve}.nvd.json'; p.write_bytes(data)
            row.update({'status':'fetched','source_file':str(p),'url':full,'bytes':len(data)})
        else:
            row['note']='Network fetch not performed; use offline-bundle/vuln-db or rerun with --allow-network where permitted.'
        rows.append(row)
    (out/'fetch-plan.json').write_text(json.dumps({'sources':rows}, indent=2))
    print(f'[PVAS-FETCH-PLAN] wrote {out/"fetch-plan.json"}')
if __name__=='__main__': main()
