#!/usr/bin/env python3
import argparse, json, pathlib, re, sys
import xml.etree.ElementTree as ET

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from pvas_io import load_json, write_json

def add_candidate(cands, cid, title, component, file=None, line=None, evidence=None, score=0):
    loc={'file':file or 'unknown'}
    if line:
        loc['start_line']=int(line); loc['end_line']=int(line)
    cands.append({'id':cid,'type':'T-CAND','status':'Raw Tool Hit','title':title,'component':component,'profile':'unknown','source_locations':[loc],'evidence':evidence or {},'confidence':'low','provisional_severity':'unknown','rank_score':score,'missing_evidence':['source-to-sink','validation'],'disclosure_level':'D0-internal-candidate'})

CPPCHECK_RE = re.compile(
    r'^(?P<file>.+?):(?P<line>\d+):(?:(?P<column>\d+):)?\s*'
    r'(?P<severity>error|warning|style|performance|portability|information):\s*'
    r'(?P<message>.*?)(?:\s*\[(?P<id>[^\]]+)\])?\s*$',
    re.I,
)
CPPCHECK_SECURITY_TERMS = (
    'array', 'bounds', 'buffer', 'crash', 'dangling', 'deadlock', 'doublefree',
    'free', 'leak', 'memory', 'mem', 'null', 'overflow', 'resource', 'uninit',
    'unsafe', 'useafter', 'zerodiv',
)
CPPCHECK_HIGH_VALUE_SEVERITIES = {'error', 'warning'}
CPPCHECK_COVERAGE_LIMITATION_IDS = {
    'toomanyconfigs',
    'unknownmacro',
    'syntaxerror',
    'normalchecklevelmaxbranches',
}


def parse_cppcheck_line(line):
    m = CPPCHECK_RE.match(line)
    if not m:
        return None
    return {
        'file': m.group('file'),
        'line': m.group('line'),
        'severity': (m.group('severity') or '').lower(),
        'message': (m.group('message') or '').strip(),
        'id': (m.group('id') or '').strip(),
    }


def cppcheck_is_high_value(item):
    cid = item.get('id', '').lower()
    msg = item.get('message', '').lower()
    severity = item.get('severity', '')
    if severity in CPPCHECK_HIGH_VALUE_SEVERITIES:
        return True
    return any(term in cid or term in msg for term in CPPCHECK_SECURITY_TERMS)


def cppcheck_limitation_id(item):
    cid = (item.get('id') or '').strip()
    if cid.lower() in CPPCHECK_COVERAGE_LIMITATION_IDS:
        return cid
    return ''


def parse_cppcheck_xml(path):
    items = []
    try:
        root = ET.fromstring(path.read_text(errors='ignore'))
    except (OSError, ET.ParseError):
        return items
    for error in root.findall('.//error'):
        location = error.find('location')
        items.append({
            'file': location.get('file', '') if location is not None else '',
            'line': location.get('line', '') if location is not None else '',
            'severity': (error.get('severity') or '').lower(),
            'message': (error.get('msg') or error.get('verbose') or '').strip(),
            'id': (error.get('id') or '').strip(),
        })
    return items


def iter_cppcheck_items(raw):
    cpp = raw / 'cppcheck.out'
    if cpp.exists():
        text = cpp.read_text(errors='ignore')
        if text.lstrip().startswith('<?xml') or text.lstrip().startswith('<results'):
            yield from parse_cppcheck_xml(cpp)
        else:
            for line in text.splitlines():
                item = parse_cppcheck_line(line)
                if item:
                    yield item
    xml = raw / 'cppcheck.xml'
    if xml.exists():
        yield from parse_cppcheck_xml(xml)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--tools-dir', default='audit-output/02-tools/raw'); ap.add_argument('--out', default='audit-output/03-candidates/raw-candidates.json'); args=ap.parse_args()
    raw=pathlib.Path(args.tools_dir); c=[]; n=1; summaries={}
    sem=raw/'semgrep.json'
    if sem.exists():
        try:
            data=load_json(sem, default={})
            for r in data.get('results',[])[:200]:
                add_candidate(c, f'T-CAND-{n:04d}', r.get('extra',{}).get('message','Semgrep result'), 'semgrep', r.get('path'), r.get('start',{}).get('line'), {'tool_refs':['semgrep']}, 10); n+=1
        except Exception as e:
            print(f'[PVAS-TOOL] Warning: failed to parse semgrep.json: {e}', file=sys.stderr)
    rg=raw/'rg.out'
    if rg.exists():
        for line in rg.read_text(errors='ignore').splitlines()[:300]:
            m=re.match(r'([^:]+):(\d+):(.*)', line)
            if m:
                add_candidate(c, f'T-CAND-{n:04d}', 'Dangerous API or high-risk pattern', 'rg', m.group(1), m.group(2), {'tool_refs':['rg'], 'sink':m.group(3).strip()[:200]}, 5); n+=1
    cpp_items = list(iter_cppcheck_items(raw))
    if cpp_items:
        total=0; promoted=0; suppressed=0; limitation_count=0; by_severity={}; by_id={}; limitations={}
        for item in cpp_items:
            total+=1
            sev=item['severity']; by_severity[sev]=by_severity.get(sev,0)+1
            cid=item['id'] or 'unknown'; by_id[cid]=by_id.get(cid,0)+1
            limitation_id=cppcheck_limitation_id(item)
            if limitation_id:
                limitation_count+=1
                limitations[limitation_id]=limitations.get(limitation_id,0)+1
                continue
            if not cppcheck_is_high_value(item):
                suppressed+=1
                continue
            if not item.get('file') or not item.get('line'):
                suppressed+=1
                continue
            title=(item['message'] or 'Cppcheck result')[:120]
            evidence={'tool_refs':['cppcheck'], 'cppcheck_severity':item['severity'], 'cppcheck_id':item['id'], 'message':item['message']}
            add_candidate(c, f'T-CAND-{n:04d}', title, 'cppcheck', item['file'], item['line'], evidence, 8)
            n+=1; promoted+=1
        summaries['cppcheck']={
            'total_results': total,
            'promoted_count': promoted,
            'low_value_suppressed_count': suppressed,
            'coverage_limitation_count': limitation_count,
            'coverage_limitations': limitations,
            'by_severity': by_severity,
            'by_id': by_id,
        }
    write_json(args.out, {'candidates': c, 'tool_summaries': summaries})
if __name__=='__main__': main()
