#!/usr/bin/env python3
"""Import openEuler CVE registry from 漏洞数据清单.xlsx (stdlib zipfile + xml only)."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone

NS = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
REL_NS = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id'

SCHEMA_VERSION = '1.0'
SOURCE = 'openEuler-Registry'
CVE_RE = re.compile(r'^CVE-\d{4}-\d+$', re.I)
INVALID_CELL = {'#N/A', '#REF!', '#VALUE!', '#NAME?'}
DATA_CUTOFF_RE = re.compile(r'(\d{4})[.\-/](\d{2})[.\-/](\d{2})')

SHEET_SPECS = {
    'sheet2.xml': ('unaffected', '欧拉不受影响漏洞'),
    'sheet3.xml': ('suspended', '欧拉挂起漏洞'),
    'sheet4.xml': ('fixed', '欧拉已修复漏洞'),
}

HEADER_ALIASES = {
    'cve_id': ('CVE编号',),
    'risk_level': ('风险等级',),
    'branches': ('修复情况', '关联分支'),
    'package': ('软件包名', '包名'),
    'component_location': ('组件位置',),
}


def col_to_idx(col: str) -> int:
    n = 0
    for ch in col:
        n = n * 26 + (ord(ch) - ord('A') + 1)
    return n - 1


def idx_to_col(idx: int) -> str:
    idx += 1
    out = []
    while idx:
        idx, rem = divmod(idx - 1, 26)
        out.append(chr(rem + ord('A')))
    return ''.join(reversed(out))


def parse_cell_ref(ref: str) -> tuple[int, int]:
    m = re.match(r'([A-Z]+)(\d+)', ref)
    if not m:
        raise ValueError(f'bad cell ref: {ref}')
    return col_to_idx(m.group(1)), int(m.group(2)) - 1


def load_shared_strings(zf: zipfile.ZipFile) -> list[str]:
    root = ET.fromstring(zf.read('xl/sharedStrings.xml'))
    out: list[str] = []
    for si in root.findall('.//m:si', NS):
        t = si.find('m:t', NS)
        if t is not None and t.text is not None:
            out.append(t.text)
            continue
        parts: list[str] = []
        for node in si.findall('.//m:t', NS):
            if node.text:
                parts.append(node.text)
        out.append(''.join(parts))
    return out


def cell_value(cell: ET.Element, strings: list[str]) -> str:
    t = cell.get('t')
    v = cell.find('m:v', NS)
    if v is None or v.text is None:
        return ''
    raw = v.text
    if t == 's':
        try:
            return strings[int(raw)]
        except (ValueError, IndexError):
            return ''
    if t == 'inlineStr':
        is_el = cell.find('m:is/m:t', NS)
        return is_el.text if is_el is not None and is_el.text else ''
    return raw


def parse_sheet_rows(xml_bytes: bytes, strings: list[str]) -> list[tuple[int, bool, dict[int, str]]]:
    root = ET.fromstring(xml_bytes)
    parsed: list[tuple[int, bool, dict[int, str]]] = []
    for row in root.findall('.//m:sheetData/m:row', NS):
        r_attr = row.get('r')
        row_num = int(r_attr) if r_attr else 0
        hidden = row.get('hidden') in ('1', 'true')
        cells: dict[int, str] = {}
        for cell in row.findall('m:c', NS):
            ref = cell.get('r')
            if not ref:
                continue
            col_idx, _ = parse_cell_ref(ref)
            cells[col_idx] = cell_value(cell, strings).strip()
        parsed.append((row_num, hidden, cells))
    return parsed


def find_header_row(rows: list[tuple[int, bool, dict[int, str]]]) -> tuple[int, dict[str, int]] | None:
    for row_num, _hidden, cells in rows[:5]:
        headers = {idx: val for idx, val in cells.items() if val}
        inv = {val: idx for idx, val in headers.items()}
        if 'CVE编号' not in inv:
            continue
        mapping: dict[str, int] = {}
        for field, aliases in HEADER_ALIASES.items():
            for alias in aliases:
                if alias in inv:
                    mapping[field] = inv[alias]
                    break
        if 'cve_id' not in mapping:
            continue
        return row_num, mapping
    return None


def parse_branches(raw: str) -> list[str]:
    raw = (raw or '').strip()
    if not raw or raw in INVALID_CELL or raw == '[]':
        return []
    try:
        val = ast.literal_eval(raw)
    except (SyntaxError, ValueError):
        return []
    if isinstance(val, list):
        return [str(x).strip() for x in val if str(x).strip()]
    return []


def normalize_cve(raw: str) -> str | None:
    raw = (raw or '').strip()
    if not raw or raw in INVALID_CELL:
        return None
    cve = raw.upper()
    if not CVE_RE.match(cve):
        return None
    return cve


def clean_component(raw: str) -> str:
    raw = (raw or '').strip()
    if not raw or raw in INVALID_CELL:
        return ''
    return raw


def extract_data_cutoff(strings: list[str], rows_sheet4: list[tuple[int, bool, dict[int, str]]]) -> str:
    for _row_num, _hidden, cells in rows_sheet4[:3]:
        for val in cells.values():
            m = DATA_CUTOFF_RE.search(val)
            if m:
                return f'{m.group(1)}-{m.group(2)}-{m.group(3)}'
    for val in strings[:20]:
        m = DATA_CUTOFF_RE.search(val)
        if m:
            return f'{m.group(1)}-{m.group(2)}-{m.group(3)}'
    return ''


def parse_records(
    zf: zipfile.ZipFile,
    strings: list[str],
    source_file: str,
    imported_at: str,
) -> tuple[list[dict], str]:
    records: list[dict] = []
    data_cutoff = ''

    for sheet_file, (category, sheet_name) in SHEET_SPECS.items():
        path = f'xl/worksheets/{sheet_file}'
        if path not in zf.namelist():
            continue
        rows = parse_sheet_rows(zf.read(path), strings)
        if sheet_file == 'sheet4.xml' and not data_cutoff:
            data_cutoff = extract_data_cutoff(strings, rows)
        header = find_header_row(rows)
        if not header:
            continue
        header_row_num, col_map = header
        for row_num, hidden, cells in rows:
            if row_num <= header_row_num:
                continue
            if hidden:
                continue
            cve_id = normalize_cve(cells.get(col_map.get('cve_id', -1), ''))
            if not cve_id:
                continue
            package = cells.get(col_map.get('package', -1), '').strip()
            if not package or package in INVALID_CELL:
                continue
            branches_raw = cells.get(col_map.get('branches', -1), '') if 'branches' in col_map else ''
            risk = cells.get(col_map.get('risk_level', -1), '').strip() if 'risk_level' in col_map else ''
            component = clean_component(cells.get(col_map.get('component_location', -1), ''))
            record = {
                'cve_id': cve_id,
                'category': category,
                'risk_level': risk,
                'affected_branches': parse_branches(branches_raw),
                'package': package,
                'component_location': component,
                'provenance': {
                    'source_file': source_file,
                    'sheet': sheet_name,
                    'sheet_row': row_num,
                    'imported_at': imported_at,
                },
            }
            records.append(record)

    if not data_cutoff:
        data_cutoff = extract_data_cutoff(strings, [])
    return records, data_cutoff


def build_cve_index(records: list[dict]) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}
    for rec in records:
        entry = {
            'cve_id': rec['cve_id'],
            'category': rec['category'],
            'risk_level': rec.get('risk_level', ''),
            'package': rec['package'],
            'component_location': rec.get('component_location', ''),
            'affected_branches': rec.get('affected_branches', []),
        }
        index.setdefault(rec['cve_id'], []).append(entry)
    return index


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def import_registry(xlsx_path: pathlib.Path, out_dir: pathlib.Path) -> dict:
    imported_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    source_file = xlsx_path.name
    file_hash = sha256_file(xlsx_path)

    with zipfile.ZipFile(xlsx_path) as zf:
        strings = load_shared_strings(zf)
        records, data_cutoff = parse_records(zf, strings, source_file, imported_at)

    cve_index = build_cve_index(records)
    record_count = len(records)

    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        'schema_version': SCHEMA_VERSION,
        'source': SOURCE,
        'data_cutoff': data_cutoff,
        'record_count': record_count,
        'last_updated': imported_at,
        'source_file': source_file,
        'source_file_hash': file_hash,
        'imported_at': imported_at,
    }
    records_doc = {
        'schema_version': SCHEMA_VERSION,
        'source': SOURCE,
        'data_cutoff': data_cutoff,
        'record_count': record_count,
        'records': records,
    }
    index_doc = {
        'schema_version': SCHEMA_VERSION,
        'record_count': record_count,
        'index': cve_index,
    }

    (out_dir / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (out_dir / 'records.json').write_text(json.dumps(records_doc, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (out_dir / 'cve-index.json').write_text(json.dumps(index_doc, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description='Import openEuler CVE registry xlsx to offline JSON bundle')
    ap.add_argument('--xlsx', required=True, type=pathlib.Path, help='Path to 漏洞数据清单.xlsx')
    ap.add_argument('--out', required=True, type=pathlib.Path, help='Output directory')
    args = ap.parse_args()

    if not args.xlsx.is_file():
        print(f'error: xlsx not found: {args.xlsx}', file=sys.stderr)
        return 2

    manifest = import_registry(args.xlsx.resolve(), args.out.resolve())
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
