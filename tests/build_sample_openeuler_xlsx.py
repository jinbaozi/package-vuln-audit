#!/usr/bin/env python3
"""Generate minimal synthetic openEuler registry xlsx for CI tests (stdlib zipfile only)."""
from __future__ import annotations
import pathlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / 'tests' / 'fixtures' / 'sample-openeuler-registry.xlsx'

CONTENT_TYPES = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet4.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"""

RELS = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

WORKBOOK_RELS = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet3.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet4.xml"/>
  <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
  <Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

WORKBOOK = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="欧拉不受影响漏洞" sheetId="2" r:id="rId1"/>
    <sheet name="欧拉挂起漏洞" sheetId="3" r:id="rId2"/>
    <sheet name="欧拉已修复漏洞" sheetId="4" r:id="rId3"/>
  </sheets>
</workbook>""".encode('utf-8')

STYLES = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1"><font/></fonts>
  <fills count="1"><fill/></fills>
  <borders count="1"><border/></borders>
  <cellStyleXfs count="1"><xf/></cellStyleXfs>
  <cellXfs count="1"><xf/></cellXfs>
</styleSheet>"""

STRINGS = [
    'CVE编号', '风险等级', '修复情况', '软件包名', '组件位置',
    '序号', '关联分支', '包名',
    '数据统计日期截止2026.06.01',
    'CVE-2026-0001', '高危', "['master']", 'pkg-a', 'iso',
    'CVE-2026-0002', '中危', "['openEuler-24.03-LTS']", 'pkg-b', 'iso',
    'CVE-2026-0003', '低危', '[]', 'pkg-c', 'src',
    'CVE-2026-0004', '严重', "['master', 'openEuler-22.03-LTS-SP4']", 'pkg-d', 'iso',
    'CVE-2026-0005', '中危', "['master']", 'pkg-e', 'iso',
    'CVE-2026-0006', '高危', "['master']", 'pkg-f', 'iso',
    '#N/A', '#REF!',
]


def shared_strings_xml() -> bytes:
    parts = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>']
    parts.append('<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="%d" uniqueCount="%d">' % (len(STRINGS), len(STRINGS)))
    for s in STRINGS:
        esc = s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        parts.append(f'<si><t>{esc}</t></si>')
    parts.append('</sst>')
    return ''.join(parts).encode('utf-8')


def si(name: str) -> int:
    return STRINGS.index(name)


def cell(col: str, row: int, string_idx: int) -> str:
    return f'<c r="{col}{row}" t="s"><v>{string_idx}</v></c>'


def cell_num(col: str, row: int, value: int) -> str:
    return f'<c r="{col}{row}"><v>{value}</v></c>'


def row_xml(rnum: int, cells: list[str], hidden: bool = False) -> str:
    attrs = f' r="{rnum}"'
    if hidden:
        attrs += ' hidden="1"'
    return f'<row{attrs}>{"".join(cells)}</row>'


def sheet2_xml() -> bytes:
    rows = [
        row_xml(1, []),
        row_xml(2, [
            cell('A', 2, si('CVE编号')), cell('B', 2, si('风险等级')),
            cell('C', 2, si('修复情况')), cell('D', 2, si('软件包名')),
            cell('E', 2, si('组件位置')),
        ]),
        row_xml(3, [
            cell('A', 3, si('CVE-2026-0001')), cell('B', 3, si('高危')),
            cell('C', 3, si("['master']")), cell('D', 3, si('pkg-a')),
            cell('E', 3, si('iso')),
        ]),
        row_xml(4, [
            cell('A', 4, si('CVE-2026-0002')), cell('B', 4, si('中危')),
            cell('C', 4, si("['openEuler-24.03-LTS']")), cell('D', 4, si('pkg-b')),
            cell('E', 4, si('#N/A')),
        ], hidden=True),
    ]
    body = ''.join(rows)
    xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>{body}</sheetData>
</worksheet>"""
    return xml.encode('utf-8')


def sheet3_xml() -> bytes:
    rows = [
        row_xml(1, [
            cell('A', 1, si('序号')), cell('B', 1, si('CVE编号')),
            cell('C', 1, si('风险等级')), cell('D', 1, si('关联分支')),
            cell('E', 1, si('包名')), cell('F', 1, si('组件位置')),
        ]),
        row_xml(2, [
            cell_num('A', 2, 1), cell('B', 2, si('CVE-2026-0003')),
            cell('C', 2, si('低危')), cell('D', 2, si('[]')),
            cell('E', 2, si('pkg-c')), cell('F', 2, si('#REF!')),
        ]),
        row_xml(3, [
            cell_num('A', 3, 2), cell('B', 3, si('CVE-2026-0004')),
            cell('C', 3, si('严重')), cell('D', 3, si("['master', 'openEuler-22.03-LTS-SP4']")),
            cell('E', 3, si('pkg-d')), cell('F', 3, si('iso')),
        ]),
    ]
    body = ''.join(rows)
    xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>{body}</sheetData>
</worksheet>"""
    return xml.encode('utf-8')


def sheet4_xml() -> bytes:
    rows = [
        row_xml(1, [cell('A', 1, si('数据统计日期截止2026.06.01'))]),
        row_xml(2, [
            cell('A', 2, si('CVE编号')), cell('B', 2, si('风险等级')),
            cell('C', 2, si('修复情况')), cell('D', 2, si('软件包名')),
            cell('E', 2, si('组件位置')),
        ]),
        row_xml(3, [
            cell('A', 3, si('CVE-2026-0005')), cell('B', 3, si('中危')),
            cell('C', 3, si("['master']")), cell('D', 3, si('pkg-e')),
            cell('E', 3, si('iso')),
        ]),
        row_xml(4, [
            cell('A', 4, si('CVE-2026-0006')), cell('B', 4, si('高危')),
            cell('C', 4, si("['master']")), cell('D', 4, si('pkg-f')),
            cell('E', 4, si('iso')),
        ]),
    ]
    body = ''.join(rows)
    xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>{body}</sheetData>
</worksheet>"""
    return xml.encode('utf-8')


def build(out: pathlib.Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', CONTENT_TYPES)
        z.writestr('_rels/.rels', RELS)
        z.writestr('xl/workbook.xml', WORKBOOK)
        z.writestr('xl/_rels/workbook.xml.rels', WORKBOOK_RELS)
        z.writestr('xl/sharedStrings.xml', shared_strings_xml())
        z.writestr('xl/styles.xml', STYLES)
        z.writestr('xl/worksheets/sheet2.xml', sheet2_xml())
        z.writestr('xl/worksheets/sheet3.xml', sheet3_xml())
        z.writestr('xl/worksheets/sheet4.xml', sheet4_xml())
    print(f'wrote {out}')


if __name__ == '__main__':
    build(OUT)
