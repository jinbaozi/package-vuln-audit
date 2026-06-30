# openEuler CVE Registry (Offline Bundle)

This directory holds the imported openEuler CVE disposition registry used by PVAS public-vulnerability correlation (`correlate_public_vulns.py`).

## Files

| File | Purpose |
|------|---------|
| `manifest.json` | Metadata: data cutoff, record count, source xlsx SHA256 |
| `cve-index.json` | Lightweight CVE → record entries index (correlation loads this) |
| `records.json` | Full records with provenance (audit traceability) |

## Update workflow

1. Obtain an updated `漏洞数据清单.xlsx` from the openEuler vulnerability tracking process (do **not** commit the xlsx; it stays in `.gitignore`).

2. Run the importer from the repository root:

```bash
python3 tools/import_openeuler_vuln_registry.py \
  --xlsx /path/to/漏洞数据清单.xlsx \
  --out offline-bundle/vuln-db/openeuler
```

3. Review `manifest.json` — check `data_cutoff`, `record_count`, and `source_file_hash`.

4. Commit the generated JSON files (`manifest.json`, `cve-index.json`, `records.json`) and this README if changed.

5. Run `./run-tests.sh` to confirm schema and import tests pass.

## Sheet mapping

| xlsx sheet | Registry `category` |
|------------|---------------------|
| sheet2 欧拉不受影响漏洞 | `unaffected` |
| sheet3 欧拉挂起漏洞 | `suspended` |
| sheet4 欧拉已修复漏洞 | `fixed` |

Sheet1 (component ranking) and sheet5 (iso list) are not imported.

## Notes

- Import uses Python stdlib only (`zipfile` + XML); no openpyxl/pandas.
- Hidden Excel rows, invalid CVE IDs, and `#N/A` / `#REF!` cells are skipped.
- `affected_branches` is parsed from the xlsx「修复情况」/「关联分支」Python list string.
- Registry hits mark `disclosure_status` only; they do **not** auto-elevate `disclosure_level`.
