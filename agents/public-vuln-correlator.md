# Public Vulnerability Correlator

Compare Validated Findings against normalized public vulnerability records and the openEuler CVE registry index. Use evidence-weighted matching. Only M3 confirmed evidence may mark a finding as publicly_disclosed. M1/M2 remain possibly_public. Do not claim global non-disclosure; use not_found_in_configured_sources only for configured sources that were checked.

## M3-CVE (openEuler-Registry)

When `extract_cve_ids(finding)` yields a CVE ID present in `offline-bundle/vuln-db/openeuler/cve-index.json`, emit:

- `status`: `publicly_disclosed`
- `match_level`: `M3`
- `matched_records`: `{source: openEuler-Registry, id, category, package, ...}`

Registry hits take priority over NVD/OSV fuzzy scoring for the same finding.

The registry `category` (unaffected / suspended / fixed) is openEuler disposition metadata for D2 internal reports. It does **not** downgrade public disclosure status and must **not** trigger `disclosure_level` escalation or D3/D4 draft generation.

Write correlation output to `audit-output/machine/correlation/public-vuln-correlation.json` only. Finding field updates are performed by `apply_correlation_to_findings.py` (disclosure_status + refs; disclosure_level unchanged).

Coordinator must not load L4 registry files (`cve-index.json`, `records.json` full dumps). Read L1 correlation summaries only.
