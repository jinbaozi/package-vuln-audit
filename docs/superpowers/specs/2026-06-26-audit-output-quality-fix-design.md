# Audit Output Quality Fix Design

**Date**: 2026-06-26
**Status**: Approved
**Scope**: Fix 12 identified issues in audit-output workflow compliance, tool correctness, output quality, and schema conformance

---

## 1. Background

A full audit of `package-vuln-audit-skill` was run against GNU Autoconf 2.71, producing output under `audit-output/`. Comparison of the output against the skill's workflow specification (SKILL.md, workflows/, schemas/) revealed **12 issues** spanning 5 categories:

| Category | Issues |
|----------|--------|
| Missing generated files | No `environment-check.json`, `tool-install-plan.md`, `context-budget.json` |
| Path/label inconsistencies | PoC at `machine/` instead of `04-validation/`; `report-completeness.json` path shift; `A-HYP-*` vs `A-CAND-*` |
| Content quality | Placeholder finding reports (all `—`); Final Summary showing "0 Validated Findings"; PoC skipped despite Validated status; Internal Report CVSS showing `?` |
| Schema non-compliance | `tool-summary.json` uses wrong structure; `correlation.json` missing `match_level` |
| Validation reliability | `report-completeness.json` passed despite placeholder content |

Root cause analysis revealed the issues stem from two sources: (1) tool/script bugs in field name handling and validation depth, and (2) workflow process gaps where required steps were not triggered.

---

## 2. Fix Domains

The 12 issues are grouped into **6 fix domains**, each covering related tools, workflows, and quality gates.

### Domain 1: Environment & Step Completeness

**Root cause**: `verify_environment.py`, `generate_install_plan.py`, and `context_budget.py` were never invoked in this audit run. The tools themselves are correct — the gap is in process enforcement.

**Fix**: No tool logic changes. Add a step-completeness validator (see Domain 6) that scans `audit-output/` for all required artifacts and blocks the report phase if any are missing. This prevents silent omission of these steps in future runs.

### Domain 2: Tool Output Schema Compliance

**Root cause**: The `tool-summary.json` in the audit output uses a custom format (`scans_completed`/`results`/`high_priority_candidates`) rather than the schema-compliant format produced by `run_tools.sh` (`tools`/`raw_outputs`/`summary`). Similarly, `correlation.json` lacks the `match_level` field required by `public-vuln-correlation.schema.json`.

**Verification**: `run_tools.sh` (lines 62–79) already produces the correct `tool-summary.json` format. `correlate_public_vulns.py` (line 115) already includes `match_level` in each correlation entry.

**Fix**: No tool changes needed. Both tools produce correct output when used. The non-compliant files in this audit were hand-crafted, not tool-generated. Step-completeness validation (Domain 6) ensures tools run and produce standard output.

### Domain 3: Candidate State Machine Naming

**Root cause**: AI hypotheses use `A-HYP-*` IDs, but when promoted to candidates the state machine (SKILL.md:55–56) specifies the format should be `A-CAND-*`. The `make_ai_packets.py` tool uses the candidate's raw ID for output filenames without conversion.

**Fix**: `make_ai_packets.py` — before writing packet files (line 98), convert candidate IDs from `A-HYP-*` to `A-CAND-*`.

### Domain 4: Report Content Integrity

**Root cause (primary)**: `findings-index.json` uses a field schema that does not match `finding.schema.json`:

| Schema Required | Actual in findings-index.json |
|---|---|
| `status` | `validated_status` |
| `cvss: {vector, base_score, severity}` | Flat `cvss_v4_vector`, `cvss_v4_score`, `cvss_v4_severity` |
| `discovery_method: [{type, description}]` | String `"tool / ai / manual"` |
| `source_code_evidence`, `source_to_sink_path`, `root_cause`, `fix_recommendation`, `validation`, `poc_test_artifacts` | Missing entirely |

This mismatch causes three downstream tools to produce empty/incorrect output:

**Fixes** (3 tools, additive fallback logic):

1. **`generate_poc_testcase.py:296`** — Replace `f.get('status') != 'Validated'` with `(f.get('status') or f.get('validated_status')) != 'Validated'`

2. **`publish_bilingual_reports.py`** — Add `get_cvss_field(f, field)` helper that checks nested `cvss.{field}` first, then falls back to flat `cvss_v4_{field}`. Apply to all CVSS read sites in `write_finding()` and `write_internal_report()`.

3. **`generate_final_report.py`** — Replace all `f.get('status')` calls with `f.get('status') or f.get('validated_status')` in `build_executive_summary()`, `build_validated_table()`, and `gather_disclosure_stats()`.

### Domain 5: PoC Lifecycle

**Root cause**: `generate_poc_testcase.py` skips findings whose `status != 'Validated'`. Since `findings-index.json` uses `validated_status` instead of `status`, all findings are skipped. Additionally, PoC output is written to `machine/poc-tests/` instead of the workflow-specified `04-validation/poc-tests/`.

**Fixes**:
1. Status field fallback (covered in Domain 4)
2. `enforced_audit_driver.py:97` — Change PoC output path from `out / 'machine' / 'poc-tests'` to `out / '04-validation' / 'poc-tests'`

### Domain 6: Workflow Orchestration & Quality Gates

**Root cause**: No single gate validates that all required workflow artifacts exist and contain meaningful content. `validate_report_completeness.py` checks only surface-level conditions (heading presence, Markdown tables, disclosure summary existence) but not content depth (placeholder detection, required field presence in finding entries).

**Fixes**:

1. **New file: `tools/validate_step_completeness.py`** — Post-audit validation scanning `audit-output/` for 14 required artifacts:

   | Check | Path |
   |---|---|
   | Environment check | `00-environment/environment-check.json` |
   | Tool install plan | `00-environment/tool-install-plan.md` |
   | Context budget | `01-profile/context-budget.json` |
   | Tool summary | `02-tools/tool-summary.json` |
   | Tool raw outputs | `02-tools/raw/` (≥1 file) |
   | AI hypotheses | `03-candidates/ai-hypotheses.json` |
   | Candidate reviews | `03-candidates/reviews/` (≥1 file) |
   | Validations | `04-validation/` (≥1 VAL-* file) |
   | CVSS scores | `05-findings/CVSS-*.json` |
   | Machine report | `06-report/machine/report.json` |
   | zh-CN findings | `06-report/zh-CN/04-漏洞发现/` |
   | en-US findings | `06-report/en-US/04-findings/` |
   | CVE preparation | `07-disclosure/machine/cve-preparation.json` |
   | Findings index | `findings-index.json` |
   | Correlation | `correlation.json` |

   Output: `machine/step-completeness.json`

2. **`validate_report_completeness.py`** — Add 5 content-depth checks:

   - **Placeholder detection**: For each validated finding, check that `summary`, `root_cause`, `fix_recommendation` are not `—` or `?`
   - **Status field**: Accept both `status` and `validated_status`
   - **CVSS completeness**: Check nested `cvss.base_score` or flat `cvss_v4_score` is a number
   - **Source code evidence**: Require at least one entry with `file` and `start_line`
   - **Discovery method**: Require each entry to have non-empty `description`

3. **`enforced_audit_driver.py`** — Two changes:
   - Line 97: PoC output path `machine/poc-tests/` → `04-validation/poc-tests/`
   - Before final `return 0` (line 125): integrate `validate_step_completeness.py`

---

## 3. File Change Summary

| File | Operation | Lines Changed | Description |
|------|-----------|--------------|-------------|
| `tools/validate_report_completeness.py` | Modify | +~40 | Add 5 content-depth checks |
| `tools/generate_poc_testcase.py` | Modify | 1 | Status field fallback at line 296 |
| `tools/publish_bilingual_reports.py` | Modify | +~12 | Add `get_cvss_field()` helper + apply |
| `tools/generate_final_report.py` | Modify | +~6 | `status`/`validated_status` fallback at read sites |
| `tools/make_ai_packets.py` | Modify | +~5 | `A-HYP-*` → `A-CAND-*` rename before line 98 |
| `tools/enforced_audit_driver.py` | Modify | 2 | PoC path (line 97) + step completeness gate (line 123+) |
| **`tools/validate_step_completeness.py`** | **New** | ~80 | 14-item artifact presence validator |
| `workflows/06-validation.md` | Modify | 1 | Record PoC output path (`04-validation/poc-tests/`) |
| `workflows/03-tool-scan.md` | Modify | 1 | Reference standard `tool-summary.json` format |

Total: **8 files modified + 1 new file + 2 workflow doc updates**.
No new dependencies. No toolchain changes. No external integrations.

---

## 4. Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Fallback logic hides genuine schema violations | Low | `validate_report_completeness.py` enhanced checks catch both cases |
| Step-completeness gate too strict for partial audits | Low | Default to warning, not blocking; `--allow-partial` flag |
| `A-HYP-*` rename breaks review file references | Low | Only packet filenames change; IDs in JSON bodies remain untouched |
| CVSS field fallback returns wrong severity class | Low | Fallback maps explicitly: `cvss_v4_score` → `base_score`, `cvss_v4_severity` → `severity`, `cvss_v4_vector` → `vector` |

---

## 5. Success Criteria

After all fixes are applied and a re-audit of a known target is run:

1. `00-environment/environment-check.json` and `tool-install-plan.md` exist
2. `01-profile/context-budget.json` exists with valid `decision` field
3. `tool-summary.json` matches `tool-summary.schema.json`
4. `correlation.json` includes `match_level` on every entry
5. Candidate packet files use `A-CAND-*` format (not `A-HYP-*`)
6. Finding reports (`06-report/{en-US,zh-CN}/04-*/*.md`) contain real content, not `—` placeholders
7. `final-summary-report.md` shows correct validated finding count (>0)
8. `internal-security-report.md` shows correct CVSS scores and severities
9. PoC artifacts exist under `04-validation/poc-tests/` for each Validated finding
10. `validate_report_completeness.py` errors on empty reports and passes on complete ones
11. `validate_step_completeness.py` detects missing artifacts and passes when all present
