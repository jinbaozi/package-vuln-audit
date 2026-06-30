# 08 Report

## Purpose

Create bilingual Markdown and JSON reports with finding index, validation evidence, tool evidence index, public vulnerability correlation, and discovery method documentation.

## Inputs

- validated findings (with discovery_method and disclosure_status populated)
- CVSS artifacts
- tool summaries
- validation summaries
- public vulnerability correlation (if available)
- PoC test artifacts (from validation phase)

## Subagent role

`report-writer`

## Allowed tools

- read final artifacts
- write audit-output/06-report/

## Required steps (in order)

1. **Generate PoC artifacts** for each Validated and Needs Manual Review finding (if not already done in 06-validation):
   `tools/generate_poc_testcase.py --findings <finding-index.json> --generate-from-finding --languages <lang1,lang2,...> --profile <package-profile.json>`

2. **Publish bilingual reports** (machine/zh-CN/en-US):
   `tools/publish_bilingual_reports.py --findings <finding-index.json> --correlation <correlation.json> --out audit-output/06-report`
   - This generates `machine/report.json`, `zh-CN/04-findings/*.md`, `zh-CN/05-内部安全报告/internal-security-report.md`, `en-US/04-findings/*.md`, `en-US/05-internal-security-report/internal-security-report.md`

3. **Validate language output and report completeness** (CJK isolation + disclosure gates):
   `tools/validate_report_completeness.py --findings <finding-index.json> --correlation <correlation.json> --report-root audit-output --check-language-isolation`
   - Standalone workflow runs may use `--report-root audit-output/06-report` when reports live under that directory.
   - The enforced driver writes bilingual output to the audit-output root; use `--report-root audit-output` on that path.

4. **Validate report completeness** (checks discovery_method, poc_test_artifacts, disclosure_status):
   `tools/validate_report_completeness.py --findings <finding-index.json> --correlation <correlation.json> --report-root audit-output/06-report --poc-root audit-output/machine/poc-tests`

5. **Validate PoC artifacts**:
   `tools/validate_poc_artifacts.py --poc-root audit-output/machine/poc-tests`

6. **Generate final summary report** (aggregates all 10 workflow steps into a single bilingual summary):
   `tools/generate_final_report.py --audit-root audit-output --findings <finding-index.json> --correlation <correlation.json> --out audit-output/06-report`

## Outputs

- audit-output/06-report/machine/report.json (canonical machine artifact)
- audit-output/06-report/machine/bilingual-map.json
- audit-output/06-report/zh-CN/04-findings/*.md (Chinese finding reports)
- audit-output/06-report/zh-CN/05-内部安全报告/internal-security-report.md (Chinese internal report)
- audit-output/06-report/en-US/04-findings/*.md (English finding reports)
- audit-output/06-report/en-US/05-internal-security-report/internal-security-report.md (English internal report)
- audit-output/06-report/machine/report-completeness.json (validation result)
- audit-output/machine/poc-tests/*/ (PoC artifact directories)

## Failure behavior

- Do not include Candidate issues as confirmed vulnerabilities.
- If `validate_report_completeness.py` reports errors, fix the missing fields before proceeding.
- If `validate_poc_artifacts.py` reports errors, regenerate or fix the PoC artifacts.

## Report content requirements

最终汇总报告默认简体中文，必须分别展示 `Validated Findings` 和 `Needs Manual Review`。`Validated` 必须引用已通过执行校验的 PoC 包；`Needs Manual Review` 必须引用人工验证计划。报告不得把人工复核项描述为已验证漏洞。

Every report must include for each Validated finding:
1. **Disclosure status** (publicly_disclosed / not_found_in_configured_sources / possibly_public / unknown)
2. **Public vulnerability references** (source, id, url, match_level)
3. **Discovery method** (tool name / AI hypothesis ref / manual review with description)
4. **PoC artifact index** (generated-script / manifest / testcase-file / readme with paths)
5. **CVSS** (v3.1 vector, score, severity; calculator-validated)
6. **Source code evidence** (file, function, line range)
7. **Source-to-sink path**
8. **Fix recommendation**

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.
