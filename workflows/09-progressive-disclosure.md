# 09 Progressive Disclosure

## Purpose

Generate internal, maintainer-private, and public-after-fix material according to disclosure level.

## Inputs

- validated findings
- disclosure policy
- fix status

## Subagent role

`disclosure-coordinator`

## Allowed tools

- read final findings
- write audit-output/07-disclosure/

## Outputs

- audit-output/07-disclosure/zh-CN/maintainer-private-report.md
- audit-output/07-disclosure/en-US/maintainer-private-report.md
- audit-output/07-disclosure/machine/cve-preparation.json
- audit-output/07-disclosure/machine/public-advisory-draft.md

## Output directory alignment

All disclosure outputs follow the same `machine/zh-CN/en-US` structure established by 08-report:
- `machine/` — canonical JSON artifacts (CVE prep, vulnerability record)
- `zh-CN/` — Chinese-language disclosure reports
- `en-US/` — English-language disclosure reports

## Failure behavior

Public advisory drafts must omit sensitive reproduction details (PoC scripts, testcase bytes, exploit logic) unless fix/public authorization is confirmed.

## Disclosure level mapping

| Finding disclosure_level | Action |
|--------------------------|--------|
| D2-internal-validated | Internal report only |
| D3-maintainer-private | Generate maintainer-private report |
| D4-public-after-fix | Generate maintainer report + public advisory draft (fix pending) |

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.

## 多语言输出要求

每个步骤完成后，必须生成 `machine/`、`zh-CN/`、`en-US/` 三份阶段性结论：
- `machine/`：JSON 格式的结构化步骤输出摘要
- `zh-CN/`：中文自然语言步骤结论
- `en-US/`：英文自然语言步骤结论
