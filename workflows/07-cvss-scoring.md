# 07 CVSS Scoring

## Purpose

Assign CVSS v3.1 scores only to Likely or Validated issues, and mark provisional scores clearly. See `references/cvss31-scoring-guide.md`.

## Inputs

- validation result
- finding draft
- deployment assumptions

## Subagent role

`cvss-scorer`

## Allowed tools

- read finding/validation evidence
- write cvss artifact
- `tools/cvss31_calculator.py` (compute and `--validate`)

## Required steps

1. Produce CVSS vector and per-metric rationale (Likely → provisional; Validated → final).
2. Run `python3 tools/cvss31_calculator.py --vector '<vector>'` to obtain base_score and severity; do not hand-compute.
3. Write artifact under `audit-output/05-findings/CVSS-*.json`.
4. Run `python3 tools/cvss31_calculator.py --validate --in <artifact>`; fix mismatches before proceeding.

## Outputs

- audit-output/05-findings/CVSS-*.json

## Failure behavior

If evidence is incomplete, output provisional severity only.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.

## 多语言输出要求

每个步骤完成后，必须生成 `machine/`、`zh-CN/`、`en-US/` 三份阶段性结论：
- `machine/`：JSON 格式的结构化步骤输出摘要
- `zh-CN/`：中文自然语言步骤结论
- `en-US/`：英文自然语言步骤结论
