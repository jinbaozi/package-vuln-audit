# 06 Validation

## Purpose

Validate Likely candidates using safe local tests, sanitizer output, fuzz reproducer, static refutation, or regression tests.

## Inputs

- Likely candidate review
- validation plan
- build permissions

## Subagent role

`validator`

## Allowed tools

- approved bash commands
- read/write audit-output/04-validation/
- no source writes except optional patch suggestions

## Outputs

- audit-output/04-validation/VAL-*.json
- audit-output/04-validation/poc-tests/FINDING-*/
- audit-output/04-validation/poc-tests/FINDING-*/poc-run-result.json
- audit-output/04-validation/manual-review/MANUAL-*/manual-validation-plan.md
- audit-output/04-validation/manual-review/MANUAL-*/manual-validation-plan.json

## Failure behavior

If validation cannot be performed, mark Needs Manual Review with missing prerequisites.

无法稳定自动复现的问题不得进入 `Validated`；应输出为 `Needs Manual Review`，并生成中文优先的人工验证计划和测试方法。

## Post-validation steps

After validation passes (status becomes Validated) or Needs Manual Review, generate multi-language PoC artifacts:

1. Run `tools/generate_poc_testcase.py --findings <finding-index.json> --generate-from-finding --languages <lang1,lang2,...> --profile <package-profile.json>` to create multi-language reproducer scripts. Default languages: Python, C, C++, Java, Go (auto-selected based on project profile).
   - **Validated findings**: At least one language variant must execute successfully (`poc-run-result.json` status = `passed`).
   - **Needs Manual Review findings**: PoC is generated as `draft`/`unverified`. At least one local draft variant must execute successfully (`poc-run-result.json` status = `passed`). This passed execution is a reproducible observation signal only; it does not change the finding status.
2. Validate PoC artifacts: `tools/validate_poc_artifacts.py --poc-root audit-output/04-validation/poc-tests`
3. Each PoC manifest must include `discovery_method_ref` referencing the finding's discovery_method entries.
4. Each language variant directory must include `input-description.md` with SHA256 and purpose fields.
5. The main `reproduce.sh` tries all language variants and reports aggregate results.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.

## 多语言输出要求

每个步骤完成后，必须生成 `machine/`、`zh-CN/`、`en-US/` 三份阶段性结论：
- `machine/`：JSON 格式的结构化步骤输出摘要
- `zh-CN/`：中文自然语言步骤结论
- `en-US/`：英文自然语言步骤结论
