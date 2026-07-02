# 04 AI Hypothesis

## Purpose

Generate source-grounded, multidimensional hypotheses for issues traditional tools may miss.
This stage does not declare vulnerabilities.

## Inputs

- package-profile.json
- selected recipes
- limited code slices
- tool-summary.json

## Subagent role

`hypothesis-hunter`

## Allowed tools

- read selected slices
- write audit-output/03-candidates/AI-HYP-*.json
- no broad repository reads

## Outputs

- audit-output/03-candidates/ai-hypotheses.json

Each hypothesis must include:

- `dimension`: one of `dataflow`, `semantic-invariant`, or `attack-surface`
- source-grounded assumption, attacker-controlled input, possible gap, and possible sink
- non-empty `evidence_refs`
- a concrete `failure_scenario`
- non-empty `review_questions`
- confidence (`low`, `medium`, or `high`)

## Generation model

For each Top-N candidate packet, `hypothesis-hunter` reviews three fixed dimensions:

- `dataflow`: attacker-controlled input reaching memory, parser, type, or resource sinks.
- `semantic-invariant`: length, offset, arithmetic, state, ownership, or lifecycle assumptions.
- `attack-surface`: command, path, resource, concurrency, process, or object-lifecycle exposure.

The generator then synthesizes the strongest source-reviewable hypotheses and deduplicates by `(candidate_id, dimension, possible_gap, possible_sink)`, keeping the higher-confidence or better-evidenced hypothesis. There is no minimum hypothesis count per dimension; zero strong hypotheses for a dimension is acceptable.

## Schema gate

`tools/validate_hypotheses.py` must reject empty artifacts, duplicate hypothesis IDs, invalid dimensions, invalid confidence values, empty evidence references, empty failure scenarios, and empty review questions.

## Failure behavior

Hypotheses that cannot identify input, assumption, possible gap, evidence references, failure scenario, review questions, and validation method are discarded. Fallback hypotheses must still carry weak but explicit evidence references such as `selected-scope.json`.

## Candidate review handoff

`ai-hypotheses.json` is passed to candidate review as context only. Candidate reviewers must use actual source packets and code evidence for state transitions; an AI hypothesis alone must never promote an item to `Candidate`, `Likely`, `Validated`, or `Needs Manual Review`.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.

## Context Budget Guard

Use `context-budget.json` before loading artifacts into an agent context. The budget model is per-agent independent context: each subagent invocation has its own 200K hard window. Do not treat 200K as a workflow-wide shared limit, and do not treat it as permission to load raw repositories or raw logs.

## 多语言输出要求

每个步骤完成后，必须生成 `machine/`、`zh-CN/`、`en-US/` 三份阶段性结论：
- `machine/`：JSON 格式的结构化步骤输出摘要
- `zh-CN/`：中文自然语言步骤结论
- `en-US/`：英文自然语言步骤结论
