# 05 Candidate Review

## Purpose

Review one candidate packet at a time and decide Reject, Candidate, or Likely.

## Inputs

- CAND-*.md
- limited source slices
- relevant tool/hypothesis evidence

## Subagent role

`candidate-reviewer`

## Allowed tools

- read candidate packet
- write review result
- no full repository reads

## Outputs

- audit-output/03-candidates/reviews/CAND-*.json

## Failure behavior

If source evidence is insufficient, keep the issue as Candidate or Needs Manual Review; do not validate it.

## Parent context rule

The parent agent should read only the declared output summary files from this workflow. Raw logs, full source scans, and large intermediate artifacts must stay in workflow-specific `audit-output/` subdirectories.

## Context Budget Guard

Use `context-budget.json` before loading artifacts into an agent context. The budget model is per-agent independent context: each subagent invocation has its own 200K hard window. Do not treat 200K as a workflow-wide shared limit, and do not treat it as permission to load raw repositories or raw logs.
