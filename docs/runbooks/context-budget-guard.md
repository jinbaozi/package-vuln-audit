# Context Budget Guard v2.1 Runbook

## Purpose

Prevent source traversal and traditional-tool output from flooding AI contexts while preserving full-repository coverage for non-AI tools.

## Model

- Every Agent/Subagent invocation has an independent 200K hard context window.
- 200K is not a target payload size.
- Recommended input target is 140K; warning threshold is 170K; hard input limit is 180K.
- Aggregate run tokens are cost telemetry, not a shared context limit.

## Required artifacts

- `audit-output/01-profile/traversal-manifest.json`
- `audit-output/01-profile/context-budget.json`
- `audit-output/03-candidates/packets/packet-index.json`

## Coordinator rule

The coordinator reads summaries and indexes only. It must not read raw repositories, raw tool logs, raw fuzz logs, full build logs, or all candidate packets at once.

## Candidate review batching

If candidate packets exceed one review window, split them into independent candidate-reviewer invocations. Merge only batch summaries.
