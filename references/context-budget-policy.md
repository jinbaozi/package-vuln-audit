# Context Budget Policy

## Core model

Each Agent or Subagent invocation has an independent default context window of 200,000 tokens.
This is a per-invocation hard window, not a recommendation to fill the window.

The workflow does not share one 200K window. A multi-stage audit may consume more than 200K tokens across all invocations, but no single invocation may exceed its own budget.

## Default limits

| Setting | Default | Meaning |
|---|---:|---|
| `PVAS_AGENT_CONTEXT_BUDGET_TOKENS` | 200000 | hard per-agent context window |
| `PVAS_AGENT_INPUT_TARGET_TOKENS` | 140000 | preferred maximum input payload |
| `PVAS_AGENT_INPUT_WARNING_TOKENS` | 170000 | warning threshold |
| `PVAS_AGENT_HARD_INPUT_LIMIT_TOKENS` | 180000 | hard input payload limit before output reserve |
| `PVAS_AGENT_OUTPUT_RESERVE_TOKENS` | 20000 | reserved room for reasoning and output |
| `PVAS_PACKET_BUDGET_TOKENS` | 8000 | preferred maximum per candidate packet |
| `PVAS_PACKET_REVIEW_BATCH_TOKENS` | 160000 | preferred maximum candidate-review batch input |
| `PVAS_MAX_PACKET_COUNT_PER_REVIEW` | 20 | default candidate packets per review batch |

## Role-specific targets

| Agent role | Hard window | Target input | Notes |
|---|---:|---:|---|
| coordinator | 200000 | 30000-50000 | scheduling and decision only |
| package-profiler | 200000 | 60000-100000 | summaries, traversal manifest, build hints |
| tool-runner | 200000 | 20000-40000 | tool configuration; raw logs remain on disk |
| result-normalizer | 200000 | 80000-120000 | structured tool output summaries |
| hypothesis-hunter | 200000 | 100000-140000 | recipes, module summaries, limited slices |
| candidate-reviewer | 200000 | 120000-160000 | batches of candidate packets |
| validator | 200000 | 80000-120000 | likely candidates and validation summaries |
| cvss-scorer | 200000 | 30000-60000 | validated evidence and scoring rationale |
| report-writer | 200000 | 80000-120000 | validated findings, not raw logs |
| disclosure-coordinator | 200000 | 50000-90000 | validated private/public disclosure material |

## Artifact class policy

Coordinator and report-oriented agents must not ingest raw repositories or raw logs.
They consume summaries and indexes. Tool and validation agents may create raw artifacts, but they should return structured summaries.

Forbidden for coordinator by default:

- full repository source dumps
- `all-files.txt` full content
- raw Semgrep / CodeQL / Cppcheck logs
- full fuzz logs
- full build logs
- all candidate packets at once

## Candidate batching

If aggregate candidate packet tokens exceed 200K, do not fail the workflow. Split into independent candidate-reviewer invocations:

```text
Batch 1: up to 160K input
Batch 2: up to 160K input
Batch 3: up to 160K input
```

Only batch summaries return to the coordinator. Rejected details do not re-enter the active context.

## Codex adapter rule

When the target platform does not provide native subagents, simulate them with fresh invocations:

1. input = task packet + selected artifacts only;
2. output = result packet + written artifacts;
3. do not concatenate prior subtask transcripts into the next subtask;
4. coordinator reads only result packets.
