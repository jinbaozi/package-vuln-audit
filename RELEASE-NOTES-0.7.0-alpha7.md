# Release Notes: 0.7.0-alpha7

This release implements Context Budget Guard v2.1.

Key changes:

- Each Agent/Subagent invocation has an independent 200K hard context window.
- 200K is not a target payload size; default target input is 140K and warning threshold is 170K.
- Coordinator remains summary-only and is forbidden from ingesting raw repositories, raw tool logs, raw fuzz logs, and full build logs.
- Candidate packets are token-estimated and split into independent candidate-review batches.
- Aggregate token usage is reported as cost telemetry, not as a shared context-window limit.
- Codex adapter guidance supports fresh-invocation subagent emulation.
