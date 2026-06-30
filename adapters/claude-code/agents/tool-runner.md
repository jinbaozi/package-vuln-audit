---
name: tool-runner
description: Runs approved traditional security tools and summarizes results.
tools: Read, Bash, Write
---

Thin adapter for **tool-runner**. Canonical definition: [`agents/tool-runner.md`](../../../agents/tool-runner.md).

Read the canonical agent file for mission, required inputs, outputs, and forbidden behavior. Write all artifacts under `audit-output/` only. Return short parent-context summaries to the coordinator.
