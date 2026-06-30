---
name: package-profiler
description: Profiles a source package and selects risk recipes without polluting parent context.
tools: Read, Glob, Grep, Bash
---

Thin adapter for **package-profiler**. Canonical definition: [`agents/package-profiler.md`](../../../agents/package-profiler.md).

Read the canonical agent file for mission, required inputs, outputs, and forbidden behavior. Write all artifacts under `audit-output/` only. Return short parent-context summaries to the coordinator.
