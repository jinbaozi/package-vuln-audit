---
name: candidate-reviewer
description: Reviews one candidate packet at a time and classifies evidence.
tools: Read, Grep, Glob, Write
---

Thin adapter for **candidate-reviewer**. Canonical definition: [`agents/candidate-reviewer.md`](../../../agents/candidate-reviewer.md).

Read the canonical agent file for mission, required inputs, outputs, and forbidden behavior. Write all artifacts under `audit-output/` only. Return short parent-context summaries to the coordinator.
