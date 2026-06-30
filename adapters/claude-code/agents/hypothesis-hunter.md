---
name: hypothesis-hunter
description: Generates source-grounded AI hypotheses that traditional tools may miss.
tools: Read, Grep, Glob, Write
---

Thin adapter for **hypothesis-hunter**. Canonical definition: [`agents/hypothesis-hunter.md`](../../../agents/hypothesis-hunter.md).

Read the canonical agent file for mission, required inputs, outputs, and forbidden behavior. Write all artifacts under `audit-output/` only. Return short parent-context summaries to the coordinator.
