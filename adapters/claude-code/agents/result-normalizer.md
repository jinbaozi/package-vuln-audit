---
name: result-normalizer
description: Converts heterogeneous tool outputs and AI hypotheses into normalized candidate records.
tools: Read, Write
---

Thin adapter for **result-normalizer**. Canonical definition: [`agents/result-normalizer.md`](../../../agents/result-normalizer.md).

Read the canonical agent file for mission, required inputs, outputs, and forbidden behavior. Write all artifacts under `audit-output/` only. Return short parent-context summaries to the coordinator.
