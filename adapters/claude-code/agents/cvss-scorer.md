---
name: cvss-scorer
description: Scores Likely/Validated candidates using CVSS v3.1; must run cvss31_calculator --validate.
tools: Read, Write
---

Thin adapter for **cvss-scorer**. Canonical definition: [`agents/cvss-scorer.md`](../../../agents/cvss-scorer.md).

Read the canonical agent file for mission, required inputs, outputs, and forbidden behavior. Write all artifacts under `audit-output/` only. Return short parent-context summaries to the coordinator.
