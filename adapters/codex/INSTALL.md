# Codex Adapter Installation

Codex reads repository instructions from `AGENTS.md` and can use Agent Skills packaged as folders containing `SKILL.md`, resources, and optional scripts.

## Project-scoped install

From the audited repository root:

```bash
cp -a /path/to/package-vuln-audit-skill/adapters/codex/AGENTS.md ./AGENTS.md
mkdir -p .codex/skills/package-vuln-audit
cp -a /path/to/package-vuln-audit-skill/SKILL.md \
      /path/to/package-vuln-audit-skill/AGENTS.md \
      /path/to/package-vuln-audit-skill/README.md \
      /path/to/package-vuln-audit-skill/workflows \
      /path/to/package-vuln-audit-skill/recipes \
      /path/to/package-vuln-audit-skill/agents \
      /path/to/package-vuln-audit-skill/tools \
      /path/to/package-vuln-audit-skill/schemas \
      /path/to/package-vuln-audit-skill/templates \
      /path/to/package-vuln-audit-skill/references \
      .codex/skills/package-vuln-audit/
cp -a /path/to/package-vuln-audit-skill/adapters/codex/skills/package-vuln-audit/* .codex/skills/package-vuln-audit/
```

If your Codex environment uses a different skills directory, copy the `skills/package-vuln-audit/` folder there.

## Subagent fallback

When native subagents are unavailable, emulate subagent delegation with:

1. A fresh task packet from `schemas/`.
2. A fresh Codex invocation for that packet.
3. A schema-conformant artifact under `audit-output/`.
4. A short artifact summary for the parent agent.

Do not carry raw tool logs into follow-up Codex turns.

## Scripted install

From the skill package root:

```bash
install/install.sh --target /path/to/repo --platform codex --mode copy --force
install/verify-install.sh --target /path/to/repo --platform codex
```

## Context Budget Guard v2.1

Each Agent/Subagent task should be treated as an independent invocation with a default 200K hard context window. Do not concatenate raw transcripts or raw logs across tasks. When native subagents are unavailable, use fresh task packets and consume only result packets.
