# Claude Code Adapter Installation

This adapter maps the portable `package-vuln-audit-skill` into Claude Code project files.

## Project-scoped install

From the root of the repository you want to audit:

```bash
mkdir -p .claude/commands .claude/agents .claude/skills/package-vuln-audit
cp -a /path/to/package-vuln-audit-skill/SKILL.md .claude/skills/package-vuln-audit/SKILL.md
cp -a /path/to/package-vuln-audit-skill/AGENTS.md ./AGENTS.md
cp -a /path/to/package-vuln-audit-skill/adapters/claude-code/CLAUDE.md ./CLAUDE.md
cp -a /path/to/package-vuln-audit-skill/adapters/claude-code/commands/*.md .claude/commands/
cp -a /path/to/package-vuln-audit-skill/adapters/claude-code/agents/*.md .claude/agents/
```

## Usage

Use slash commands from Claude Code:

```text
/package-vuln-audit source_path=. output_dir=audit-output
/package-profile source_path=. output_dir=audit-output
/hypothesis-hunt profile=audit-output/01-profile/package-profile.json
/candidate-review candidate=audit-output/03-candidates/CAND-001.md
/validate-finding candidate=audit-output/03-candidates/CAND-001.md
```

## Safety

Do not grant broad write access to source directories. Subagents should write only to `audit-output/`. Full tool logs, SARIF, sanitizer logs, and fuzz noise must stay out of the parent agent context.

## Scripted install

From the skill package root:

```bash
install/install.sh --target /path/to/repo --platform claude-code --mode copy --force
install/verify-install.sh --target /path/to/repo --platform claude-code
```

## Context Budget Guard v2.1

Each Agent/Subagent task should be treated as an independent invocation with a default 200K hard context window. Do not concatenate raw transcripts or raw logs across tasks. When native subagents are unavailable, use fresh task packets and consume only result packets.
