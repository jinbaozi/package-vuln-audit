# Installation and Migration Runbook

This runbook explains how to install `package-vuln-audit-skill` into an audited repository for Claude Code, Codex, and opencode.

## Goals

- Keep the portable skill core platform-neutral.
- Install platform adapters without modifying source code under audit.
- Preserve parent-agent context hygiene by storing workflows, recipes, schemas, templates, and tools in a dedicated skill directory.
- Support copy mode for reproducible offline bundles and symlink mode for local development.

## Install all adapters into a repository

```bash
/path/to/package-vuln-audit-skill/install/install.sh \
  --target /path/to/repo \
  --platform all \
  --mode copy \
  --force
```

Verify:

```bash
/path/to/package-vuln-audit-skill/install/verify-install.sh \
  --target /path/to/repo \
  --platform all
```

## Claude Code only

```bash
install/install.sh --target /path/to/repo --platform claude-code --mode copy --force
install/verify-install.sh --target /path/to/repo --platform claude-code
```

Installed paths:

```text
/path/to/repo/.claude/skills/package-vuln-audit/
/path/to/repo/.claude/commands/
/path/to/repo/.claude/agents/
/path/to/repo/CLAUDE.md
/path/to/repo/AGENTS.md
```

## Codex only

```bash
install/install.sh --target /path/to/repo --platform codex --mode copy --force
install/verify-install.sh --target /path/to/repo --platform codex
```

Installed paths:

```text
/path/to/repo/.codex/skills/package-vuln-audit/
/path/to/repo/AGENTS.md
```

Codex environments without native subagents should use fresh task packets and fresh invocations for package profiling, tool execution, hypothesis hunting, validation, CVSS scoring, and reporting.

## opencode only

```bash
install/install.sh --target /path/to/repo --platform opencode --mode copy --force
install/verify-install.sh --target /path/to/repo --platform opencode
```

Installed paths:

```text
/path/to/repo/.opencode/opencode.json
/path/to/repo/.opencode/agents/
/path/to/repo/.opencode/commands/
/path/to/repo/.opencode/skills/package-vuln-audit/
/path/to/repo/AGENTS.md
```

opencode is the most direct mapping for primary-agent plus subagent orchestration.

## Offline install guidance

For a pure intranet environment:

1. Copy the release archive into the intranet.
2. Extract it under a controlled path, for example `/opt/package-vuln-audit-skill`.
3. Run install scripts in `--mode copy`; avoid symlinks if the package path may change.
4. Ensure required traditional tools are installed locally or accept graceful degradation in `run_tools.sh`.
5. Keep vulnerability databases, Semgrep rules, CodeQL packs, and OSV/Trivy/Grype databases locally mirrored if those tools are enabled.

## Safety notes

- The installer only copies or links skill/adaptation files; it does not run scanning tools against the target repository.
- Do not install with `--force` unless you accept overwriting existing AGENTS.md, CLAUDE.md, or agent command files.
- The skill requires validated evidence before PoC/testcase materials are emitted into a formal finding.
