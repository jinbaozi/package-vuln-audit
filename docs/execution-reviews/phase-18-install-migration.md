# Phase 18 Review: Installation and Migration Scripts

## Implementation summary

Implemented scripted adapter installation and verification:

- `install/install.sh`
- `install/verify-install.sh`
- `docs/runbooks/install-and-migration.md`
- Adapter install documentation updates
- Alpha6 release notes and metadata updates

## Spec compliance review

- Supports Claude Code, Codex, and opencode adapters.
- Keeps core skill package platform-neutral.
- Installs complete core resources under platform-specific skill directories.
- Supports copy mode for offline/intranet use and symlink mode for development.
- Verifies required files after install.
- Does not run scanning tools during installation.

## Quality review

- Scripts use `set -euo pipefail`.
- Shell syntax is checked by the test suite.
- Scripts fail closed on unknown platforms, modes, and unexpected overwrite unless `--force` is supplied.
- Installation behavior is deterministic and repository-scoped.

## Limitations

- Does not detect platform-specific global skill directories automatically.
- Does not merge with existing AGENTS.md or CLAUDE.md; it overwrites only when `--force` is used.
- Does not install traditional tools or vulnerability databases.
