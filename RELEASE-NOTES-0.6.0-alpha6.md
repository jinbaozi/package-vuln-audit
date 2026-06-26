# Release Notes: 0.6.0-alpha6

## Focus

Installation and migration experience.

This release adds scripted installation and verification for Claude Code, Codex, and opencode adapters. It is intended to make the portable skill easier to copy into an audited repository, especially in intranet environments where package managers may be unavailable or undesirable.

## Added

- `install/install.sh`
  - Installs one or all platform adapters into a target repository.
  - Supports `copy` and `symlink` modes.
  - Supports `--force` overwrite behavior.
- `install/verify-install.sh`
  - Verifies expected platform files and core skill resources.
- `docs/runbooks/install-and-migration.md`
  - Documents all-adapter install, single-platform install, offline install, and safety notes.
- Scripted install sections in each adapter `INSTALL.md`.
- Install-script tests in `tests/test_install_scripts.py`.

## Changed

- README now identifies alpha6 as the current alpha and documents scripted install commands.
- `skill.json` version metadata updated to `0.6.0-alpha6`.
- Changelog updated with alpha6 notes.

## Verification

The release was validated with:

```bash
./run-tests.sh
```

The test suite validates schema files, candidate ranking, AI packet generation, report admission rules, toy C project E2E execution, Binutils helper scripts, JSON files, and install/verify scripts.
