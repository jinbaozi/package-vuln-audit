# package-vuln-audit-skill 0.8.0-alpha8

This release adds Tool Availability Advisor support.

## Highlights

- Explicit `[PVAS-TOOL-MISSING]` warnings when attempted traditional tools are missing.
- `tools/verify_environment.py` for preflight environment checks.
- `tools/generate_install_plan.py` for user-local installation guidance.
- New schemas for `environment-check.json` and `tool-install-plan.json`.
- Install guidance prioritizes Python/pipx/uv, npm/npx, user-local binaries, and offline bundles.
- Default behavior remains advisory only: no automatic installation, no sudo, no system package manager changes.

## Safety

Automatic installation is not performed by default. Future installer automation must require explicit opt-in and install only under a user-controlled prefix such as `.pvas/tools`.
