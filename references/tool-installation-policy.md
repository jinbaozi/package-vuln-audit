# Tool Installation Policy

Traditional tools are capability enhancers. Missing tools must be visible to the user, but should not silently break the workflow or trigger uncontrolled system changes.

## Rules

1. Missing required or recommended tools must be reported explicitly.
2. The report must explain which capability is degraded.
3. The Skill must generate `environment-check.json` and `tool-install-plan.md` when missing tools are detected.
4. Default behavior is advisory only; do not auto-install tools.
5. Preferred methods are Python/pipx/uv, npm/npx, user-local binaries, and offline bundles.
6. Avoid `sudo`, system package managers, `/usr/local/bin`, and `curl | sh` by default.
7. Automatic installation requires explicit opt-in such as `PVAS_ALLOW_INSTALL=1` and must install into a user-controlled prefix such as `~/.pvas`.
8. Offline environments should use `offline-bundle/` with wheels, npm cache, binaries, checksums, and an install manifest.

## Installation Priority

1. Python/pipx/uv for Python CLI tools.
2. npm/npx or built-in npm commands for Node.js workflows.
3. Official user-local binary or bundle for Go/native tools.
4. Containerized or approved build environment for heavy fuzzing/toolchain workflows.
5. System package manager only as a documented fallback.
6. Source compilation only when necessary.
