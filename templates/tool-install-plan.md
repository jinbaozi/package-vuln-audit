# Tool Installation Plan

## Policy

- Default: do not auto-install tools.
- Preferred: Python/pipx/uv, npm/npx, user-local binaries, offline bundles.
- Avoid by default: sudo, system package managers, `/usr/local/bin`, and `curl | sh`.

## Missing Tools

{{missing_tools}}

## Recommended Installation Commands

{{install_commands}}

## Offline Bundle

Use an offline bundle when the target environment cannot reach public registries:

```text
offline-bundle/
├── wheels/
├── npm-cache/
├── binaries/
├── codeql/
├── checksums/SHA256SUMS
└── install-manifest.json
```
