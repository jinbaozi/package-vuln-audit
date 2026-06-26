# Tool Availability Advisor Runbook

This runbook explains how `package-vuln-audit-skill` handles missing traditional analysis tools.

## Check environment

```bash
tools/verify_environment.py --profile standard --out audit-output/00-environment
```

Supported profiles:

- `minimal`
- `standard`
- `full`
- `binutils`

## Generate install plan

```bash
tools/generate_install_plan.py \
  --environment-check audit-output/00-environment/environment-check.json \
  --out audit-output/00-environment
```

The plan is advisory by default. It prioritizes Python/pipx/uv, npm/npx, user-local binaries, and offline bundles over system package managers.

## Missing tool behavior during scan

`tools/run_tools.sh` does not fail when an optional scanner is missing. It records `not-installed` in `tool-summary.json`, prints `[PVAS-TOOL-MISSING]`, and writes an install plan to `audit-output/00-environment/tool-install-plan.md`.

## Strict mode recommendation

For controlled CI or formal audit baselines, run an environment check first and fail the pipeline if a required profile is degraded.
