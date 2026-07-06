# Sandbox Debugging Runbook

PVAS runs generated PoC reproducers and generated tool-matrix rows through the stdlib-only `pvas_container` wrapper when `PVAS_SANDBOX` is enabled.

`pvas_container.wrap_command()` exists only as a compatibility API for callers
that need an argv suitable for `subprocess.run()`. It returns a local Python
runner command that decodes a `ContainerSpec` and calls `pvas_container.run()`;
it does not expose raw `docker run` arguments. New code should prefer building
`ContainerSpec` directly and calling `pvas_container.run()` or `run_parallel()`.

## Runtime State

Complete audits write:

- `audit-output/machine/sandbox-runtime.json` — audit id, sandbox mode, backend, imported image, runtime image, and any initialization error.
- `audit-output/machine/sandbox-cleanup.jsonl` — cleanup actions when containers or images are removed.
- `audit-output/02-tools/tool-summary.json` — per-tool `container` metadata for sandboxed tool runs.
- `audit-output/04-validation/poc-tests/<finding>/poc-run-result.json` — PoC `executed_via` and `container` metadata.

## Common Checks

1. Confirm Docker or Podman is available:

   ```bash
   sandbox/scripts/pvas-check-backend.sh
   ```

2. Confirm environment gate output:

   ```bash
   python3 tools/verify_environment.py --profile standard --mode strict --out audit-output/00-environment
   ```

3. Inspect sandbox runtime state:

   ```bash
   python3 -m json.tool audit-output/machine/sandbox-runtime.json
   ```

## Compatibility Switches

- `PVAS_SANDBOX=enabled` is the default.
- `PVAS_SANDBOX=disabled` uses the host compatibility path and writes `executed_via: host-degraded-sandbox-disabled` for PoC runs.
- `PVAS_SANDBOX=warn-only` keeps container execution but records `container-warn-only` in PoC run results.

Use `PVAS_SANDBOX=disabled` only for local debugging or temporary Phase 0/1 compatibility. Strict complete audits should treat a missing backend as a blocking environment issue unless degraded execution is explicitly approved.

## Image Issues

The runtime image tags are fixed:

- `pvas-sandbox:v11-2503-imported`
- `pvas-sandbox:v11-2503-runtime`

If `sandbox-runtime.json` says `image-unavailable`, check:

- `sandbox/rootfs/v11-2503-rootfs.tar` exists.
- `sandbox/rootfs/SHA256SUMS` matches the tarball, unless the all-zero placeholder is intentionally used.
- `sandbox/images/Dockerfile.runtime` exists.

No Python Docker SDK is used; all execution goes through Docker/Podman CLI commands.
