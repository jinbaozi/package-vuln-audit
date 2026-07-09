# PVAS Sandbox Netpolicy Templates

This directory contains iptables rule templates applied by
`tools/pvas_netpolicy.py` based on the `network_policy` field of each
`ContainerSpec`.

## Policies

| Policy | File | Effect | Default for |
|--------|------|--------|-------------|
| `bridge-deny` | `bridge-deny.rules` | Drop all outbound except established/related + DNS | complete audits, POC validation |
| `bridge-allow` | `bridge-allow.rules` | Allow all outbound (no enforcement) | ad-hoc tool scans needing network |
| `host` | (no template) | Use docker host network | driver orchestrator, dev iteration |

## Variables

The `<AUDIT_ID>` placeholder in each rule file is replaced at apply time
with the actual `pvas-audit-id` label value, allowing multiple audits to
run concurrently with independent netpolicy chains.

## Usage

These templates are loaded by `tools/pvas_netpolicy.py` which is called
from `pvas_container.run()` automatically when the spec's
`network_policy` is `bridge-deny` or `bridge-allow`.

## Limitations

- `host` network policy is enforced at the docker level (uses `--network host`)
  and bypasses iptables rules.
- These rules apply to the docker bridge network only. If the container
  is run with `--network=none` no traffic is possible at all.