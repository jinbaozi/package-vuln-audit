# Sandbox Netpolicy Runbook

PVAS applies network policy through `tools/pvas_netpolicy.py` for PVAS-managed containers.

## Default Policy

- PoC reproducers use `bridge-deny`.
- Offline/restricted tool runs use `bridge-deny`.
- Online-approved tools may use `bridge-allow` when the matrix row has `network_required: true` and the audit intake permits network access.

`allowed_cidrs` defaults to an empty list. Empty means loopback and established connections are allowed, then other outbound traffic is dropped by the PVAS chain.

## Cleanup

The enforced driver registers cleanup that calls:

```text
pvas_netpolicy.flush_all()
pvas_image.prompt_cleanup(audit_id, backend)
```

Manual cleanup can be run from Python when needed:

```bash
python3 - <<'PY'
import sys
sys.path.insert(0, "tools")
import pvas_netpolicy
pvas_netpolicy.flush_all()
PY
```

## Degraded Netpolicy

If iptables is unavailable or rejects a rule, `pvas_container.run()` degrades the container network to host mode for that execution and records:

```json
{
  "netpolicy_id": "degraded-no-netpolicy",
  "executed_via": "host-degraded-sandbox-disabled"
}
```

That is degraded evidence. Do not treat it as equivalent to a normal `bridge-deny` sandbox run in final validation claims.

## Troubleshooting

Check current PVAS chains:

```bash
iptables -S | grep '^-[AN] PV_'
```

If stale PVAS chains remain after an interrupted run, call `pvas_netpolicy.flush_all()` as shown above. The cleanup only targets chains with the PVAS `PV_` prefix and OUTPUT jumps to those chains.
