#!/usr/bin/env python3
"""Post-build image verification for PVAS sandbox runtime.

Reads deps.json#verify_commands list and runs each command inside the
sandbox via pvas_container. All checks must PASS before audit can proceed.

For each check, expect_match is the substring expected in output. Per-check
mem_limit_mb is honored (some tools need >512 MB).

Usage:
    python3 audit-image-verify.py [--image TAG] [--manifest PATH]

Exit code 0 if all checks pass, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

TOOLS = pathlib.Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))

import pvas_container  # noqa: E402

SKILL_ROOT = pathlib.Path(__file__).resolve().parents[2]


def make_spec(image: str, command: list, env: dict, mem_mb: int, audit_id: str, name: str):
    return pvas_container.ContainerSpec(
        image=image,
        command=command,
        mounts=[],
        network_policy="host",
        timeout_seconds=120,
        user="root",
        read_only_rootfs=False,
        mem_limit_mb=mem_mb,
        env=env,
        labels={
            "pvas-audit-id": audit_id,
            "pvas-purpose": "verify",
            "pvas-tool": name,
        },
        cap_drop=["ALL"],
        cap_add=["DAC_OVERRIDE", "CHOWN", "FOWNER", "SETUID", "SETGID"],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(SKILL_ROOT / "sandbox" / "manifest" / "deps.json"))
    parser.add_argument("--image", default=None, help="Override image tag")
    parser.add_argument("--audit-id", default="pvas-image-verify")
    args = parser.parse_args()

    manifest = json.loads(pathlib.Path(args.manifest).read_text())
    image = args.image or manifest["image"]
    env = manifest.get("env", {})
    verify = manifest.get("verify_commands", [])

    print(f"[verify] image={image}")
    print(f"[verify] {len(verify)} checks to run")
    print()

    pass_count = fail_count = 0
    for check in verify:
        name = check["name"]
        cmd = check["cmd"]
        expect = check.get("expect_match", "")
        mem_mb = int(check.get("mem_limit_mb", 512))

        spec = make_spec(image, ["/bin/sh", "-c", cmd], env, mem_mb, args.audit_id, name)
        result = pvas_container.run(spec)
        combined = (result.stdout or "") + (result.stderr or "")
        ok = result.exit_code == 0 and expect in combined
        if ok:
            print(f"[PASS] {name}")
            pass_count += 1
        else:
            print(f"[FAIL] {name} exit={result.exit_code}")
            print(f"       expected: {expect!r}")
            print(f"       output: {combined[:300]!r}")
            fail_count += 1

    print()
    print(f"[verify] pass={pass_count} fail={fail_count} total={len(verify)}")
    if fail_count > 0:
        print("[verify] FAILED — image is not ready for audit run")
        return 1
    print("[verify] all checks passed — image is ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())