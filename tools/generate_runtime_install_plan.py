#!/usr/bin/env python3
"""Generate the container runtime tool installation plan."""
from __future__ import annotations

import argparse
import pathlib
import sys
from typing import Any

from pvas_io import write_json
from tool_catalog import CATALOG, PROFILE_TOOLS, STRICT_REQUIRED_TOOLS


HOST_BOOTSTRAP = ["python3", "docker|podman"]


def _tool_names(profile: str, profile_tools: dict[str, list[str]]) -> list[str]:
    return list(profile_tools.get(profile) or profile_tools.get("standard") or [])


def build_runtime_install_plan(
    *,
    profile: str,
    network_mode: str,
    target_runtime: str,
    catalog: dict[str, dict[str, Any]] | None = None,
    profile_tools: dict[str, list[str]] | None = None,
    strict_required: dict[str, list[str]] | None = None,
) -> dict:
    catalog = catalog or CATALOG
    profile_tools = profile_tools or PROFILE_TOOLS
    strict_required = strict_required or STRICT_REQUIRED_TOOLS
    strict = set(strict_required.get(profile) or strict_required.get("standard") or [])
    dnf_install: list[dict] = []
    offline_bundle: list[dict] = []
    blocking_items: list[dict] = []

    for name in _tool_names(profile, profile_tools):
        meta = catalog.get(name, {})
        binary = str(meta.get("binary") or name)
        methods = list(meta.get("install_methods") or [])
        dnf_package = meta.get("dnf_package")
        item = {
            "tool": name,
            "binary": binary,
            "dnf_package": dnf_package or "",
            "runtime_scope": meta.get("runtime_scope", "container-required"),
            "strict_required": name in strict,
            "version_command": [binary, *list(meta.get("version_args") or ["--version"])],
        }
        if dnf_package:
            dnf_install.append(item)
        elif "offline-bundle" in methods or meta.get("install_hint_id"):
            offline_bundle.append(item)
        elif name in strict:
            blocking_items.append({
                "tool": name,
                "binary": binary,
                "reason": "no dnf_package or offline install hint",
            })

    status = "blocked-install-source-missing" if blocking_items else "planned"
    return {
        "schema_version": "1.0",
        "status": status,
        "profile": profile,
        "network_mode": network_mode,
        "target_runtime": target_runtime,
        "host_bootstrap": {
            "required_binaries": HOST_BOOTSTRAP,
            "optional_binaries": ["dnf"],
            "notes": "Host tools bootstrap container image creation only; audit tools are verified in the runtime container.",
        },
        "container": {
            "dnf_install": dnf_install,
            "offline_bundle": offline_bundle,
            "verify_command": [
                "python3",
                "tools/verify_runtime_tools.py",
                "--profile",
                profile,
                "--target-runtime",
                target_runtime,
            ],
        },
        "blocking_items": blocking_items,
        "recovery_action": "rebuild-runtime-image" if not blocking_items else "provide-offline-bundle-or-approved-repo",
    }


def render_markdown(plan: dict) -> str:
    dnf_packages = [item["dnf_package"] for item in plan["container"]["dnf_install"] if item.get("dnf_package")]
    offline_tools = [item["tool"] for item in plan["container"]["offline_bundle"]]
    blockers = [item["tool"] for item in plan.get("blocking_items") or []]
    lines = [
        "# Runtime Install Plan",
        "",
        f"- Status: {plan['status']}",
        f"- Profile: {plan['profile']}",
        f"- Target runtime: {plan['target_runtime']}",
        f"- Host bootstrap: {', '.join(plan['host_bootstrap']['required_binaries'])}",
        "",
        "## Container dnf packages",
        "",
        "`dnf install -y " + " ".join(dnf_packages) + "`" if dnf_packages else "No dnf packages planned.",
        "",
        "## Offline bundle tools",
        "",
        ", ".join(offline_tools) if offline_tools else "No offline bundle tools planned.",
        "",
        "## Blocking Items",
        "",
        ", ".join(blockers) if blockers else "None.",
        "",
    ]
    return "\n".join(lines)


def write_runtime_install_plan(plan: dict, out_dir: pathlib.Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "runtime-install-plan.json", plan)
    (out_dir / "runtime-install-plan.md").write_text(render_markdown(plan))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="standard")
    ap.add_argument("--network-mode", default="restricted")
    ap.add_argument("--target-runtime", default="pvas-container")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    plan = build_runtime_install_plan(
        profile=args.profile,
        network_mode=args.network_mode,
        target_runtime=args.target_runtime,
    )
    write_runtime_install_plan(plan, pathlib.Path(args.out))
    return 2 if plan["status"].startswith("blocked") else 0


if __name__ == "__main__":
    raise SystemExit(main())
