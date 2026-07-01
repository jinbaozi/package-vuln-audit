#!/usr/bin/env python3
"""Generate project-profile-driven traditional tool execution matrix."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from pvas_io import load_json, write_json  # noqa: E402
from tool_catalog import CATALOG, PROFILE_TOOLS  # noqa: E402


SEMGRP_EVIDENCE = "complete-audit baseline required by workflow gate design"
NETWORK_POLICY_VALUES = {"offline", "restricted", "online-approved"}


def is_node_project(profile: dict) -> bool:
    build = {str(x).lower() for x in profile.get("build_system", [])}
    langs = {str(x).lower() for x in profile.get("primary_language", [])}
    files = " ".join(str(x).lower() for x in profile.get("build_files", []))
    return "node" in langs or "javascript" in langs or "typescript" in langs or "npm" in build or "package.json" in files


def has_node_lockfile(profile: dict) -> bool:
    files = {pathlib.PurePosixPath(str(x).replace("\\", "/")).name.lower() for x in profile.get("build_files", [])}
    return bool(files & {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"})


def tool_applicability(name: str, profile: dict, env_profile: str) -> tuple[str, str, bool]:
    if name == "semgrep":
        return "mandatory", SEMGRP_EVIDENCE, False
    if name == "npm" and (not is_node_project(profile) or not has_node_lockfile(profile)):
        return "not-applicable", "no Node.js lockfile requiring npm audit in package profile", True
    if name in {"gcc", "make", "timeout"} and env_profile == "binutils":
        return "profile-required", f"{env_profile} profile requires {name}", False
    level = CATALOG[name]["level"]
    if level == "recommended":
        return "recommended", f"{name} is recommended for {env_profile} profile", False
    return "optional", f"{name} is optional for {env_profile} profile", True


def local_semgrep_config() -> pathlib.Path | None:
    candidates = [
        ROOT / "rules" / "semgrep",
        ROOT / "offline-bundle" / "semgrep-rules",
        ROOT / "offline-bundle" / "rules" / "semgrep",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def command_template(name: str, *, network_policy: str, allow_network: bool) -> list[str]:
    if name == "rg":
        return ["rg", "-n", "strcpy|strcat|sprintf|vsprintf|memcpy|memmove|malloc|calloc|realloc|free|system\\(|popen\\(|mktemp|tmpnam|open\\(|unlink\\(", "<source>"]
    if name == "semgrep":
        local_config = local_semgrep_config()
        if local_config:
            return ["semgrep", "scan", "--config", str(local_config), "--json", "--output", "<raw>/semgrep.json", "<source>"]
        if network_policy == "online-approved" and allow_network:
            return ["semgrep", "scan", "--config", "auto", "--json", "--output", "<raw>/semgrep.json", "<source>"]
        return ["semgrep", "scan", "--json", "--output", "<raw>/semgrep.json", "<source>"]
    if name == "cppcheck":
        return ["cppcheck", "--enable=warning,style,performance,portability", "--template=gcc", "<source>"]
    if name == "osv-scanner":
        return ["osv-scanner", "scan", "--format", "json", "<source>"]
    if name == "npm":
        return ["npm", "audit", "--json"]
    return [CATALOG[name]["binary"], *CATALOG[name].get("version_args", ["--version"])]


def build_matrix(package_profile: dict, env_profile: str, timeout: str, retries: int, *, network_policy: str, allow_network: bool, out_root: pathlib.Path | None = None) -> dict:
    if network_policy not in NETWORK_POLICY_VALUES:
        raise ValueError(f"network_policy must be one of {sorted(NETWORK_POLICY_VALUES)}")
    names = list(PROFILE_TOOLS[env_profile])
    if "semgrep" not in names:
        names.insert(0, "semgrep")
    tools = []
    for name in names:
        applicability, evidence, allow_degraded = tool_applicability(name, package_profile, env_profile)
        meta = CATALOG[name]
        command = command_template(name, network_policy=network_policy, allow_network=allow_network)
        env = {}
        if name == "semgrep":
            env_base = out_root / "00-environment" if out_root else pathlib.Path("<raw>").parent / "00-environment"
            env = {
                "SEMGREP_SETTINGS_FILE": str(env_base / "semgrep-settings.yml"),
                "SEMGREP_LOG_FILE": str(env_base / "semgrep.log"),
            }
        network_required = name in {"codeql", "grype", "trivy", "syft"} or (name == "semgrep" and "--config" in command and "auto" in command)
        tools.append({
            "name": name,
            "binary": meta["binary"],
            "applicability": applicability,
            "evidence": evidence,
            "command": command,
            "env": env,
            "timeout": timeout,
            "network_policy": network_policy,
            "network_required": network_required,
            "offline_fallback": "local-rules-or-incomplete" if name == "semgrep" else "local-db-or-incomplete" if name in {"codeql", "grype", "trivy", "syft"} else "",
            "watchdog": {"strategy": "adaptive", "idle_timeout": "15s"},
            "output_validator": "semgrep-json" if name == "semgrep" else "",
            "not_applicable_when": "no package source manifests" if name == "osv-scanner" else "",
            "retry_policy": {"max_attempts": retries + 1},
            "allowed_recovery_actions": ["retry", "increase-timeout", "split-scope", "tool-install-assistant"],
            "degraded_continuation_allowed": bool(allow_degraded),
            "final_status": "planned",
            "final_decision_rationale": "",
        })
    return {
        "schema_version": "1.0",
        "environment_profile": env_profile,
        "package": package_profile.get("package_name", "unknown"),
        "source_root": package_profile.get("source_root", ""),
        "network_policy": network_policy,
        "network_allowed": bool(allow_network),
        "tools": tools,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package-profile", required=True)
    ap.add_argument("--profile", default="standard", choices=sorted(PROFILE_TOOLS))
    ap.add_argument("--timeout", default="60s")
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--network-policy", default=os.environ.get("PVAS_NETWORK_POLICY", "restricted"), choices=sorted(NETWORK_POLICY_VALUES))
    ap.add_argument("--allow-network", action="store_true", default=os.environ.get("PVAS_ALLOW_NETWORK", "0") == "1")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    profile = load_json(pathlib.Path(args.package_profile))
    out = pathlib.Path(args.out)
    matrix = build_matrix(
        profile,
        args.profile,
        args.timeout,
        args.retries,
        network_policy=args.network_policy,
        allow_network=args.allow_network,
        out_root=out.parent.parent if out.parent.name == "01-profile" else None,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(matrix, indent=2, ensure_ascii=False))
    print(f"[PVAS-TOOL-MATRIX] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
