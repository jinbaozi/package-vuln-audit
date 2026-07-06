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
CPPCHECK_MODE_VALUES = {"fast", "deep"}


def is_c_cpp_project(profile: dict) -> bool:
    langs = {str(x).lower() for x in profile.get("primary_language", [])}
    build = {str(x).lower() for x in profile.get("build_system", [])}
    files = " ".join(str(x).lower() for x in profile.get("build_files", []))
    return bool(langs & {"c", "c++", "cpp", "c/c++"}) or "makefile" in files or "configure" in files or "autotools" in build


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


def cppcheck_enable_arg(mode: str) -> str:
    if mode == "deep":
        return "--enable=warning,style,performance,portability"
    return "--enable=warning"


def cppcheck_mode_limitations(mode: str) -> str:
    if mode == "deep":
        return "deep mode includes warning, style, performance, and portability checks; may take longer"
    return "fast mode runs cppcheck default/error checks plus warning; style/performance/portability checks are omitted by design"


def cppcheck_jobs() -> int:
    try:
        return max(int(os.environ.get("PVAS_CPPCHECK_JOBS", "1")), 1)
    except ValueError:
        return 1


def command_template(
    name: str,
    *,
    network_policy: str,
    allow_network: bool,
    package_profile: dict | None = None,
    cppcheck_mode: str = "fast",
    cppcheck_scope: dict | None = None,
) -> list[str]:
    if name == "rg":
        return ["rg", "-n", "strcpy|strcat|sprintf|vsprintf|memcpy|memmove|malloc|calloc|realloc|free|system\\(|popen\\(|mktemp|tmpnam|open\\(|unlink\\(", "<source>"]
    if name == "semgrep":
        local_config = local_semgrep_config()
        if local_config:
            return ["semgrep", "scan", "--config", str(local_config), "--json", "--output", "<raw>/semgrep.json", "<source>"]
        if network_policy == "online-approved" and allow_network:
            return ["semgrep", "scan", "--config", "auto", "--json", "--output", "<raw>/semgrep.json", "<source>"]
        is_c_cpp = package_profile is not None and is_c_cpp_project(package_profile)
        if is_c_cpp:
            return ["semgrep", "scan", "--config", "p/c", "--json", "--output", "<raw>/semgrep.json", "<source>"]
        return ["semgrep", "scan", "--json", "--output", "<raw>/semgrep.json", "<source>"]
    if name == "cppcheck":
        base = [
            "cppcheck",
            cppcheck_enable_arg(cppcheck_mode),
            "--template=gcc",
            "--cppcheck-build-dir=<raw>/cppcheck-build-dir",
            f"-j{cppcheck_jobs()}",
        ]
        if cppcheck_scope and cppcheck_scope.get("scope_mode") == "compile-database" and cppcheck_scope.get("compile_database"):
            return [*base, f"--project={cppcheck_scope['compile_database']}"]
        if cppcheck_scope:
            for include_path in cppcheck_scope.get("include_paths") or []:
                base.append(f"-I{include_path}")
        return [*base, "<source>"]
    if name == "osv-scanner":
        return ["osv-scanner", "scan", "--format", "json", "<source>"]
    if name == "npm":
        return ["npm", "audit", "--json"]
    return [CATALOG[name]["binary"], *CATALOG[name].get("version_args", ["--version"])]


def build_matrix(
    package_profile: dict,
    env_profile: str,
    timeout: str,
    retries: int,
    *,
    network_policy: str,
    allow_network: bool,
    out_root: pathlib.Path | None = None,
    cppcheck_mode: str = "fast",
    cppcheck_mode_source: str = "default-fast",
    cppcheck_scope_path: pathlib.Path | None = None,
    cppcheck_scope: dict | None = None,
) -> dict:
    if network_policy not in NETWORK_POLICY_VALUES:
        raise ValueError(f"network_policy must be one of {sorted(NETWORK_POLICY_VALUES)}")
    if cppcheck_mode not in CPPCHECK_MODE_VALUES:
        raise ValueError(f"cppcheck_mode must be one of {sorted(CPPCHECK_MODE_VALUES)}")
    names = list(PROFILE_TOOLS[env_profile])
    if "semgrep" not in names:
        names.insert(0, "semgrep")
    tools = []
    for name in names:
        applicability, evidence, allow_degraded = tool_applicability(name, package_profile, env_profile)
        meta = CATALOG[name]
        command = command_template(
            name,
            network_policy=network_policy,
            allow_network=allow_network,
            package_profile=package_profile,
            cppcheck_mode=cppcheck_mode,
            cppcheck_scope=cppcheck_scope,
        )
        env = {}
        if name == "semgrep":
            env_base = out_root / "00-environment" if out_root else pathlib.Path("<raw>").parent / "00-environment"
            env = {
                "SEMGREP_SETTINGS_FILE": str(env_base / "semgrep-settings.yml"),
                "SEMGREP_LOG_FILE": str(env_base / "semgrep.log"),
            }
        network_required = bool(meta.get("network_required")) or (name == "semgrep" and "--config" in command and "auto" in command)
        tool_row = {
            "name": name,
            "binary": meta["binary"],
            "applicability": applicability,
            "evidence": evidence,
            "command": command,
            "env": env,
            "timeout": timeout,
            "network_policy": network_policy,
            "network_required": network_required,
            "allowed_cidrs": list(meta.get("allowed_cidrs") or []),
            "mem_limit_mb": int(meta.get("mem_limit_mb") or 1024),
            "sandbox_runtime": "pvas-container",
            "offline_fallback": "local-rules-or-incomplete" if name == "semgrep" else "local-db-or-incomplete" if name in {"codeql", "grype", "trivy", "syft"} else "",
            "watchdog": {"strategy": "adaptive", "idle_timeout": "15s"},
            "output_validator": "semgrep-json" if name == "semgrep" else "",
            "not_applicable_when": "no package source manifests" if name == "osv-scanner" else "",
            "retry_policy": {"max_attempts": retries + 1},
            "allowed_recovery_actions": ["retry", "increase-timeout", "split-scope", "tool-install-assistant"],
            "degraded_continuation_allowed": bool(allow_degraded),
            "final_status": "planned",
            "final_decision_rationale": "",
        }
        if name == "cppcheck":
            scope_mode = str(cppcheck_scope.get("scope_mode") or "unspecified") if cppcheck_scope else "unspecified"
            tool_row.update({
                "execution_mode": "project" if scope_mode == "compile-database" else "sharded",
                "output_validator": "cppcheck-gcc-template",
                "expected_output": "<raw>/cppcheck.out",
                "shard_size": 100,
                "cppcheck_mode": cppcheck_mode,
                "cppcheck_mode_source": cppcheck_mode_source,
                "mode_limitations": cppcheck_mode_limitations(cppcheck_mode),
                "cppcheck_scope_mode": scope_mode,
                "cppcheck_scope_file": str(cppcheck_scope_path) if cppcheck_scope_path else "",
                "cppcheck_compile_database": str(cppcheck_scope.get("compile_database") or "") if cppcheck_scope else "",
                "cppcheck_profile_ids": list(cppcheck_scope.get("profile_ids") or []) if cppcheck_scope else [],
                "scope_limitations": list(cppcheck_scope.get("limitations") or []) if cppcheck_scope else [],
                "cppcheck_include_paths": list(cppcheck_scope.get("include_paths") or []) if cppcheck_scope else [],
                "cppcheck_build_dir": "<raw>/cppcheck-build-dir",
                "cppcheck_jobs": cppcheck_jobs(),
            })
        tools.append(tool_row)
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
    ap.add_argument("--timeout", default="600s")
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--network-policy", default=os.environ.get("PVAS_NETWORK_POLICY", "restricted"), choices=sorted(NETWORK_POLICY_VALUES))
    ap.add_argument("--allow-network", action="store_true", default=os.environ.get("PVAS_ALLOW_NETWORK", "0") == "1")
    ap.add_argument("--cppcheck-mode", choices=sorted(CPPCHECK_MODE_VALUES), default=None)
    ap.add_argument("--cppcheck-mode-source", default=None)
    ap.add_argument("--cppcheck-scope", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    profile = load_json(pathlib.Path(args.package_profile))
    out = pathlib.Path(args.out)
    env_cppcheck_mode = os.environ.get("PVAS_CPPCHECK_MODE") or ""
    if args.cppcheck_mode:
        cppcheck_mode = args.cppcheck_mode
        cppcheck_mode_source = args.cppcheck_mode_source or "cli-cppcheck-mode"
    elif env_cppcheck_mode:
        cppcheck_mode = env_cppcheck_mode.strip().lower()
        if cppcheck_mode not in CPPCHECK_MODE_VALUES:
            ap.error(f"invalid PVAS_CPPCHECK_MODE {env_cppcheck_mode!r}")
        cppcheck_mode_source = args.cppcheck_mode_source or "env-cppcheck-mode"
    else:
        cppcheck_mode = "fast"
        cppcheck_mode_source = args.cppcheck_mode_source or "default-fast"
    cppcheck_scope_path = pathlib.Path(args.cppcheck_scope) if args.cppcheck_scope else pathlib.Path(args.package_profile).parent / "cppcheck-scope.json"
    cppcheck_scope = None
    if cppcheck_scope_path.exists():
        cppcheck_scope = load_json(cppcheck_scope_path, default={})
    matrix = build_matrix(
        profile,
        args.profile,
        args.timeout,
        args.retries,
        network_policy=args.network_policy,
        allow_network=args.allow_network,
        out_root=out.parent.parent if out.parent.name == "01-profile" else None,
        cppcheck_mode=cppcheck_mode,
        cppcheck_mode_source=cppcheck_mode_source,
        cppcheck_scope_path=cppcheck_scope_path if cppcheck_scope else None,
        cppcheck_scope=cppcheck_scope,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(matrix, indent=2, ensure_ascii=False))
    print(f"[PVAS-TOOL-MATRIX] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
