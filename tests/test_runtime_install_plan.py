#!/usr/bin/env python3
import json
import pathlib
import tempfile
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from generate_runtime_install_plan import build_runtime_install_plan, write_runtime_install_plan  # noqa: E402


def test_binutils_plan_groups_dnf_and_offline_tools():
    plan = build_runtime_install_plan(profile="binutils", network_mode="restricted", target_runtime="pvas-container")
    dnf_tools = {item["tool"] for item in plan["container"]["dnf_install"]}
    offline_tools = {item["tool"] for item in plan["container"]["offline_bundle"]}
    for name in ("clang", "clang++", "llvm-symbolizer", "gcc", "g++", "make", "timeout"):
        assert name in dnf_tools, name
    assert "osv-scanner" in offline_tools
    assert plan["host_bootstrap"]["required_binaries"] == ["python3", "docker|podman"]


def test_strict_required_without_install_source_blocks():
    catalog = {
        "missing-tool": {
            "binary": "missing-tool",
            "level": "recommended",
            "profiles": ["binutils"],
            "required_for": ["validation"],
            "runtime_scope": "container-required",
            "version_args": ["--version"],
        }
    }
    plan = build_runtime_install_plan(
        profile="binutils",
        network_mode="offline",
        target_runtime="pvas-container",
        catalog=catalog,
        profile_tools={"binutils": ["missing-tool"]},
        strict_required={"binutils": ["missing-tool"]},
    )
    assert plan["status"] == "blocked-install-source-missing"
    assert plan["blocking_items"][0]["tool"] == "missing-tool"


def test_write_runtime_install_plan_outputs_json_and_markdown():
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / "00-environment"
        plan = build_runtime_install_plan(profile="binutils", network_mode="restricted", target_runtime="pvas-container")
        write_runtime_install_plan(plan, out)
        payload = json.loads((out / "runtime-install-plan.json").read_text())
        text = (out / "runtime-install-plan.md").read_text()
        assert payload["profile"] == "binutils"
        assert "Runtime Install Plan" in text
        assert "dnf install" in text


if __name__ == "__main__":
    test_binutils_plan_groups_dnf_and_offline_tools()
    test_strict_required_without_install_source_blocks()
    test_write_runtime_install_plan_outputs_json_and_markdown()
    print("runtime install plan tests passed")
