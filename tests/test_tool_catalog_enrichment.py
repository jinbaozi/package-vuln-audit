#!/usr/bin/env python3
"""Verify sandbox runtime metadata is present in the shared tool catalog."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from tool_catalog import CATALOG  # noqa: E402


PLANNED_TOOLS = [
    "rg",
    "semgrep",
    "cppcheck",
    "osv-scanner",
    "npm",
    "codeql",
    "joern",
    "syft",
    "grype",
    "trivy",
    "afl-fuzz",
    "gcc",
    "g++",
    "clang",
    "clang++",
    "llvm-symbolizer",
    "llvm-profdata",
    "llvm-cov",
    "make",
    "autoconf",
    "automake",
    "libtool",
    "bison",
    "flex",
    "cmake",
    "ninja",
    "pkg-config",
]


def test_planned_tools_have_sandbox_metadata():
    for name in PLANNED_TOOLS:
        meta = CATALOG[name]
        assert isinstance(meta.get("mem_limit_mb"), int), name
        assert 1 <= meta["mem_limit_mb"] <= 4096, name
        assert isinstance(meta.get("network_required"), bool), name
        assert isinstance(meta.get("allowed_cidrs"), list), name


def test_npm_catalog_key_remains_authoritative_for_npm_audit():
    assert "npm-audit" not in CATALOG
    assert "npm-audit" in CATALOG["npm"]["required_for"]


def test_known_network_policy_defaults_are_conservative():
    for name in ("semgrep", "cppcheck", "rg", "gcc", "make"):
        assert CATALOG[name]["network_required"] is False, name
        assert CATALOG[name]["allowed_cidrs"] == [], name
    for name in ("osv-scanner", "npm"):
        assert CATALOG[name]["network_required"] is True, name
        assert CATALOG[name]["allowed_cidrs"] == [], name


def test_timeout_helper_also_has_runtime_budget():
    meta = CATALOG["timeout"]
    assert meta["mem_limit_mb"] <= 4096
    assert meta["network_required"] is False
    assert meta["allowed_cidrs"] == []


def test_binutils_strict_required_includes_validation_toolchain():
    from tool_catalog import STRICT_REQUIRED_TOOLS

    required = set(STRICT_REQUIRED_TOOLS["binutils"])
    for name in (
        "clang",
        "clang++",
        "llvm-symbolizer",
        "gcc",
        "g++",
        "make",
        "timeout",
    ):
        assert name in required, name


def test_profile_tools_have_install_source_and_runtime_scope():
    from tool_catalog import PROFILE_TOOLS

    for name in PROFILE_TOOLS["binutils"]:
        meta = CATALOG[name]
        assert meta.get("runtime_scope") in {
            "host-bootstrap",
            "container-required",
            "container-optional",
            "validation-required",
        }, name
        assert meta.get("dnf_package") or meta.get("install_hint_id"), name
        assert meta.get("install_methods"), name


if __name__ == "__main__":
    test_planned_tools_have_sandbox_metadata()
    test_npm_catalog_key_remains_authoritative_for_npm_audit()
    test_known_network_policy_defaults_are_conservative()
    test_timeout_helper_also_has_runtime_budget()
    test_binutils_strict_required_includes_validation_toolchain()
    test_profile_tools_have_install_source_and_runtime_scope()
    print("tool catalog enrichment tests passed")
