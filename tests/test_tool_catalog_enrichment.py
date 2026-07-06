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
    "make",
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


if __name__ == "__main__":
    test_planned_tools_have_sandbox_metadata()
    test_npm_catalog_key_remains_authoritative_for_npm_audit()
    test_known_network_policy_defaults_are_conservative()
    test_timeout_helper_also_has_runtime_budget()
    print("tool catalog enrichment tests passed")
