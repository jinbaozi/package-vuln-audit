#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_matrix(profile_payload, profile_name="standard", *extra_args):
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        profile = td / "package-profile.json"
        out = td / "required-tools-matrix.json"
        profile.write_text(json.dumps(profile_payload))
        subprocess.check_call([
            sys.executable,
            str(ROOT / "tools" / "generate_tool_matrix.py"),
            "--package-profile",
            str(profile),
            "--profile",
            profile_name,
            *extra_args,
            "--out",
            str(out),
        ])
        return json.loads(out.read_text())


def test_standard_profile_marks_semgrep_mandatory():
    matrix = run_matrix({
        "package_name": "demo",
        "primary_language": ["Python"],
        "profiles": ["cli-tool"],
        "build_system": ["unknown"],
        "input_surfaces": ["command-line arguments"],
    })
    semgrep = next(t for t in matrix["tools"] if t["name"] == "semgrep")
    assert semgrep["applicability"] == "mandatory"
    assert semgrep["degraded_continuation_allowed"] is False
    assert "complete-audit baseline" in semgrep["evidence"]
    assert "SEMGREP_SETTINGS_FILE" in semgrep["env"]
    assert "SEMGREP_LOG_FILE" in semgrep["env"]


def test_npm_can_be_not_applicable_for_non_node_project():
    matrix = run_matrix({
        "package_name": "demo",
        "primary_language": ["C/C++"],
        "profiles": ["binary-parser"],
        "build_system": ["make"],
        "input_surfaces": ["files"],
    })
    npm = next(t for t in matrix["tools"] if t["name"] == "npm")
    assert npm["applicability"] == "not-applicable"
    assert "no Node.js lockfile" in npm["evidence"]


def test_binutils_profile_includes_build_tools():
    matrix = run_matrix({
        "package_name": "binutils-demo",
        "primary_language": ["C/C++"],
        "profiles": ["binary-parser"],
        "build_system": ["autotools", "make"],
        "input_surfaces": ["files"],
    }, profile_name="binutils")
    names = {t["name"]: t for t in matrix["tools"]}
    assert names["gcc"]["applicability"] in {"profile-required", "mandatory"}
    assert names["make"]["applicability"] in {"profile-required", "mandatory"}
    assert names["timeout"]["applicability"] in {"profile-required", "mandatory"}


def test_restricted_network_does_not_use_semgrep_auto_config():
    matrix = run_matrix({
        "package_name": "demo",
        "primary_language": ["Python"],
        "profiles": ["cli-tool"],
        "build_system": ["unknown"],
        "input_surfaces": ["command-line arguments"],
    }, "standard", "--network-policy", "restricted")
    semgrep = next(t for t in matrix["tools"] if t["name"] == "semgrep")
    assert "auto" not in semgrep["command"]
    assert semgrep["network_required"] is False


def test_online_approved_can_use_semgrep_auto_config():
    matrix = run_matrix({
        "package_name": "demo",
        "primary_language": ["Python"],
        "profiles": ["cli-tool"],
        "build_system": ["unknown"],
        "input_surfaces": ["command-line arguments"],
    }, "standard", "--network-policy", "online-approved", "--allow-network")
    semgrep = next(t for t in matrix["tools"] if t["name"] == "semgrep")
    assert semgrep["command"][semgrep["command"].index("--config") + 1] == "auto"
    assert semgrep["network_required"] is True


if __name__ == "__main__":
    test_standard_profile_marks_semgrep_mandatory()
    test_npm_can_be_not_applicable_for_non_node_project()
    test_binutils_profile_includes_build_tools()
    test_restricted_network_does_not_use_semgrep_auto_config()
    test_online_approved_can_use_semgrep_auto_config()
    print("tool matrix tests passed")
