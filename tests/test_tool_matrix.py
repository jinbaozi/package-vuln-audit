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
    assert names["g++"]["applicability"] in {"profile-required", "mandatory"}
    assert names["clang"]["applicability"] in {"profile-required", "mandatory"}
    assert names["clang++"]["applicability"] in {"profile-required", "mandatory"}
    assert names["llvm-symbolizer"]["applicability"] in {"profile-required", "mandatory"}
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
    assert semgrep["command"][semgrep["command"].index("--config") + 1].endswith("offline-bundle/semgrep-rules")
    assert semgrep["network_required"] is False
    assert semgrep["mem_limit_mb"] <= 4096
    assert semgrep["allowed_cidrs"] == []
    assert semgrep["sandbox_runtime"] == "pvas-container"


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


def test_matrix_propagates_catalog_sandbox_metadata():
    matrix = run_matrix({
        "package_name": "demo",
        "primary_language": ["C/C++"],
        "profiles": ["binary-parser"],
        "build_system": ["make"],
        "input_surfaces": ["files"],
    }, profile_name="binutils")
    for tool in matrix["tools"]:
        assert isinstance(tool.get("mem_limit_mb"), int), tool["name"]
        assert 1 <= tool["mem_limit_mb"] <= 4096, tool["name"]
        assert isinstance(tool.get("network_required"), bool), tool["name"]
        assert isinstance(tool.get("allowed_cidrs"), list), tool["name"]
        assert tool.get("sandbox_runtime") == "pvas-container", tool["name"]
        assert tool.get("expected_runtime") == "pvas-container", tool["name"]
        assert tool.get("required_binary") == tool["binary"], tool["name"]
        assert isinstance(tool.get("version_command"), list), tool["name"]
        assert tool.get("runtime_scope"), tool["name"]
        assert tool.get("install_requirement"), tool["name"]


def test_cppcheck_matrix_uses_sharded_runner_and_gcc_template():
    matrix = run_matrix({
        "package_name": "demo",
        "primary_language": ["C/C++"],
        "profiles": ["binary-parser"],
        "build_system": ["make"],
        "input_surfaces": ["files"],
    })
    cppcheck = next(t for t in matrix["tools"] if t["name"] == "cppcheck")
    assert cppcheck["execution_mode"] == "sharded"
    assert cppcheck["output_validator"] == "cppcheck-gcc-template"
    assert cppcheck["expected_output"] == "<raw>/cppcheck.out"
    assert "--template=gcc" in cppcheck["command"]
    assert "--enable=warning" in cppcheck["command"]
    assert "--enable=warning,style,performance,portability" not in cppcheck["command"]
    assert cppcheck["cppcheck_mode"] == "fast"
    assert cppcheck["cppcheck_mode_source"] == "default-fast"
    assert "style/performance/portability" in cppcheck["mode_limitations"]


def test_cppcheck_deep_matrix_preserves_existing_enable_set():
    matrix = run_matrix({
        "package_name": "demo",
        "primary_language": ["C/C++"],
        "profiles": ["binary-parser"],
        "build_system": ["make"],
        "input_surfaces": ["files"],
    }, "standard", "--cppcheck-mode", "deep", "--cppcheck-mode-source", "test-explicit")
    cppcheck = next(t for t in matrix["tools"] if t["name"] == "cppcheck")
    assert "--enable=warning,style,performance,portability" in cppcheck["command"]
    assert cppcheck["cppcheck_mode"] == "deep"
    assert cppcheck["cppcheck_mode_source"] == "test-explicit"
    assert "may take longer" in cppcheck["mode_limitations"]


def test_tool_summary_schema_has_admission_policy_fields():
    schema = json.loads((ROOT / "schemas" / "tool-summary.schema.json").read_text())
    tool_props = schema["properties"]["tools"]["items"]["properties"]
    assert "coverage_profile" in tool_props
    assert "accuracy_risk" in tool_props
    assert "admission_policy" in tool_props
    assert "negative_conclusion_allowed" in tool_props


def test_admission_policy_marks_missing_required_tool_not_admissible():
    sys.path.insert(0, str(ROOT / "tools"))
    import run_tool_matrix

    row = {
        "name": "semgrep",
        "status": "blocked-recovery-required",
        "reason": "not-installed",
        "strict_decision": "block",
        "coverage_impact": "semgrep SAST missing",
    }
    annotated = run_tool_matrix.apply_admission_policy(row)
    assert annotated["coverage_profile"] == "unavailable"
    assert annotated["accuracy_risk"] == "missing_tool"
    assert annotated["admission_policy"] == "not_admissible"
    assert annotated["negative_conclusion_allowed"] is False


def test_admission_policy_marks_partial_cppcheck_positive_only():
    sys.path.insert(0, str(ROOT / "tools"))
    import run_tool_matrix

    row = {
        "name": "cppcheck",
        "status": "incomplete",
        "reason": "partial-timeout",
        "result_count": 2,
        "coverage_impact": {"limitation": "partial cppcheck coverage"},
    }
    annotated = run_tool_matrix.apply_admission_policy(row)
    assert annotated["coverage_profile"] == "partial"
    assert annotated["accuracy_risk"] == "limited_coverage"
    assert annotated["admission_policy"] == "positive_only"
    assert annotated["negative_conclusion_allowed"] is False


if __name__ == "__main__":
    test_standard_profile_marks_semgrep_mandatory()
    test_npm_can_be_not_applicable_for_non_node_project()
    test_binutils_profile_includes_build_tools()
    test_restricted_network_does_not_use_semgrep_auto_config()
    test_online_approved_can_use_semgrep_auto_config()
    test_matrix_propagates_catalog_sandbox_metadata()
    test_cppcheck_matrix_uses_sharded_runner_and_gcc_template()
    test_cppcheck_deep_matrix_preserves_existing_enable_set()
    test_tool_summary_schema_has_admission_policy_fields()
    test_admission_policy_marks_missing_required_tool_not_admissible()
    test_admission_policy_marks_partial_cppcheck_positive_only()
    print("tool matrix tests passed")
