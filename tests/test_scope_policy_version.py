#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys

from tool_runner import ROOT, run_subprocess, temp_audit_dir


EXPECTED_VERSION = "0.10.0-alpha11"
VALID_RECIPES = {
    "binary-parser", "build-system", "cli-tool", "compiler-toolchain",
    "crypto-auth", "library-parser", "mixed-project", "network-service",
    "package-manager", "privileged-tool", "unknown-conservative",
}


def test_select_scope_uses_selected_recipes_and_existing_fallbacks():
    sys.path.insert(0, str(ROOT / "tools"))
    import select_scope

    selected = select_scope.select_scope({
        "package_name": "demo",
        "selected_recipes": ["recipes/cli-tool.md", "recipes/binary-parser.md"],
        "profiles": ["nonexistent-profile"],
    }, source=".")
    assert selected["selected_recipes"] == ["recipes/binary-parser.md", "recipes/cli-tool.md"]

    try:
        select_scope.select_scope({
            "package_name": "demo",
            "selected_recipes": ["recipes/missing.md"],
        }, source=".")
    except ValueError as exc:
        assert "selected recipe does not exist" in str(exc)
    else:
        raise AssertionError("missing explicit selected_recipes must block")

    fallback = select_scope.select_scope({"package_name": "demo", "profiles": ["unknown"]}, source=".")
    assert fallback["selected_recipes"] == ["recipes/unknown-conservative.md"]

    for profile in VALID_RECIPES:
        result = select_scope.select_scope({"package_name": "demo", "profiles": [profile]}, source=".")
        for recipe in result["selected_recipes"]:
            assert (ROOT / recipe).is_file(), recipe


def test_validate_stage_policy_sync_passes_for_current_contracts():
    with temp_audit_dir() as td:
        out = pathlib.Path(td) / "policy-sync.json"
        run_subprocess("tools/validate_stage_policy_sync.py", [
            "--root", str(ROOT),
            "--out", str(out),
        ])
        data = json.loads(out.read_text())
        assert data["passed"] is True
        assert data["workflow_steps"] == [
            "00-intake", "01-package-profile", "02-scope-selection", "03-tool-scan",
            "04-ai-hypothesis", "05-candidate-review", "06-validation",
            "07-cvss-scoring", "08-report", "09-progressive-disclosure",
        ]


def test_alpha11_version_strings_are_synchronized():
    skill = json.loads((ROOT / "skill.json").read_text())
    assert skill["version"] == EXPECTED_VERSION
    for rel in ["README.md", "CLAUDE.md", "run-tests.sh"]:
        text = (ROOT / rel).read_text()
        assert EXPECTED_VERSION in text, rel
        assert "0.10.0-alpha10" not in text, rel


if __name__ == "__main__":
    test_select_scope_uses_selected_recipes_and_existing_fallbacks()
    test_validate_stage_policy_sync_passes_for_current_contracts()
    test_alpha11_version_strings_are_synchronized()
    print("scope policy version tests passed")
