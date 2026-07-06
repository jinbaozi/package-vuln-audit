#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def poc_env():
    env = os.environ.copy()
    env["PVAS_SANDBOX"] = "disabled"
    return env


def test_generate_poc_writes_run_result_for_validated_status():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        findings = td / "findings.json"
        findings.write_text(json.dumps({"findings": [{
            "id": "FINDING-100",
            "status": "Validated",
            "title": "fixture",
            "affected_component": {"package": "demo", "component": "parser"},
            "source_code_evidence": [{"file": "src/parser.c"}],
            "source_to_sink_path": "input -> parser -> sink",
            "validation": {"command": "cat", "expected_vulnerable": "pass", "expected_fixed": "fixed"},
            "cvss": {},
            "fix_recommendation": "fix",
            "disclosure_level": "D3-maintainer-private",
            "discovery_method": [{"type": "tool", "tool_name": "semgrep", "description": "fixture"}],
            "disclosure_status": "not_found_in_configured_sources",
        }]}))
        out = td / "poc"
        subprocess.check_call([
            sys.executable,
            str(ROOT / "tools" / "generate_poc_testcase.py"),
            "--findings",
            str(findings),
            "--generate-from-finding",
            "--language",
            "python",
            "--out",
            str(out),
        ], env=poc_env())
        run_result = json.loads((out / "FINDING-100" / "poc-run-result.json").read_text())
        assert run_result["status"] == "passed"
        assert run_result["exit_code"] == 0
        assert run_result["executed_via"] == "host-degraded-sandbox-disabled"
        assert run_result["container"]["network_policy"] == "host"
        subprocess.check_call([
            sys.executable,
            str(ROOT / "tools" / "validate_poc_artifacts.py"),
            "--poc-root",
            str(out),
        ], env=poc_env())


def test_validate_poc_artifacts_rejects_missing_run_result():
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td) / "poc"
        d = root / "FINDING-001"
        d.mkdir(parents=True)
        (d / "reproduce.sh").write_text("#!/usr/bin/env bash\ntimeout 1s true\n")
        (d / "input-description.md").write_text("SHA256: abc\nPurpose: local validation\n")
        (d / "poc-manifest.json").write_text(json.dumps({
            "finding_id": "FINDING-001",
            "status": "Validated",
            "poc_type": "local-reproducer",
            "safety_class": "local-validation-only",
            "discovery_method_ref": "tool(semgrep)",
            "artifacts": {},
            "commands": {"reproduce": "./reproduce.sh"},
            "expected_results": {"vulnerable": "x", "fixed": "y"},
            "disclosure_level": "D3-maintainer-private",
        }))
        p = subprocess.run([
            sys.executable,
            str(ROOT / "tools" / "validate_poc_artifacts.py"),
            "--poc-root",
            str(root),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 2
        assert "poc-run-result.json" in p.stderr


def test_validate_poc_artifacts_accepts_passed_draft():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        findings = td / "findings.json"
        findings.write_text(json.dumps({"findings": [{
            "id": "FINDING-200",
            "status": "Needs Manual Review",
            "title": "fixture",
            "affected_component": {"package": "demo", "component": "parser"},
            "source_code_evidence": [{"file": "src/parser.py"}],
            "source_to_sink_path": "input -> parser -> sink",
            "validation": {"command": "cat", "expected_vulnerable": "pass", "expected_fixed": "fixed"},
            "cvss": {},
            "fix_recommendation": "fix",
            "disclosure_level": "D3-maintainer-private",
            "discovery_method": [{"type": "tool", "tool_name": "semgrep", "description": "fixture"}],
            "disclosure_status": "not_found_in_configured_sources",
        }]}))
        out = td / "poc"
        subprocess.check_call([
            sys.executable,
            str(ROOT / "tools" / "generate_poc_testcase.py"),
            "--findings",
            str(findings),
            "--generate-from-finding",
            "--language",
            "python",
            "--out",
            str(out),
        ], env=poc_env())
        manifest = json.loads((out / "FINDING-200" / "poc-manifest.json").read_text())
        assert manifest["status"] == "draft"
        assert manifest["verification"] == "unverified"
        subprocess.check_call([
            sys.executable,
            str(ROOT / "tools" / "validate_poc_artifacts.py"),
            "--poc-root",
            str(out),
        ])


def test_validate_poc_artifacts_rejects_failed_draft_run_result():
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td) / "poc"
        d = root / "FINDING-201"
        d.mkdir(parents=True)
        (d / "reproduce.sh").write_text("#!/usr/bin/env bash\ntimeout 1s false\n")
        (d / "input-description.md").write_text("SHA256: abc\nPurpose: local validation\n")
        (d / "poc-run-result.json").write_text(json.dumps({
            "status": "failed",
            "exit_code": 1,
            "command": "timeout 1s ./reproduce.sh",
        }))
        (d / "poc-manifest.json").write_text(json.dumps({
            "finding_id": "FINDING-201",
            "status": "draft",
            "verification": "unverified",
            "poc_type": "generated-reproducer",
            "safety_class": "local-validation-only",
            "discovery_method_ref": "tool(semgrep)",
            "artifacts": {"reproduce_script": "reproduce.sh"},
            "commands": {"reproduce": "./reproduce.sh"},
            "expected_results": {"vulnerable": "x", "fixed": "y"},
            "disclosure_level": "D3-maintainer-private",
        }))
        p = subprocess.run([
            sys.executable,
            str(ROOT / "tools" / "validate_poc_artifacts.py"),
            "--poc-root",
            str(root),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 2
        assert "poc-run-result status is not passed" in p.stderr


if __name__ == "__main__":
    test_generate_poc_writes_run_result_for_validated_status()
    test_validate_poc_artifacts_rejects_missing_run_result()
    test_validate_poc_artifacts_accepts_passed_draft()
    test_validate_poc_artifacts_rejects_failed_draft_run_result()
    print("poc execution result tests passed")
