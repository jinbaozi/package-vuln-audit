#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


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
        ])
        run_result = json.loads((out / "FINDING-100" / "poc-run-result.json").read_text())
        assert run_result["status"] == "passed"
        assert run_result["exit_code"] == 0
        subprocess.check_call([
            sys.executable,
            str(ROOT / "tools" / "validate_poc_artifacts.py"),
            "--poc-root",
            str(out),
        ])


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


if __name__ == "__main__":
    test_generate_poc_writes_run_result_for_validated_status()
    test_validate_poc_artifacts_rejects_missing_run_result()
    print("poc execution result tests passed")
