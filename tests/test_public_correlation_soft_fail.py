from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import public_correlation_soft_fail as soft_fail


class FakeFrame:
    def __init__(self, f_locals, f_globals):
        self.f_locals = f_locals
        self.f_globals = f_globals


def test_build_not_configured_correlation_has_per_finding_rows():
    payload = soft_fail.build_not_configured_correlation([
        {"id": "PVAS-001", "status": "Validated"},
        {"id": "PVAS-002", "status": "Validated"},
    ])

    assert payload["status"] == "correlation_not_configured"
    assert payload["negative_public_disclosure_conclusion_allowed"] is False
    assert len(payload["correlations"]) == 2
    assert payload["correlations"][0]["status"] == "correlation_not_configured"
    assert payload["correlations"][0]["match_level"] == "M0"
    assert payload["correlations"][0]["matched_records"] == []


def test_maybe_recover_respects_hard_gate(monkeypatch, tmp_path):
    monkeypatch.setenv("PVAS_REQUIRE_PUBLIC_CORRELATION_FOR_VALIDATED", "1")
    frame = FakeFrame({}, {})

    result = soft_fail.maybe_recover_missing_public_records(
        frame,
        [soft_fail.PUBLIC_CORRELATION_REQUIRED_ISSUE],
    )

    assert result is None


def test_recover_missing_public_records_generates_internal_degraded_artifacts(tmp_path, monkeypatch):
    monkeypatch.delenv("PVAS_REQUIRE_PUBLIC_CORRELATION_FOR_VALIDATED", raising=False)
    out = tmp_path / "audit-output"
    corr = out / "machine/correlation/public-vuln-correlation.json"
    finding_index = out / "05-findings/finding-index.json"
    finding_index.parent.mkdir(parents=True)
    finding_index.write_text(json.dumps({"findings": [{"id": "PVAS-001", "status": "Validated"}]}))
    calls = []

    def fake_write_json(path, payload):
        path = pathlib.Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2))

    def fake_run(cmd, allow_fail=False):
        calls.append(cmd)
        text = " ".join(str(part) for part in cmd)
        if "generate_final_report.py" in text:
            for rel in ["06-report/machine", "06-report/zh-CN", "06-report/en-US"]:
                (out / rel).mkdir(parents=True, exist_ok=True)
            (out / "06-report/machine/final-report.json").write_text("{}")
            (out / "06-report/zh-CN/final-summary-report.md").write_text("# ZH")
            (out / "06-report/en-US/final-summary-report.md").write_text("# EN")
        if "validate_report_completeness.py" in text:
            (out / "machine").mkdir(parents=True, exist_ok=True)
            (out / "machine/report-completeness-pre-disclosure.json").write_text(
                json.dumps({"status": "passed", "errors": [], "warnings": []})
            )
        return 0, "ok"

    frame = FakeFrame(
        {
            "out": out,
            "corr": corr,
            "finding_index_path": finding_index,
            "validated": [{"id": "PVAS-001", "status": "Validated"}],
        },
        {
            "run": fake_run,
            "write_json": fake_write_json,
        },
    )

    recovery = soft_fail.maybe_recover_missing_public_records(
        frame,
        [soft_fail.PUBLIC_CORRELATION_REQUIRED_ISSUE],
    )
    payload = json.loads(corr.read_text())

    assert recovery is not None
    assert recovery["details"]["public_correlation_status"] == "correlation_not_configured"
    assert recovery["limitations"] == [soft_fail.CORRELATION_NOT_CONFIGURED_LIMITATION]
    assert payload["correlations"][0]["finding_id"] == "PVAS-001"
    assert payload["correlations"][0]["status"] == "correlation_not_configured"
    assert any("apply_correlation_to_findings.py" in " ".join(map(str, call)) for call in calls)
    assert any("publish_bilingual_reports.py" in " ".join(map(str, call)) for call in calls)
    assert any("generate_final_report.py" in " ".join(map(str, call)) for call in calls)
    assert any("validate_report_completeness.py" in " ".join(map(str, call)) for call in calls)
